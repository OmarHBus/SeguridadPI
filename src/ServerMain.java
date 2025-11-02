// === Embedded HTTP server utilities (no external dependencies) ===
import com.sun.net.httpserver.HttpExchange; // Represents an HTTP request/response pair
import com.sun.net.httpserver.HttpHandler;  // Interface used to handle endpoints
import com.sun.net.httpserver.HttpServer;   // Lightweight embedded HTTP server
import com.sun.net.httpserver.HttpsConfigurator; // HTTPS configurator helper
import com.sun.net.httpserver.HttpsServer;  // HTTPS server variant

// === I/O and filesystem helpers ===
import java.io.*;                           // Streams, readers, writers, IOExceptions
import java.net.InetSocketAddress;          // Address/port binding
import java.net.URI;                        // URI inspection helpers
import java.nio.charset.StandardCharsets;   // Stable UTF-8 charset
import java.nio.file.*;                     // Paths, Files for reading/writing .properties
import java.util.Properties;                // Simple key=value storage (.properties)
import javax.net.ssl.KeyManagerFactory;     // TLS keystore manager
import javax.net.ssl.SSLContext;            // TLS context setup
import java.security.KeyStore;              // Keystore abstraction
import java.util.UUID;                      // Unique identifiers for files
import java.util.Base64;                    // Base64 sanitation helpers
import java.util.HashMap;                   // Session storage
import java.util.Map;                       // Generic map
import java.util.List;                      // JSON array handling
import java.util.Set;                       // Allowed roles
import java.util.regex.Pattern;             // Input validation patterns

/**
 * Servidor HTTP mínimo para gestionar registros de usuarios.
 * Mantiene usuarios en "server_users/<username>.properties" con:
 *  - username, saltB64, dkB64, publicKeyB64, encPrivateB64, ivB64
 *
 * Endpoints:
 *  GET  /exists/{user}  -> 200 si existe, 404 si no
 *  GET  /user/{user}    -> JSON con los campos si existe
 *  POST /register       -> crea el usuario a partir de JSON
 */
public class ServerMain {
    private static final int PORT = 8080;                // Puerto HTTP
    private static final int TLS_PORT = 8443;            // Puerto HTTPS
    private static final Path ROOT = Paths.get("server_users"); // Carpeta de almacenamiento
    private static final Path FILES = Paths.get("server_files");

    private static final int MAX_REGISTER_BODY = 8_192;
    private static final int MAX_GENERIC_BODY = 32_768;
    private static final int MAX_UPLOAD_BODY = 12_582_912; // ~9.4 MiB decoded -> 12.6 MiB Base64
    private static final int MAX_FILE_DECODED_BYTES = 9_437_184; // Approximately 9 MiB decoded payload per encrypted file
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]{3,32}$");
    private static final int MAX_FILENAME_LENGTH = 255;
    private static final Set<String> ALLOWED_ROLES = Set.of("ADMIN", "USER", "WORKER", "AUDITOR");

    private static final Base64.Decoder B64_DEC = Base64.getDecoder();
    private static final Base64.Encoder B64_ENC = Base64.getEncoder();

    // In-memory session storage (MVP): token -> (user, role)
    private static final Map<String, Session> SESSIONS = new HashMap<>();
    private static final class Session {
        final String user; final String role;
        Session(String u, String r){ this.user=u; this.role=r; }
    }

    /** Starts the embedded HTTP server and registers routes. */
    public static void main(String[] args) throws Exception {
        // Asegura que la carpeta de usuarios exista
        Files.createDirectories(ROOT);
        Files.createDirectories(FILES);
        // Crea HTTP o HTTPS según disponibilidad de keystore PKCS#12
        HttpServer srv;
        Path ksPath = Paths.get("server_keystore.p12");
        if (Files.exists(ksPath)) {
            char[] pass = "changeit".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream is = Files.newInputStream(ksPath)) { ks.load(is, pass); }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pass);
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(kmf.getKeyManagers(), null, null);
            HttpsServer https = HttpsServer.create(new InetSocketAddress(TLS_PORT), 0);
            https.setHttpsConfigurator(new HttpsConfigurator(ssl));
            srv = https;
        } else {
            srv = HttpServer.create(new InetSocketAddress(PORT), 0);
        }

        // --- Rutas / Endpoints ---

        // GET /exists/{user} -> Comprueba si el archivo <user>.properties existe
        srv.createContext("/exists", exchange -> {
            try {
                String user = lastPathSegment(exchange.getRequestURI());
                if (user == null) { send(exchange, 400, "missing user"); return; }
                boolean ok = Files.exists(ROOT.resolve(user + ".properties"));
                send(exchange, ok ? 200 : 404, ok ? "true" : "false");
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // GET /user/{user} -> Devuelve JSON con los campos del usuario
        srv.createContext("/user", exchange -> {
            try {
                String user = lastPathSegment(exchange.getRequestURI());
                if (user == null) { send(exchange, 400, "missing user"); return; }

                Path f = ROOT.resolve(user + ".properties");
                if (!Files.exists(f)) { send(exchange, 404, "not found"); return; }

                // Carga del .properties del usuario
                Properties p = new Properties();
                try (InputStream is = Files.newInputStream(f)) { p.load(is); }

                // Construcción manual de JSON (simple, sin librerías)
                String json = "{"+
                        "\"username\":"+JsonUtil.quote(p.getProperty("username"))+","+
                        "\"saltB64\":"+JsonUtil.quote(p.getProperty("saltB64"))+","+
                        "\"publicKeyB64\":"+JsonUtil.quote(p.getProperty("publicKeyB64"))+","+
                        "\"encPrivateB64\":"+JsonUtil.quote(p.getProperty("encPrivateB64"))+","+
                        "\"ivB64\":"+JsonUtil.quote(p.getProperty("ivB64"))+","+
                        "\"role\":"+JsonUtil.quote(p.getProperty("role","USER"))
                        +"}";
                sendJson(exchange, 200, json);
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // POST /register -> Crea un usuario a partir de un JSON con 6 campos
        srv.createContext("/register", new RegisterHandler());

        // --- Ficheros (MVP simple, sin auth aún) ---
        // Recibe un JSON de fichero cifrado y guarda metadatos y ciphertext
        srv.createContext("/upload", exchange -> {
            try {
                Session sess = getSession(exchange);
                if (sess == null) { send(exchange, 401, "unauthorized"); return; }
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use POST"); return; }
                String user = lastPathSegment(exchange.getRequestURI());
                if (user == null) { send(exchange, 400, "missing user"); return; }
                if (!"ADMIN".equals(sess.role) && !sess.user.equals(user)) { send(exchange, 403, "forbidden"); return; }

                String body;
                try {
                    body = readBody(exchange, MAX_UPLOAD_BODY);
                } catch (IllegalArgumentException tooBig) {
                    send(exchange, 413, "body too large");
                    return;
                }

                try {
                    Map<String, String> data = JsonUtil.parseObject(body, 16, 4096);
                    String filename = enforceFilename(require(data, "filename"));
                    String ivB64 = canonicalBase64("ivB64", require(data, "ivB64"), 12, 48);
                    String cekWrapB64 = canonicalBase64("cekWrappedB64", require(data, "cekWrappedB64"), 32, 1024);
                    String ctB64 = canonicalBase64("ctB64", require(data, "ctB64"), 0, MAX_FILE_DECODED_BYTES);

                    String id = UUID.randomUUID().toString().replace("-", "");
                    Path dir = FILES.resolve(user);
                    Files.createDirectories(dir);

                    Properties p = new Properties();
                    p.setProperty("id", id);
                    p.setProperty("owner", user);
                    p.setProperty("filename", filename);
                    p.setProperty("ivB64", ivB64);
                    p.setProperty("cekWrappedB64", cekWrapB64);
                    p.setProperty("ctB64", ctB64);

                    try (OutputStream os = Files.newOutputStream(dir.resolve(id+".properties"))) { p.store(os, "File record"); }
                    sendJson(exchange, 201, "{\"fileId\":"+JsonUtil.quote(id)+"}");
                } catch (IllegalArgumentException badInput) {
                    send(exchange, 400, badInput.getMessage());
                }
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // Lista ficheros subidos (id + filename) para un usuario
        srv.createContext("/files", exchange -> {
            try {
                Session sess = getSession(exchange);
                if (sess == null) { send(exchange, 401, "unauthorized"); return; }
                String user = lastPathSegment(exchange.getRequestURI());
                if (user == null) { send(exchange, 400, "missing user"); return; }
                if (!"ADMIN".equals(sess.role) && !sess.user.equals(user)) { send(exchange, 403, "forbidden"); return; }
                Path dir = FILES.resolve(user);
                if (!Files.exists(dir)) { sendJson(exchange, 200, "[]"); return; }
                StringBuilder sb = new StringBuilder("[");
                boolean first = true;
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "*.properties")) {
                    for (Path f : ds) {
                        Properties p = new Properties();
                        try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                        if (!first) sb.append(',');
                        first = false;
                        sb.append('{')
                          .append("\"id\":").append(JsonUtil.quote(p.getProperty("id"))).append(',')
                          .append("\"filename\":").append(JsonUtil.quote(p.getProperty("filename")))
                          .append('}');
                    }
                }
                sb.append(']');
                sendJson(exchange, 200, sb.toString());
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // Lista ficheros que contienen wrap.<user> en cualquier owner
        srv.createContext("/files/shared", exchange -> {
            try {
                Session sess = getSession(exchange);
                if (sess == null) { send(exchange, 401, "unauthorized"); return; }
                String user = lastPathSegment(exchange.getRequestURI());
                if (user == null) { send(exchange, 400, "missing user"); return; }
                if (!"ADMIN".equals(sess.role) && !sess.user.equals(user)) { send(exchange, 403, "forbidden"); return; }
                StringBuilder sb = new StringBuilder("[");
                boolean first = true;
                if (Files.exists(FILES)) {
                    try (DirectoryStream<Path> owners = Files.newDirectoryStream(FILES)) {
                        for (Path ownerDir : owners) {
                            if (!Files.isDirectory(ownerDir)) continue;
                            String owner = ownerDir.getFileName().toString();
                            try (DirectoryStream<Path> ds = Files.newDirectoryStream(ownerDir, "*.properties")) {
                                for (Path f : ds) {
                                    Properties p = new Properties();
                                    try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                                    String wrap = p.getProperty("wrap."+user);
                                    if (wrap == null) continue;
                                    if (!first) sb.append(','); first = false;
                                    sb.append('{')
                                      .append("\"owner\":").append(JsonUtil.quote(owner)).append(',')
                                      .append("\"id\":").append(JsonUtil.quote(p.getProperty("id"))).append(',')
                                      .append("\"filename\":").append(JsonUtil.quote(p.getProperty("filename")))
                                      .append('}');
                                }
                            }
                        }
                    }
                }
                sb.append(']');
                sendJson(exchange, 200, sb.toString());
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // --- Administración (solo ADMIN) ---
        srv.createContext("/admin/users", exchange -> {
            try {
                Session sess = getSession(exchange);
                if (sess == null || !"ADMIN".equals(sess.role)) { send(exchange, 403, "admin only"); return; }
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use GET"); return; }
                StringBuilder sb = new StringBuilder("[");
                boolean first = true;
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(ROOT, "*.properties")) {
                    for (Path f : ds) {
                        Properties p = new Properties();
                        try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                        if (!first) sb.append(','); first=false;
                        sb.append('{')
                          .append("\"username\":").append(JsonUtil.quote(p.getProperty("username"))).append(',')
                          .append("\"role\":").append(JsonUtil.quote(p.getProperty("role","USER").toUpperCase()))
                          .append('}');
                    }
                }
                sb.append(']');
                sendJson(exchange, 200, sb.toString());
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        srv.createContext("/admin/setRole", exchange -> {
            try {
                Session sess = getSession(exchange);
                if (sess == null || !"ADMIN".equals(sess.role)) { send(exchange, 403, "admin only"); return; }
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use POST"); return; }

                String body;
                try {
                    body = readBody(exchange, MAX_GENERIC_BODY);
                } catch (IllegalArgumentException tooBig) {
                    send(exchange, 413, "body too large");
                    return;
                }

                try {
                    Map<String, String> data = JsonUtil.parseObject(body, 6, 512);
                    String user = enforceUsername(require(data, "username"));
                    String role = enforceRole(require(data, "role"));
                    Path f = ROOT.resolve(user + ".properties");
                    if (!Files.exists(f)) { send(exchange, 404, "not found"); return; }
                    Properties p = new Properties();
                    try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                    p.setProperty("role", role);
                    try (OutputStream os = Files.newOutputStream(f)) { p.store(os, "User record"); }
                    send(exchange, 200, "ok");
                } catch (IllegalArgumentException badInput) {
                    send(exchange, 400, badInput.getMessage());
                }
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // --- Autenticación por reto/firma (MVP sin tokens) ---
        srv.createContext("/auth/start", exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use POST"); return; }

                String body;
                try {
                    body = readBody(exchange, MAX_GENERIC_BODY);
                } catch (IllegalArgumentException tooBig) {
                    send(exchange, 413, "body too large");
                    return;
                }

                String user;
                try {
                    Map<String, String> data = JsonUtil.parseObject(body, 4, 256);
                    user = enforceUsername(require(data, "username"));
                } catch (IllegalArgumentException badInput) {
                    send(exchange, 400, badInput.getMessage());
                    return;
                }

                Path f = ROOT.resolve(user + ".properties");
                if (!Files.exists(f)) { send(exchange, 404, "not found"); return; }
                Properties p = new Properties();
                try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                byte[] nonce = new byte[32]; new java.security.SecureRandom().nextBytes(nonce);
                String nonceB64 = B64_ENC.encodeToString(nonce);
                String json = "{"+
                        "\"nonceB64\":"+JsonUtil.quote(nonceB64)+","+
                        "\"saltB64\":"+JsonUtil.quote(p.getProperty("saltB64"))+","+
                        "\"publicKeyB64\":"+JsonUtil.quote(p.getProperty("publicKeyB64"))+","+
                        "\"encPrivateB64\":"+JsonUtil.quote(p.getProperty("encPrivateB64"))+","+
                        "\"ivB64\":"+JsonUtil.quote(p.getProperty("ivB64"))
                        +"}";
                exchange.getResponseHeaders().add("X-Auth-Nonce", nonceB64);
                sendJson(exchange, 200, json);
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        srv.createContext("/auth/finish", exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use POST"); return; }

                String body;
                try {
                    body = readBody(exchange, MAX_GENERIC_BODY);
                } catch (IllegalArgumentException tooBig) {
                    send(exchange, 413, "body too large");
                    return;
                }

                String user;
                byte[] nonce;
                byte[] sig;
                try {
                    Map<String, String> data = JsonUtil.parseObject(body, 8, 2048);
                    user = enforceUsername(require(data, "username"));
                    nonce = decodeBase64("nonceB64", require(data, "nonceB64"), 16, 128);
                    sig = decodeBase64("signatureB64", require(data, "signatureB64"), 64, 4096);
                } catch (IllegalArgumentException badInput) {
                    send(exchange, 400, badInput.getMessage());
                    return;
                }

                Path f = ROOT.resolve(user + ".properties");
                if (!Files.exists(f)) { send(exchange, 404, "not found"); return; }
                Properties p = new Properties();
                try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                byte[] pubBytes = decodeBase64("publicKeyB64", p.getProperty("publicKeyB64"), 256, 4096);
                java.security.PublicKey pk = java.security.KeyFactory.getInstance("RSA")
                        .generatePublic(new java.security.spec.X509EncodedKeySpec(pubBytes));
                java.security.Signature s = java.security.Signature.getInstance("RSASSA-PSS");
                s.setParameter(new java.security.spec.PSSParameterSpec(
                        "SHA-256", "MGF1", new java.security.spec.MGF1ParameterSpec("SHA-256"), 32, 1));
                s.initVerify(pk);
                s.update(nonce);
                boolean ok = s.verify(sig);
                if (!ok) { send(exchange, 401, "bad signature"); return; }
                String role = p.getProperty("role","USER").toUpperCase();
                String token = java.util.UUID.randomUUID().toString().replace("-", "");
                SESSIONS.put(token, new Session(user, role));
                String out = "{"+
                        "\"ok\":true,"+
                        "\"token\":"+JsonUtil.quote(token)+","+
                        "\"role\":"+JsonUtil.quote(role)+","+
                        "\"username\":"+JsonUtil.quote(user)
                        +"}";
                sendJson(exchange, 200, out);
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // Devuelve un fichero concreto en JSON (metadatos + ciphertext)
        srv.createContext("/file", exchange -> {
            try {
                Session sess = getSession(exchange);
                if (sess == null) { send(exchange, 401, "unauthorized"); return; }
                // Ruta esperada: /file/{user}/{id}
                String path = exchange.getRequestURI().getPath();
                String[] parts = path.split("/");
                if (parts.length < 4) { send(exchange, 400, "missing user or id"); return; }
                String user = parts[2];
                String id = parts[3];
                String recipient = parts.length >= 5 ? parts[4] : null;
                Path f = FILES.resolve(user).resolve(id+".properties");
                if (!Files.exists(f)) {
                    // Búsqueda tolerante: localizar por id en cualquier owner
                    Path found = null;
                    if (Files.exists(FILES)) {
                        try (DirectoryStream<Path> owners = Files.newDirectoryStream(FILES)) {
                            for (Path ownerDir : owners) {
                                Path candidate = ownerDir.resolve(id+".properties");
                                if (Files.exists(candidate)) { found = candidate; break; }
                            }
                        }
                    }
                    if (found == null) { send(exchange, 404, "not found"); return; }
                    f = found;
                }

                Properties p = new Properties();
                try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                boolean isOwner = user.equals(sess.user);
                boolean isRecipient = p.getProperty("wrap."+sess.user) != null;
                if (!"ADMIN".equals(sess.role) && !(isOwner || isRecipient)) { send(exchange, 403, "forbidden"); return; }
                String cekWrap = recipient == null ? p.getProperty("cekWrappedB64") : p.getProperty("wrap."+recipient);
                if (cekWrap == null) cekWrap = p.getProperty("cekWrappedB64");
                String json = "{"+
                        "\"id\":"+JsonUtil.quote(p.getProperty("id"))+","+
                        "\"filename\":"+JsonUtil.quote(p.getProperty("filename"))+","+
                        "\"ivB64\":"+JsonUtil.quote(p.getProperty("ivB64"))+","+
                        "\"cekWrappedB64\":"+JsonUtil.quote(cekWrap)+","+
                        "\"ctB64\":"+JsonUtil.quote(p.getProperty("ctB64"))
                        +"}";
                sendJson(exchange, 200, json);
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // Añade un destinatario: envuelve CEK para user y guarda bajo wrap.<user>
        srv.createContext("/share", exchange -> {
            try {
                Session sess = getSession(exchange);
                if (sess == null) { send(exchange, 401, "unauthorized"); return; }
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use POST"); return; }
                // Ruta: /share/{owner}/{id}
                String path = exchange.getRequestURI().getPath();
                String[] parts = path.split("/");
                if (parts.length < 4) { send(exchange, 400, "missing owner or id"); return; }
                String owner = parts[2];
                String id = parts[3];
                if (!"ADMIN".equals(sess.role) && !sess.user.equals(owner)) { send(exchange, 403, "forbidden"); return; }
                if ("WORKER".equalsIgnoreCase(sess.role) || "AUDITOR".equalsIgnoreCase(sess.role)) { send(exchange, 403, "role cannot share"); return; }
                Path f = FILES.resolve(owner).resolve(id+".properties");
                if (!Files.exists(f)) { send(exchange, 404, "not found"); return; }

                String body;
                try {
                    body = readBody(exchange, MAX_GENERIC_BODY);
                } catch (IllegalArgumentException tooBig) {
                    send(exchange, 413, "body too large");
                    return;
                }

                try {
                    Map<String, String> data = JsonUtil.parseObject(body, 8, 2048);
                    String target = enforceUsername(require(data, "user"));
                    String cekWrapB64 = canonicalBase64("cekWrappedB64", require(data, "cekWrappedB64"), 32, 1024);
                    Properties p = new Properties();
                    try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                    p.setProperty("wrap."+target, cekWrapB64);
                    try (OutputStream os = Files.newOutputStream(f)) { p.store(os, "File record"); }
                    send(exchange, 200, "shared");
                } catch (IllegalArgumentException badInput) {
                    send(exchange, 400, badInput.getMessage());
                }
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });
        
        // Un único hilo por defecto (suficiente para la práctica)
        srv.setExecutor(null);
        srv.start();
        if (srv instanceof HttpsServer) {
            System.out.println("Server running on https://localhost:" + TLS_PORT + " (keystore server_keystore.p12)");
        } else {
            System.out.println("Server running on http://localhost:" + PORT + " (TLS no configurado, crea server_keystore.p12)");
        }

        // Hook para liberar el puerto al cerrar Eclipse o el programa
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n🧹 Cerrando servidor y liberando puerto " + PORT + "...");
            srv.stop(0);
            System.out.println("Servidor detenido correctamente.");
        }));
    }

    // --- Handler dedicado para /register (POST) ---
    static class RegisterHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            // Only accept POST
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                send(exchange, 405, "use POST"); return;
            }
            try {
                String body = readBody(exchange, MAX_REGISTER_BODY);
                Map<String, String> data = JsonUtil.parseObject(body, 12, 2048);

                String user = enforceUsername(require(data, "username"));
                String saltB64 = canonicalBase64("saltB64", require(data, "saltB64"), 16, 32);
                String pubB64 = canonicalBase64("publicKeyB64", require(data, "publicKeyB64"), 256, 4096);
                String encPriv = canonicalBase64("encPrivateB64", require(data, "encPrivateB64"), 256, 6144);
                String ivB64 = canonicalBase64("ivB64", require(data, "ivB64"), 12, 48);

                Path f = ROOT.resolve(user + ".properties");
                if (Files.exists(f)) { send(exchange, 409, "user exists"); return; }

                Properties p = new Properties();
                p.setProperty("username", user);
                p.setProperty("saltB64", saltB64);
                p.setProperty("publicKeyB64", pubB64);
                p.setProperty("encPrivateB64", encPriv);
                p.setProperty("ivB64", ivB64);

                try (OutputStream os = Files.newOutputStream(f)) { p.store(os, "User record"); }
                send(exchange, 201, "created");
            } catch (IllegalArgumentException e) {
                send(exchange, 400, e.getMessage());
            }
        }
    }

    // --- Utilidades comunes ---

    /** Devuelve el último segmento de una ruta: /user/alex -> "alex" */
    private static String lastPathSegment(URI uri) {
        String p = uri.getPath();
        int i = p.lastIndexOf('/');
        return (i>=0 && i+1<p.length()) ? p.substring(i+1) : null;
    }

    /** Sends plain text responses with the desired HTTP status code. */
    private static void send(HttpExchange ex, int code, String txt) throws IOException {
        byte[] out = txt.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type","text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, out.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(out); }
    }

    /** Sends JSON responses with the desired HTTP status code. */
    private static void sendJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] out = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type","application/json; charset=utf-8");
        ex.sendResponseHeaders(code, out.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(out); }
    }

    /** Escapa comillas para embutir valores en JSON manual */
    private static String esc(String s){ return s==null? "": s.replace("\"","\\\""); }

    /** Resolves the bearer token from the Authorization header. */
    private static Session getSession(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("Authorization");
        if (h == null || !h.startsWith("Bearer ")) return null;
        String tok = h.substring(7);
        return SESSIONS.get(tok);
    }

    /** Reads the request body enforcing an upper bound in bytes. */
    private static String readBody(HttpExchange exchange, int maxBytes) throws IOException {
        try (InputStream in = exchange.getRequestBody(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int total = 0;
            int read;
            while ((read = in.read(buf)) != -1) {
                total += read;
                if (total > maxBytes) {
                    throw new IllegalArgumentException("body too large");
                }
                baos.write(buf, 0, read);
            }
            return baos.toString(StandardCharsets.UTF_8);
        }
    }

    /** Returns a trimmed field from the parsed JSON map or fails fast. */
    private static String require(Map<String, String> data, String key) {
        String value = data.get(key);
        if (value == null) {
            throw new IllegalArgumentException("missing field: " + key);
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("empty field: " + key);
        }
        return trimmed;
    }

    /** Validates usernames against the server policy. */
    private static String enforceUsername(String raw) {
        String candidate = raw.trim();
        if (!USERNAME_PATTERN.matcher(candidate).matches()) {
            throw new IllegalArgumentException("invalid username");
        }
        return candidate;
    }

    /** Ensures filenames remain within allowed characters and length. */
    private static String enforceFilename(String raw) {
        String name = raw.trim();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("invalid filename");
        }
        if (name.length() > MAX_FILENAME_LENGTH) {
            throw new IllegalArgumentException("filename too long");
        }
        if (name.contains("/") || name.contains("\\") || name.contains("..")) {
            throw new IllegalArgumentException("invalid filename");
        }
        for (int i = 0; i < name.length(); i++) {
            char ch = name.charAt(i);
            if (ch < 0x20) {
                throw new IllegalArgumentException("invalid filename");
            }
        }
        return name;
    }

    /** Canonicalises a Base64 field after validating its decoded size. */
    private static String canonicalBase64(String field, String value, int minBytes, int maxBytes) {
        byte[] decoded = decodeBase64(field, value, minBytes, maxBytes);
        return B64_ENC.encodeToString(decoded);
    }

    /** Decodes Base64 data enforcing size constraints. */
    private static byte[] decodeBase64(String field, String value, int minBytes, int maxBytes) {
        String sanitized = value.trim();
        if (sanitized.isEmpty() && minBytes > 0) {
            throw new IllegalArgumentException("missing field: " + field);
        }
        try {
            byte[] out = B64_DEC.decode(sanitized);
            if (out.length < minBytes) {
                throw new IllegalArgumentException(field + " too short");
            }
            if (out.length > maxBytes) {
                throw new IllegalArgumentException(field + " too large");
            }
            return out;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid base64: " + field);
        }
    }

    /** Normalises and validates roles allowed in the system. */
    private static String enforceRole(String raw) {
        String role = raw.trim().toUpperCase();
        if (!ALLOWED_ROLES.contains(role)) {
            throw new IllegalArgumentException("invalid role");
        }
        return role;
    }
}