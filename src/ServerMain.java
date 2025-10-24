// === Librerías del servidor HTTP embebido de Java (sin dependencias externas) ===
import com.sun.net.httpserver.HttpExchange; // Representa una petición/respuesta HTTP
import com.sun.net.httpserver.HttpHandler;  // Interfaz para manejar endpoints
import com.sun.net.httpserver.HttpServer;   // Servidor HTTP ligero embebido
import com.sun.net.httpserver.HttpsConfigurator; // Configurador HTTPS
import com.sun.net.httpserver.HttpsServer;  // Servidor HTTPS

// === E/S y utilidades de sistema de ficheros ===
import java.io.*;                           // InputStream/OutputStream, IOException
import java.net.InetSocketAddress;          // Dirección/puerto para el servidor
import java.net.URI;                        // Para inspeccionar rutas
import java.nio.charset.StandardCharsets;   // Codificación UTF-8 estable
import java.nio.file.*;                     // Paths, Files… para leer/escribir .properties
import java.util.Properties;                // Formato .properties simple (clave=valor)
import javax.net.ssl.KeyManagerFactory;     // Gestor de claves para TLS
import javax.net.ssl.SSLContext;            // Contexto TLS
import java.security.KeyStore;              // Almacén de claves
import java.util.UUID;                      // Identificadores únicos para ficheros

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
                String json = "{"
                        + "\"username\":\""+esc(p.getProperty("username"))+"\","
                        + "\"saltB64\":\""+p.getProperty("saltB64")+"\","
                        + "\"publicKeyB64\":\""+p.getProperty("publicKeyB64")+"\","
                        + "\"encPrivateB64\":\""+p.getProperty("encPrivateB64")+"\","
                        + "\"ivB64\":\""+p.getProperty("ivB64")+"\""
                        + "}";
                sendJson(exchange, 200, json);
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // POST /register -> Crea un usuario a partir de un JSON con 6 campos
        srv.createContext("/register", new RegisterHandler());

        // --- Ficheros (MVP simple, sin auth aún) ---
        // Recibe un JSON de fichero cifrado y guarda metadatos y ciphertext
        srv.createContext("/upload", exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use POST"); return; }
                String user = lastPathSegment(exchange.getRequestURI());
                if (user == null) { send(exchange, 400, "missing user"); return; }

                // Esperamos un cuerpo binario con un encabezado JSON mínimo en query?
                // Para MVP: recibimos cuerpo como JSON texto: {filename, ivB64, cekWrappedB64, ctB64}
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String filename = jsonGet(body, "filename");
                String ivB64    = jsonGet(body, "ivB64");
                String cekWrapB64 = jsonGet(body, "cekWrappedB64");
                String ctB64    = jsonGet(body, "ctB64");
                if (filename==null || ivB64==null || cekWrapB64==null || ctB64==null) { send(exchange, 400, "missing fields"); return; }

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
                sendJson(exchange, 201, "{\"fileId\":\""+id+"\"}");
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // Lista ficheros subidos (id + filename) para un usuario
        srv.createContext("/files", exchange -> {
            try {
                String user = lastPathSegment(exchange.getRequestURI());
                if (user == null) { send(exchange, 400, "missing user"); return; }
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
                          .append("\"id\":\"").append(esc(p.getProperty("id"))).append("\",")
                          .append("\"filename\":\"").append(esc(p.getProperty("filename"))).append("\"")
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
                String user = lastPathSegment(exchange.getRequestURI());
                if (user == null) { send(exchange, 400, "missing user"); return; }
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
                                      .append("\"owner\":\"").append(esc(owner)).append("\",")
                                      .append("\"id\":\"").append(esc(p.getProperty("id"))).append("\",")
                                      .append("\"filename\":\"").append(esc(p.getProperty("filename"))).append("\"")
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

        // --- Autenticación por reto/firma (MVP sin tokens) ---
        srv.createContext("/auth/start", exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use POST"); return; }
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String user = jsonGet(body, "username");
                if (user == null) { send(exchange, 400, "missing username"); return; }
                Path f = ROOT.resolve(user + ".properties");
                if (!Files.exists(f)) { send(exchange, 404, "not found"); return; }
                Properties p = new Properties();
                try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                // Generar nonce aleatorio
                byte[] nonce = new byte[32]; new java.security.SecureRandom().nextBytes(nonce);
                String json = "{"+
                        "\"nonceB64\":\""+java.util.Base64.getEncoder().encodeToString(nonce)+"\","+
                        "\"saltB64\":\""+p.getProperty("saltB64")+"\","+
                        "\"publicKeyB64\":\""+p.getProperty("publicKeyB64")+"\","+
                        "\"encPrivateB64\":\""+p.getProperty("encPrivateB64")+"\","+
                        "\"ivB64\":\""+p.getProperty("ivB64")+"\""+
                        "}";
                exchange.getResponseHeaders().add("X-Auth-Nonce", java.util.Base64.getEncoder().encodeToString(nonce));
                sendJson(exchange, 200, json);
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        srv.createContext("/auth/finish", exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use POST"); return; }
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String user = jsonGet(body, "username");
                String nonceB64 = jsonGet(body, "nonceB64");
                String sigB64 = jsonGet(body, "signatureB64");
                if (user==null || nonceB64==null || sigB64==null) { send(exchange, 400, "missing fields"); return; }
                Path f = ROOT.resolve(user + ".properties");
                if (!Files.exists(f)) { send(exchange, 404, "not found"); return; }
                Properties p = new Properties();
                try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                byte[] pub = java.util.Base64.getDecoder().decode(p.getProperty("publicKeyB64"));
                java.security.PublicKey pk = java.security.KeyFactory.getInstance("RSA")
                        .generatePublic(new java.security.spec.X509EncodedKeySpec(pub));
                byte[] nonce = java.util.Base64.getDecoder().decode(nonceB64);
                byte[] sig = java.util.Base64.getDecoder().decode(sigB64);
                java.security.Signature s = java.security.Signature.getInstance("RSASSA-PSS");
                s.setParameter(new java.security.spec.PSSParameterSpec(
                        "SHA-256", "MGF1", new java.security.spec.MGF1ParameterSpec("SHA-256"), 32, 1));
                s.initVerify(pk);
                s.update(nonce);
                boolean ok = s.verify(sig);
                if (!ok) { send(exchange, 401, "bad signature"); return; }
                sendJson(exchange, 200, "{\"ok\":true}");
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // Devuelve un fichero concreto en JSON (metadatos + ciphertext)
        srv.createContext("/file", exchange -> {
            try {
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
                String cekWrap = recipient == null ? p.getProperty("cekWrappedB64") : p.getProperty("wrap."+recipient);
                if (cekWrap == null) cekWrap = p.getProperty("cekWrappedB64");
                String json = "{"+
                        "\"id\":\""+esc(p.getProperty("id"))+"\","+
                        "\"filename\":\""+esc(p.getProperty("filename"))+"\","+
                        "\"ivB64\":\""+p.getProperty("ivB64")+"\","+
                        "\"cekWrappedB64\":\""+cekWrap+"\","+
                        "\"ctB64\":\""+p.getProperty("ctB64")+"\""+
                        "}";
                sendJson(exchange, 200, json);
            } catch (Exception e) { send(exchange, 500, e.toString()); }
        });

        // Añade un destinatario: envuelve CEK para user y guarda bajo wrap.<user>
        srv.createContext("/share", exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { send(exchange, 405, "use POST"); return; }
                // Ruta: /share/{owner}/{id}
                String path = exchange.getRequestURI().getPath();
                String[] parts = path.split("/");
                if (parts.length < 4) { send(exchange, 400, "missing owner or id"); return; }
                String owner = parts[2];
                String id = parts[3];
                Path f = FILES.resolve(owner).resolve(id+".properties");
                if (!Files.exists(f)) { send(exchange, 404, "not found"); return; }
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String target = jsonGet(body, "user");
                String cekWrapB64 = jsonGet(body, "cekWrappedB64");
                if (target==null || cekWrapB64==null) { send(exchange, 400, "missing fields"); return; }
                Properties p = new Properties();
                try (InputStream is = Files.newInputStream(f)) { p.load(is); }
                p.setProperty("wrap."+target, cekWrapB64);
                try (OutputStream os = Files.newOutputStream(f)) { p.store(os, "File record"); }
                send(exchange, 200, "shared");
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
            // Solo acepta POST
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                send(exchange, 405, "use POST"); return;
            }
            // Lee el cuerpo de la petición (JSON plano UTF-8)
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

            // Extrae campos "clave":"valor" (parser naive)
            String user = jsonGet(body, "username");
            String saltB64 = jsonGet(body, "saltB64");
            String pubB64  = jsonGet(body, "publicKeyB64");
            String encPriv = jsonGet(body, "encPrivateB64");
            String ivB64   = jsonGet(body, "ivB64");

            // Validación de campos requeridos (ya no se acepta dkB64)
            if (user==null || saltB64==null || pubB64==null || encPriv==null || ivB64==null) {
                send(exchange, 400, "missing fields"); return;
            }

            // Evita sobreescritura: 409 si ya existe
            Path f = ROOT.resolve(user + ".properties");
            if (Files.exists(f)) { send(exchange, 409, "user exists"); return; }

            // Guarda el registro como .properties
            Properties p = new Properties();
            p.setProperty("username", user);
            p.setProperty("saltB64", saltB64);
            p.setProperty("publicKeyB64", pubB64);
            p.setProperty("encPrivateB64", encPriv);
            p.setProperty("ivB64", ivB64);

            try (OutputStream os = Files.newOutputStream(f)) { p.store(os, "User record"); }
            send(exchange, 201, "created");
        }
    }

    // --- Utilidades comunes ---

    /** Devuelve el último segmento de una ruta: /user/alex -> "alex" */
    private static String lastPathSegment(URI uri) {
        String p = uri.getPath();
        int i = p.lastIndexOf('/');
        return (i>=0 && i+1<p.length()) ? p.substring(i+1) : null;
    }

    /** Respuesta de texto plano con código HTTP */
    private static void send(HttpExchange ex, int code, String txt) throws IOException {
        byte[] out = txt.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type","text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, out.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(out); }
    }

    /** Respuesta JSON con código HTTP */
    private static void sendJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] out = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type","application/json; charset=utf-8");
        ex.sendResponseHeaders(code, out.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(out); }
    }

    /** Escapa comillas para embutir valores en JSON manual */
    private static String esc(String s){ return s==null? "": s.replace("\"","\\\""); }

    /**
     * Parser JSON muy sencillo: busca "key":"value" y extrae el valor.
     * (Válido para esta práctica; no soporta anidados ni arrays)
     */
    private static String jsonGet(String json, String key) {
        String pat = "\"" + key + "\":\"";
        int i = json.indexOf(pat);
        if (i<0) return null;
        int start = i + pat.length();
        int end = json.indexOf('"', start);
        if (end<0) return null;
        return json.substring(start, end);
    }
}