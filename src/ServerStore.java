/**
 * ServerStore.java
 * 
 * Clase que gestiona la comunicación con el servidor (ServerMain)
 * mediante peticiones HTTP para registrar y obtener usuarios.
 * 
 * Utiliza:
 *  - java.net.HttpURLConnection: para enviar peticiones HTTP (GET, POST)
 *  - java.io.*: para leer y escribir flujos de datos
 *  - java.security.*: para reconstruir claves RSA desde Base64
 *  - java.util.Base64: para codificar y decodificar binarios en texto
 *  - java.nio.charset.StandardCharsets: para asegurar codificación UTF-8
 *  - java.util.Optional: para manejar usuarios opcionales de forma segura
 */

import java.io.*;                        // Entrada y salida de datos (InputStream, OutputStream, IOException)
import java.net.HttpURLConnection;       // Clase para conexiones HTTP cliente-servidor
import java.net.URL;                     // Representa una dirección web (ej: http://localhost:8080)
import java.nio.charset.StandardCharsets; // Define codificación UTF-8 para texto
import java.security.KeyFactory;         // Permite reconstruir claves RSA desde sus bytes
import java.security.PublicKey;          // Representa una clave pública RSA
import java.security.spec.X509EncodedKeySpec; // Define el formato X.509 estándar para claves públicas
import java.util.Base64;                 // Codificación y decodificación Base64
import java.util.Optional;               // Maneja valores opcionales sin usar null
import javax.net.ssl.HttpsURLConnection; // Conexiones HTTPS
import javax.net.ssl.SSLContext;         // Contexto TLS para confiar en dev
import javax.net.ssl.TrustManager;       // Gestor de confianza
import javax.net.ssl.X509TrustManager;   // TrustManager X.509
import javax.net.ssl.HostnameVerifier;   // Verificador de host
import javax.net.ssl.SSLSession;         // Sesión SSL

public final class ServerStore {

    // Dirección base del servidor HTTP
    private static final String BASE = "https://localhost:8443";
    private static final boolean DEV_TRUST_ALL = true; // Solo para entorno de desarrollo

    static {
        // Activa confianza amplia para el certificado de desarrollo (self-signed)
        if (BASE.startsWith("https") && DEV_TRUST_ALL) {
            try { enableDevHttpsTrust(); } catch (Exception e) { e.printStackTrace(); }
        }
    }

    /**
     * Clase interna que representa un usuario con todos sus datos
     * recuperados del servidor: username, claves, salt, iv, etc.
     */
    public static final class UserRecord {
        public final String username;
        public final byte[] salt, encPriv, iv;
        public final PublicKey publicKey;
        public UserRecord(String u, byte[] s, PublicKey pub, byte[] e, byte[] i) {
            username=u; salt=s; publicKey=pub; encPriv=e; iv=i;
        }
    }

    /** Estructura para ficheros cifrados descargados. */
    public static final class EncryptedFile {
        public final String id;
        public final String filename;
        public final byte[] iv;
        public final byte[] cekWrapped;
        public final byte[] ciphertext;
        public EncryptedFile(String id, String filename, byte[] iv, byte[] cekWrapped, byte[] ciphertext) {
            this.id = id; this.filename = filename; this.iv = iv; this.cekWrapped = cekWrapped; this.ciphertext = ciphertext;
        }
    }

    /**
     * Comprueba si un usuario existe en el servidor remoto
     * mediante una petición HTTP GET a /exists/{usuario}.
     */
    /** Comprueba si existe un usuario mediante GET /exists/{username}. */
    public static boolean exists(String username) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/exists/" + username).openConnection();
        c.setRequestMethod("GET");
        int code = c.getResponseCode();
        c.disconnect();
        return code == 200; // Devuelve true si el usuario existe
    }

    /**
     * Carga la información completa de un usuario desde el servidor (GET /user/{username})
     * Devuelve Optional.empty() si no existe.
     */
    /** Carga el registro de usuario con GET /user/{username}. */
    public static Optional<UserRecord> load(String username) {
        try {
            // Crear la conexión HTTP
            HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/user/" + username).openConnection();
            c.setRequestMethod("GET");
            
            // Si no existe el usuario, devolver vacío
            if (c.getResponseCode() != 200) {
                c.disconnect();
                return Optional.empty();
            }

            // Leer respuesta en formato JSON
            String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            c.disconnect();

            // Extraer campos del JSON manualmente (sin librerías externas)
            String u   = jsonGet(json, "username");
            byte[] salt= b64d(jsonGet(json, "saltB64"));
            byte[] pub = b64d(jsonGet(json, "publicKeyB64"));
            byte[] enc = b64d(jsonGet(json, "encPrivateB64"));
            byte[] iv  = b64d(jsonGet(json, "ivB64"));
            
            // Reconstruir la clave pública RSA desde formato X.509
            PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub));
            
            // Crear objeto UserRecord con toda la información
            return Optional.of(new UserRecord(u, salt, pk, enc, iv));

        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }

    // --- Auth (challenge) ---
    /** Inicia autenticación: devuelve nonce y materiales para abrir la privada. */
    public static String authStart(String username) throws IOException {
        String json = "{\"username\":\""+esc(username)+"\"}";
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/auth/start").openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        if (c.getResponseCode() != 200) { throw new IOException("server returned " + c.getResponseCode()); }
        String resp = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        return resp; // JSON crudo con nonceB64, saltB64, publicKeyB64, encPrivateB64, ivB64
    }

    /** Finaliza autenticación enviando firma del nonce. */
    public static void authFinish(String username, String nonceB64, String signatureB64) throws IOException {
        String json = "{"+
                "\"username\":\""+esc(username)+"\","+
                "\"nonceB64\":\""+nonceB64+"\","+
                "\"signatureB64\":\""+signatureB64+"\""+
                "}";
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/auth/finish").openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        if (c.getResponseCode() != 200) { throw new IOException("server returned " + c.getResponseCode()); }
        c.disconnect();
    }

    /**
     * Envía al servidor la información de un nuevo usuario
     * mediante una petición HTTP POST /register con datos en JSON.
     */
    /** Registra un nuevo usuario enviando JSON a /register (POST). */
    public static void save(UserRecord ur) throws IOException {

        // Construir JSON con los campos del usuario
        String json = "{"+
                "\"username\":\""+esc(ur.username)+"\","+
                "\"saltB64\":\""+b64(ur.salt)+"\","+
                "\"publicKeyB64\":\""+b64(ur.publicKey.getEncoded())+"\","+
                "\"encPrivateB64\":\""+b64(ur.encPriv)+"\","+
                "\"ivB64\":\""+b64(ur.iv)+"\""+
                "}";

        byte[] body = json.getBytes(StandardCharsets.UTF_8);

        // Crear la conexión HTTP tipo POST
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/register").openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");

        // Enviar el cuerpo JSON al servidor
        try (OutputStream os = c.getOutputStream()) {
            os.write(body);
        }
        
        // Comprobar respuesta del servidor
        int code = c.getResponseCode();
        if (code != 201) throw new IOException("server returned " + code);
        c.disconnect();
    }

    // --- Files API (MVP) ---
    /** Sube el JSON de un fichero cifrado para un usuario. */
    public static void uploadFile(String username, String filename, byte[] iv, byte[] cekWrapped, byte[] ciphertext) throws IOException {
        String json = "{"+
                "\"filename\":\""+esc(filename)+"\","+
                "\"ivB64\":\""+b64(iv)+"\","+
                "\"cekWrappedB64\":\""+b64(cekWrapped)+"\","+
                "\"ctB64\":\""+b64(ciphertext)+"\""+
                "}";
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/upload/" + username).openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        int code = c.getResponseCode();
        if (code != 201) throw new IOException("server returned " + code);
        c.disconnect();
    }

    /** Lista los ficheros del usuario y devuelve [id, filename]. */
    public static String[][] listFiles(String username) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/files/" + username).openConnection();
        c.setRequestMethod("GET");
        if (c.getResponseCode() != 200) { c.disconnect(); throw new IOException("server returned " + c.getResponseCode()); }
        String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        // Minimal JSON parsing: expecting array of {id, filename}
        // Parse naively to avoid deps
        java.util.List<String[]> out = new java.util.ArrayList<>();
        int i = 0;
        while (true) {
            int idIdx = json.indexOf("\"id\":\"", i); if (idIdx<0) break;
            int idStart = idIdx+6; int idEnd = json.indexOf('"', idStart);
            String id = json.substring(idStart, idEnd);
            int fnIdx = json.indexOf("\"filename\":\"", idEnd); if (fnIdx<0) break;
            int fnStart = fnIdx+12; int fnEnd = json.indexOf('"', fnStart);
            String filename = json.substring(fnStart, fnEnd);
            out.add(new String[]{id, filename});
            i = fnEnd+1;
        }
        return out.toArray(new String[0][0]);
    }

    /** Lista ficheros compartidos conmigo: devuelve [owner, id, filename]. */
    public static String[][] listShared(String username) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/files/shared/" + username).openConnection();
        c.setRequestMethod("GET");
        if (c.getResponseCode() != 200) { c.disconnect(); throw new IOException("server returned " + c.getResponseCode()); }
        String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        java.util.List<String[]> out = new java.util.ArrayList<>();
        int i = 0;
        while (true) {
            int oIdx = json.indexOf("\"owner\":\"", i); if (oIdx<0) break;
            int oStart = oIdx+9; int oEnd = json.indexOf('"', oStart);
            String owner = json.substring(oStart, oEnd);
            int idIdx = json.indexOf("\"id\":\"", oEnd); if (idIdx<0) break;
            int idStart = idIdx+6; int idEnd = json.indexOf('"', idStart);
            String id = json.substring(idStart, idEnd);
            int fnIdx = json.indexOf("\"filename\":\"", idEnd); if (fnIdx<0) break;
            int fnStart = fnIdx+12; int fnEnd = json.indexOf('"', fnStart);
            String filename = json.substring(fnStart, fnEnd);
            out.add(new String[]{owner, id, filename});
            i = fnEnd+1;
        }
        return out.toArray(new String[0][0]);
    }

    /** Descarga un fichero cifrado: GET /file/{user}/{id}. */
    public static EncryptedFile downloadFile(String username, String id) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/file/" + username + "/" + id).openConnection();
        c.setRequestMethod("GET");
        if (c.getResponseCode() != 200) { c.disconnect(); throw new IOException("server returned " + c.getResponseCode()); }
        String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        String fid = jsonGet(json, "id");
        String fname = jsonGet(json, "filename");
        byte[] iv = b64d(jsonGet(json, "ivB64"));
        byte[] cekW = b64d(jsonGet(json, "cekWrappedB64"));
        byte[] ct = b64d(jsonGet(json, "ctB64"));
        return new EncryptedFile(fid, fname, iv, cekW, ct);
    }

    /** Descarga un fichero cifrado especificando destinatario compartido. */
    public static EncryptedFile downloadFileAs(String owner, String id, String recipient) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/file/" + owner + "/" + id + "/" + recipient).openConnection();
        c.setRequestMethod("GET");
        if (c.getResponseCode() != 200) { c.disconnect(); throw new IOException("server returned " + c.getResponseCode()); }
        String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        String fid = jsonGet(json, "id");
        String fname = jsonGet(json, "filename");
        byte[] iv = b64d(jsonGet(json, "ivB64"));
        byte[] cekW = b64d(jsonGet(json, "cekWrappedB64"));
        byte[] ct = b64d(jsonGet(json, "ctB64"));
        return new EncryptedFile(fid, fname, iv, cekW, ct);
    }

    /** Comparte un fichero con un usuario, enviando su CEK envuelta. */
    public static void shareFile(String owner, String id, String targetUser, byte[] cekWrapped) throws IOException {
        String json = "{"+
                "\"user\":\""+esc(targetUser)+"\","+
                "\"cekWrappedB64\":\""+b64(cekWrapped)+"\""+
                "}";
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + "/share/" + owner + "/" + id).openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        if (c.getResponseCode() != 200) { throw new IOException("server returned " + c.getResponseCode()); }
        c.disconnect();
    }

    // --- Métodos auxiliares de codificación/decodificación ---

    /** Codifica bytes en texto Base64 */
    private static String b64(byte[] x) {
        return Base64.getEncoder().encodeToString(x);
    }

    /** Decodifica texto Base64 a bytes */
    private static byte[] b64d(String s) {
        return Base64.getDecoder().decode(s);
    }

    /** Escapa comillas para insertar texto dentro de JSON */
    private static String esc(String s) {
        return s == null ? "" : s.replace("\"", "\\\"");
    }

    /**
     * Extrae un valor de un JSON plano en formato:
     * {"clave":"valor"}
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

    /** Configura HTTPS para confiar en cualquier certificado (solo DEV). */
    private static void enableDevHttpsTrust() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAll, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) { return true; }
        });
    }
}
