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
import java.net.URI;                     // Representa un URI inmutable y seguro
import java.nio.charset.StandardCharsets; // Define codificación UTF-8 para texto
import java.security.KeyFactory;         // Permite reconstruir claves RSA desde sus bytes
import java.security.PublicKey;          // Representa una clave pública RSA
import java.security.spec.X509EncodedKeySpec; // Define el formato X.509 estándar para claves públicas
import java.util.Base64;                 // Codificación y decodificación Base64
import java.util.Optional;               // Maneja valores opcionales sin usar null
import java.util.Map;                    // Representaciones JSON clave-valor
import java.util.List;                   // Arrays JSON de objetos
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
    private static final int LARGE_JSON_STRING = 4_194_304; // 4 MiB for Base64 payloads

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
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/exists/" + username).toURL().openConnection();
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
            HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/user/" + username).toURL().openConnection();
            c.setRequestMethod("GET");
            
            // Si no existe el usuario, devolver vacío
            if (c.getResponseCode() != 200) {
                c.disconnect();
                return Optional.empty();
            }

            // Leer respuesta en formato JSON
            String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            c.disconnect();

            Map<String, String> data = JsonUtil.parseObject(json, 16, 4096);
            String u   = require(data, "username");
            byte[] salt= b64d(require(data, "saltB64"));
            byte[] pub = b64d(require(data, "publicKeyB64"));
            byte[] enc = b64d(require(data, "encPrivateB64"));
            byte[] iv  = b64d(require(data, "ivB64"));
            
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
        String json = "{"+"\"username\":"+JsonUtil.quote(username)+"}";
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/auth/start").toURL().openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        int code = c.getResponseCode();
        InputStream stream = code >= 200 && code < 300 ? c.getInputStream() : c.getErrorStream();
        String resp = stream != null ? new String(stream.readAllBytes(), StandardCharsets.UTF_8) : "";
        c.disconnect();
        if (code != 200) { throw new IOException(buildErrorMessage(code, resp)); }
        return resp; // JSON crudo con nonceB64, saltB64, publicKeyB64, encPrivateB64, ivB64
    }

    /** Finaliza autenticación: envía firma, recibe token y rol. */
    public static String[] authFinish(String username, String nonceB64, String signatureB64) throws IOException {
        String json = "{"+
                "\"username\":"+JsonUtil.quote(username)+","+
                "\"nonceB64\":"+JsonUtil.quote(nonceB64)+","+
                "\"signatureB64\":"+JsonUtil.quote(signatureB64)
                +"}";
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/auth/finish").toURL().openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        int code = c.getResponseCode();
        InputStream stream = code >= 200 && code < 300 ? c.getInputStream() : c.getErrorStream();
        String resp = stream != null ? new String(stream.readAllBytes(), StandardCharsets.UTF_8) : "";
        c.disconnect();
        if (code != 200) { throw new IOException(buildErrorMessage(code, resp)); }
        Map<String, String> data = JsonUtil.parseObject(resp, 8, 1024);
        String token = require(data, "token");
        String role = require(data, "role");
        return new String[]{token, role};
    }

    /**
     * Envía al servidor la información de un nuevo usuario
     * mediante una petición HTTP POST /register con datos en JSON.
     */
    /** Registra un nuevo usuario enviando JSON a /register (POST). */
    public static void save(UserRecord ur) throws IOException {

        // Construir JSON con los campos del usuario
        String json = "{"+
                "\"username\":"+JsonUtil.quote(ur.username)+","+
                "\"saltB64\":"+JsonUtil.quote(b64(ur.salt))+","+
                "\"publicKeyB64\":"+JsonUtil.quote(b64(ur.publicKey.getEncoded()))+","+
                "\"encPrivateB64\":"+JsonUtil.quote(b64(ur.encPriv))+","+
                "\"ivB64\":"+JsonUtil.quote(b64(ur.iv))
                +"}";

        byte[] body = json.getBytes(StandardCharsets.UTF_8);

        // Crear la conexión HTTP tipo POST
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/register").toURL().openConnection();
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
    public static void uploadFile(String username, String filename, byte[] iv, byte[] cekWrapped, byte[] ciphertext, String bearerToken) throws IOException {
        String json = "{"+
                "\"filename\":"+JsonUtil.quote(filename)+","+
                "\"ivB64\":"+JsonUtil.quote(b64(iv))+","+
                "\"cekWrappedB64\":"+JsonUtil.quote(b64(cekWrapped))+","+
                "\"ctB64\":"+JsonUtil.quote(b64(ciphertext))
                +"}";
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/upload/" + username).toURL().openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        int code = c.getResponseCode();
        if (code != 201) throw new IOException("server returned " + code);
        c.disconnect();
    }

    /** Lista los ficheros del usuario y devuelve [id, filename]. */
    public static String[][] listFiles(String username, String bearerToken) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/files/" + username).toURL().openConnection();
        c.setRequestMethod("GET");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        if (c.getResponseCode() != 200) { c.disconnect(); throw new IOException("server returned " + c.getResponseCode()); }
        String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        List<Map<String, String>> items = JsonUtil.parseArrayOfObjects(json, 1024, 8, 1024);
        String[][] result = new String[items.size()][2];
        for (int i = 0; i < items.size(); i++) {
            Map<String, String> item = items.get(i);
            result[i][0] = require(item, "id");
            result[i][1] = require(item, "filename");
        }
        return result;
    }

    /** Lista ficheros compartidos conmigo: devuelve [owner, id, filename]. */
    public static String[][] listShared(String username, String bearerToken) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/files/shared/" + username).toURL().openConnection();
        c.setRequestMethod("GET");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        if (c.getResponseCode() != 200) { c.disconnect(); throw new IOException("server returned " + c.getResponseCode()); }
        String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        List<Map<String, String>> items = JsonUtil.parseArrayOfObjects(json, 1024, 8, 1024);
        String[][] result = new String[items.size()][3];
        for (int i = 0; i < items.size(); i++) {
            Map<String, String> item = items.get(i);
            result[i][0] = require(item, "owner");
            result[i][1] = require(item, "id");
            result[i][2] = require(item, "filename");
        }
        return result;
    }

    /** Descarga un fichero cifrado: GET /file/{user}/{id}. */
    public static EncryptedFile downloadFile(String username, String id, String bearerToken) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/file/" + username + "/" + id).toURL().openConnection();
        c.setRequestMethod("GET");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        if (c.getResponseCode() != 200) { c.disconnect(); throw new IOException("server returned " + c.getResponseCode()); }
        String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        Map<String, String> data = JsonUtil.parseObject(json, 16, LARGE_JSON_STRING);
        String fid = require(data, "id");
        String fname = require(data, "filename");
        byte[] iv = b64d(require(data, "ivB64"));
        byte[] cekW = b64d(require(data, "cekWrappedB64"));
        byte[] ct = b64d(require(data, "ctB64"));
        return new EncryptedFile(fid, fname, iv, cekW, ct);
    }

    /** Descarga un fichero cifrado especificando destinatario compartido. */
    public static EncryptedFile downloadFileAs(String owner, String id, String recipient, String bearerToken) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/file/" + owner + "/" + id + "/" + recipient).toURL().openConnection();
        c.setRequestMethod("GET");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        if (c.getResponseCode() != 200) { c.disconnect(); throw new IOException("server returned " + c.getResponseCode()); }
        String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        Map<String, String> data = JsonUtil.parseObject(json, 16, LARGE_JSON_STRING);
        String fid = require(data, "id");
        String fname = require(data, "filename");
        byte[] iv = b64d(require(data, "ivB64"));
        byte[] cekW = b64d(require(data, "cekWrappedB64"));
        byte[] ct = b64d(require(data, "ctB64"));
        return new EncryptedFile(fid, fname, iv, cekW, ct);
    }

    // --- Admin API ---
    /** Lista todos los usuarios (ADMIN). */
    public static String[][] listAllUsers(String bearerToken) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/admin/users").toURL().openConnection();
        c.setRequestMethod("GET");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        if (c.getResponseCode() != 200) { c.disconnect(); throw new IOException("server returned " + c.getResponseCode()); }
        String json = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        c.disconnect();
        List<Map<String, String>> items = JsonUtil.parseArrayOfObjects(json, 1024, 4, 512);
        String[][] result = new String[items.size()][2];
        for (int i = 0; i < items.size(); i++) {
            Map<String, String> item = items.get(i);
            result[i][0] = require(item, "username");
            result[i][1] = require(item, "role");
        }
        return result;
    }

    /** Cambia el rol de un usuario (ADMIN). */
    public static void setUserRole(String username, String role, String bearerToken) throws IOException {
        String json = "{"+"\"username\":"+JsonUtil.quote(username)+",\"role\":"+JsonUtil.quote(role)+"}";
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/admin/setRole").toURL().openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        if (c.getResponseCode() != 200) { throw new IOException("server returned " + c.getResponseCode()); }
        c.disconnect();
    }

    /** Comparte un fichero con un usuario, enviando su CEK envuelta. */
    public static void shareFile(String owner, String id, String targetUser, byte[] cekWrapped, String bearerToken) throws IOException {
        String json = "{"+
                "\"user\":"+JsonUtil.quote(targetUser)+","+
                "\"cekWrappedB64\":"+JsonUtil.quote(b64(cekWrapped))
                +"}";
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/share/" + owner + "/" + id).toURL().openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        if (c.getResponseCode() != 200) { throw new IOException("server returned " + c.getResponseCode()); }
        c.disconnect();
    }

    /** Lista los destinatarios actuales de un fichero compartido. */
    public static String[] listShareRecipients(String owner, String id, String bearerToken) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/share/list/" + owner + "/" + id).toURL().openConnection();
        c.setRequestMethod("GET");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        int code = c.getResponseCode();
        InputStream stream = code >= 200 && code < 300 ? c.getInputStream() : c.getErrorStream();
        String json = stream != null ? new String(stream.readAllBytes(), StandardCharsets.UTF_8) : "";
        c.disconnect();
        if (code != 200) { throw new IOException(buildErrorMessage(code, json)); }
        List<String> list = JsonUtil.parseArrayOfStrings(json, 1024, 256);
        return list.toArray(new String[0]);
    }

    /** Revoca el acceso previamente compartido a un usuario. */
    public static void revokeShare(String owner, String id, String targetUser, String bearerToken) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(BASE + "/share/revoke/" + owner + "/" + id + "/" + targetUser).toURL().openConnection();
        c.setRequestMethod("DELETE");
        if (bearerToken != null) c.setRequestProperty("Authorization", "Bearer " + bearerToken);
        int code = c.getResponseCode();
        InputStream stream = code >= 200 && code < 300 ? c.getInputStream() : c.getErrorStream();
        String body = stream != null ? new String(stream.readAllBytes(), StandardCharsets.UTF_8) : "";
        c.disconnect();
        if (code != 200) { throw new IOException(buildErrorMessage(code, body)); }
    }

    // --- Métodos auxiliares de codificación/decodificación ---

    private static String require(Map<String, String> map, String key) {
        String value = map.get(key);
        if (value == null) {
            throw new IllegalArgumentException("missing field: " + key);
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("empty field: " + key);
        }
        return trimmed;
    }

    /** Codifica bytes en texto Base64 */
    private static String b64(byte[] x) {
        return Base64.getEncoder().encodeToString(x);
    }

    /** Decodifica texto Base64 a bytes */
    private static byte[] b64d(String s) {
        return Base64.getDecoder().decode(s);
    }

    private static String buildErrorMessage(int code, String body) {
        if (code == 401) {
            return "Sesión expirada o token inválido";
        }
        if (code == 423) {
            return body == null || body.isBlank() ? "Cuenta bloqueada temporalmente" : body.trim();
        }
        if (body == null || body.isBlank()) {
            return "server returned " + code;
        }
        return "server returned " + code + " - " + body.trim();
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
