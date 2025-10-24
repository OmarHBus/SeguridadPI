// === Librerías de Java para derivación de claves seguras y codificación ===

// Clases del paquete javax.crypto: proporcionan herramientas criptográficas estándar
import javax.crypto.SecretKeyFactory; 
// → Se usa para generar claves derivadas a partir de contraseñas (por ejemplo, con PBKDF2).

import javax.crypto.spec.PBEKeySpec;  
// → Define los parámetros para PBKDF2: contraseña, salt, iteraciones y longitud de clave deseada.

// Clases del paquete java.security: para generar sal aleatoria de alta entropía
import java.security.SecureRandom; 
// → Genera valores aleatorios seguros (no predecibles), usados como “salt” para evitar ataques por diccionario o rainbow tables.

// Clases del paquete java.util: para codificar y decodificar en Base64
import java.util.Base64; 
// → Permite representar los bytes del hash o del salt como texto legible (para guardar en archivos o bases de datos).

/**
 * Clase responsable de gestionar el hash y la verificación de contraseñas
 * utilizando el algoritmo PBKDF2 con HMAC-SHA256.
 *
 * PBKDF2 (Password-Based Key Derivation Function 2) permite:
 *  - Derivar una clave criptográfica segura a partir de una contraseña.
 *  - Usar una SALT aleatoria para evitar ataques por rainbow tables.
 *  - Usar muchas iteraciones para dificultar ataques de fuerza bruta.
 */
public final class PasswordHasher {

    // --- Parámetros del algoritmo PBKDF2 ---
    private static final String PBKDF2 = "PBKDF2WithHmacSHA256"; // Algoritmo de derivación
    private static final int ITERATIONS = 210_000;   // Número de iteraciones (mínimo 100k recomendado)
    private static final int SALT_BYTES = 16;        // Longitud de la SALT (en bytes)
    private static final int KEY_BITS = 256;         // Longitud de la clave derivada (en bits)
    private static final SecureRandom RNG = new SecureRandom(); // Generador seguro de aleatoriedad

    /**
     * Clase interna que agrupa los resultados del hash:
     *  - salt: el valor aleatorio usado en la derivación.
     *  - dk: la clave derivada (derived key) generada por PBKDF2.
     */
    /** Agrupa la SALT y la clave derivada PBKDF2. */
    public static final class Hash {
        public final byte[] salt;   // 16 bytes
        public final byte[] dk;     // 32 bytes (256 bits)

        public Hash(byte[] salt, byte[] dk) {
            this.salt = salt;
            this.dk = dk;
        }

        /**
         * Representación en texto legible del hash:
         * SALT:ITERACIONES:DERIVED_KEY, todo en Base64.
         */
        /** Devuelve representación Base64 legible: salt:iterations:dk. */
        public String toString() {
            return Base64.getEncoder().encodeToString(salt) + ":" +
                   ITERATIONS + ":" +
                   Base64.getEncoder().encodeToString(dk);
        }
    }

    /**
     * Genera un hash PBKDF2 a partir de una contraseña.
     *
     * 1️⃣ Se crea una SALT aleatoria.
     * 2️⃣ Se aplica PBKDF2 (con HMAC-SHA256) sobre la contraseña y la SALT.
     * 3️⃣ Se obtiene una clave derivada de 256 bits (32 bytes).
     *
     * @param password Contraseña en texto plano (char[])
     * @return Objeto Hash con salt y clave derivada (dk)
     */
    /** Deriva una clave de 256 bits desde contraseña con PBKDF2-HMAC-SHA256. */
    public static Hash hash(char[] password) throws Exception {
        // Generar SALT aleatoria
        byte[] salt = new byte[SALT_BYTES];
        RNG.nextBytes(salt);

        // Crear especificación de PBKDF2 con la contraseña, SALT e iteraciones
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BITS);

        // Derivar la clave usando PBKDF2 con HMAC-SHA256
        byte[] dk = SecretKeyFactory.getInstance(PBKDF2)
                .generateSecret(spec)
                .getEncoded();

        // Limpiar la contraseña de memoria
        spec.clearPassword();

        // Devolver estructura con SALT + clave derivada
        return new Hash(salt, dk);
    }

    /**
     * Verifica si una contraseña introducida coincide con un hash almacenado.
     *
     * 1️⃣ Vuelve a derivar la clave con la misma SALT y parámetros.
     * 2️⃣ Compara los bytes de ambas claves (derivada y almacenada)
     *     mediante comparación constante (sin atajos) para evitar ataques de timing.
     *
     * @param password Contraseña introducida por el usuario
     * @param stored   Hash previamente guardado (contiene salt y dk)
     * @return true si coinciden, false si no
     */
    /** Verifica contraseña rederivando la clave y comparando a tiempo constante. */
    public static boolean verify(char[] password, Hash stored) throws Exception {
        // Derivar nuevamente la clave con la misma SALT y parámetros
        PBEKeySpec spec = new PBEKeySpec(password, stored.salt, ITERATIONS, KEY_BITS);
        byte[] dk = SecretKeyFactory.getInstance(PBKDF2)
                .generateSecret(spec)
                .getEncoded();
        spec.clearPassword();

        // Comparación constante (evita ataques de tiempo)
        if (dk.length != stored.dk.length) return false;
        int diff = 0;
        for (int i = 0; i < dk.length; i++) diff |= dk[i] ^ stored.dk[i];
        return diff == 0;
    }

    /** Deriva y devuelve solo la clave (dk) desde contraseña y SALT. */
    public static byte[] derive(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BITS);
        byte[] dk = SecretKeyFactory.getInstance(PBKDF2)
                .generateSecret(spec)
                .getEncoded();
        spec.clearPassword();
        return dk;
    }
}
