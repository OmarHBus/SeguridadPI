// --- Librerías de cifrado simétrico y asimétrico ---

import javax.crypto.Cipher;  
// Clase principal para realizar operaciones criptográficas (cifrado y descifrado).
// Soporta algoritmos como AES, RSA, DES, etc., y modos de operación (GCM, CBC...).

import javax.crypto.spec.GCMParameterSpec;  
// Permite definir los parámetros específicos del modo GCM (Galois/Counter Mode) usado con AES.
// Incluye el tamaño del tag de autenticación y el vector de inicialización (IV).

import javax.crypto.spec.SecretKeySpec;  
// Representa una clave simétrica (como AES) a partir de un array de bytes.
// Se usa para convertir una clave derivada o leída de archivo en un objeto SecretKey válido.

// --- Librerías de gestión de claves y generación aleatoria ---

import java.security.KeyPair;  
// Contiene un par de claves asimétricas: una pública y otra privada (por ejemplo, para RSA).

import java.security.KeyPairGenerator;  
// Generador de pares de claves públicas/privadas (p. ej. RSA o DSA).
// Permite especificar el tamaño de clave y la fuente de entropía.

import java.security.PrivateKey;  
// Define el tipo de objeto para una clave privada (usada para descifrar o firmar datos).

import java.security.PublicKey;  
// Define el tipo de objeto para una clave pública (usada para cifrar o verificar firmas).

import java.security.SecureRandom;  
// Generador de números aleatorios criptográficamente seguros.
// Se utiliza para generar claves, IVs o sal aleatorias de forma impredecible.

// --- Utilidades generales ---

import java.util.Base64;  
// Proporciona métodos para codificar y decodificar datos binarios en Base64.
// Es útil para almacenar claves o datos cifrados en formato texto legible.

/**
 * Clase encargada de la gestión de claves:
 *  - Generación de pares de claves RSA (pública y privada).
 *  - Cifrado y descifrado de la clave privada usando AES-GCM.
 *  - Conversión a Base64 para visualización o almacenamiento.
 *
 * Forma parte del sistema de seguridad que combina PBKDF2 + RSA + AES.
 */
public final class KeyService {

    // Generador seguro de números aleatorios
    private static final SecureRandom RNG = new SecureRandom();

    // Tamaño del par de claves RSA
    private static final int RSA_BITS = 2048;   // (Se puede subir a 3072 para más seguridad)

    // Parámetros del modo AES-GCM
    private static final int GCM_IV_BYTES = 12;  // Tamaño estándar del vector IV en bytes
    private static final int GCM_TAG_BITS = 128; // Longitud del tag de autenticación (bits)

    /**
     * Genera un nuevo par de claves RSA (pública y privada).
     * @return Un objeto KeyPair con ambas claves.
     */
    public static KeyPair newRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(RSA_BITS, RNG); // Inicializa el generador con el tamaño de clave y fuente aleatoria
        return kpg.generateKeyPair();
    }

    /**
     * Clase interna que encapsula una clave privada cifrada.
     * Guarda el IV (vector de inicialización) y el ciphertext.
     */
    public static final class EncryptedPrivateKey {
        public final byte[] iv;         // Vector IV de 12 bytes usado en AES-GCM
        public final byte[] ciphertext; // Clave privada (PKCS8) cifrada con AES-GCM

        public EncryptedPrivateKey(byte[] iv, byte[] ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }

    /** Representa un payload cifrado con AES-GCM (iv + ciphertext). */
    public static final class EncryptedBytes {
        public final byte[] iv;
        public final byte[] ciphertext;

        public EncryptedBytes(byte[] iv, byte[] ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }

    /**
     * Cifra la clave privada RSA (en formato PKCS8) usando AES-GCM.
     * La clave AES proviene de la derivación PBKDF2.dk (clave derivada del usuario).
     *
     * @param pkcs8Private Clave privada en formato PKCS8 (bytes)
     * @param pbkdf2Dk     Clave derivada PBKDF2 del usuario
     * @return Objeto EncryptedPrivateKey con IV y ciphertext cifrado
     */
    public static EncryptedPrivateKey wrapPrivate(byte[] pkcs8Private, byte[] pbkdf2Dk) throws Exception {
        // Generar IV aleatorio
        byte[] iv = new byte[GCM_IV_BYTES];
        RNG.nextBytes(iv);

        // Crear cifrador AES-GCM con la clave derivada
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(pbkdf2Dk, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));

        // Cifrar la clave privada (devuelve ciphertext + tag)
        byte[] ct = aes.doFinal(pkcs8Private);

        // Devolver objeto con IV y datos cifrados
        return new EncryptedPrivateKey(iv, ct);
    }

    /** Cifra bytes arbitrarios con AES-GCM usando una clave de 256 bits. */
    public static EncryptedBytes encryptAesGcm(byte[] plaintext, byte[] aesKey256) throws Exception {
        byte[] iv = new byte[GCM_IV_BYTES];
        RNG.nextBytes(iv);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey256, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = aes.doFinal(plaintext);
        return new EncryptedBytes(iv, ct);
    }

    /** Descifra un payload AES-GCM con la clave de 256 bits dada. */
    public static byte[] decryptAesGcm(EncryptedBytes enc, byte[] aesKey256) throws Exception {
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey256, "AES"), new GCMParameterSpec(GCM_TAG_BITS, enc.iv));
        return aes.doFinal(enc.ciphertext);
    }

    /** Genera una clave aleatoria de 256 bits (para cifrado de contenido AES). */
    public static byte[] newAes256Key() {
        byte[] k = new byte[32];
        RNG.nextBytes(k);
        return k;
    }

    /** Envuelve secretos pequeños (p.ej., CEK) con RSA-OAEP SHA-256. */
    public static byte[] rsaOaepWrap(byte[] secret, PublicKey recipientPub) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, recipientPub);
        return rsa.doFinal(secret);
    }

    /** Desenvuelve RSA-OAEP SHA-256 usando la clave privada del receptor. */
    public static byte[] rsaOaepUnwrap(byte[] wrapped, PrivateKey recipientPriv) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.DECRYPT_MODE, recipientPriv);
        return rsa.doFinal(wrapped);
    }

    /**
     * Descifra una clave privada RSA cifrada con AES-GCM,
     * usando la misma clave derivada PBKDF2.dk del usuario.
     *
     * @param enc       Objeto EncryptedPrivateKey con IV y ciphertext
     * @param pbkdf2Dk  Clave derivada PBKDF2
     * @return Clave privada descifrada (en formato PKCS8, bytes)
     */
    public static byte[] unwrapPrivate(EncryptedPrivateKey enc, byte[] pbkdf2Dk) throws Exception {
        // Configurar descifrado AES-GCM con los mismos parámetros
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(pbkdf2Dk, "AES"), new GCMParameterSpec(GCM_TAG_BITS, enc.iv));

        // Descifrar y devolver la clave privada original
        return aes.doFinal(enc.ciphertext);
    }

    /**
     * Convierte un arreglo de bytes a una cadena en Base64.
     * Se usa solo para mostrar o exportar claves.
     */
    /** Codifica bytes a Base64 para mostrar o exportar. */
    public static String b64(byte[] x) {
        return Base64.getEncoder().encodeToString(x);
    }
}
