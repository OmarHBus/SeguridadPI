// Librerías de interfaz gráfica (Swing y AWT)
import javax.swing.*;  // Proporciona los componentes de la interfaz gráfica: JFrame, JButton, JTextField, etc.
import java.awt.*;     // Contiene clases para el diseño visual y manejo de gráficos (layouts, colores, fuentes, etc.)

// Librerías de criptografía y gestión de claves
import java.security.KeyFactory;           // Permite reconstruir objetos de tipo Key (PrivateKey, PublicKey) a partir de su representación codificada
import java.security.KeyPair;              // Representa un par de claves (una pública y una privada) en algoritmos asimétricos como RSA
import java.security.PrivateKey;           // Clase que define una clave privada (para descifrar o firmar)
import java.security.PublicKey;            // Clase que define una clave pública (para cifrar o verificar firmas)
import java.security.spec.PKCS8EncodedKeySpec; // Especifica el formato estandarizado PKCS#8 para representar una clave privada codificada en bytes

/**
 * Interfaz gráfica de autenticación y registro.
 * Versión cliente/servidor: usa ServerStore para persistir usuarios en el servidor HTTP.
 *
 * Cripto:
 *  - PBKDF2 para derivación de claves desde contraseñas.
 *  - RSA para par de claves asimétricas.
 *  - AES-GCM para proteger la clave privada con una clave derivada.
 */
public final class AuthApp extends JFrame {

    // Campos de registro
    private final JTextField regUser = new JTextField(18);
    private final JPasswordField regPass = new JPasswordField(18);

    // Campos de inicio de sesión
    private final JTextField logUser = new JTextField(18);
    private final JPasswordField logPass = new JPasswordField(18);

    // Estado de sesión (útil para futuras funciones: cifrar/descifrar ficheros)
    private String currentUsername = null;
    private PublicKey currentPublicKey = null;
    private PrivateKey currentPrivateKey = null;
    private String currentRole = null;
    private String bearerToken = null;

    public AuthApp() {
        super("Demo Registro / Login (PBKDF2 + RSA) – Cliente/Servidor");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(700, 450);
        setLocationRelativeTo(null); // Centra la ventana

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Registrarse", buildRegisterPanel());
        tabs.addTab("Iniciar sesión", buildLoginPanel());
        tabs.addTab("Ficheros", buildFilesPanel());
        tabs.addTab("Compartidos conmigo", buildSharedPanel());
        tabs.addTab("Administración", buildAdminPanel());
        add(tabs);
    }

    /** Construye el panel de registro de usuario. */
    private JPanel buildRegisterPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6,6,6,6);

        c.gridx=0; c.gridy=0; c.anchor = GridBagConstraints.LINE_END;
        p.add(new JLabel("Usuario:"), c);
        c.gridy=1; p.add(new JLabel("Contraseña:"), c);

        c.gridx=1; c.gridy=0; c.anchor = GridBagConstraints.LINE_START;
        p.add(regUser, c);
        c.gridy=1; p.add(regPass, c);

        JButton bt = new JButton("Crear cuenta");
        bt.addActionListener(e -> doRegister());
        c.gridx=1; c.gridy=2; c.anchor = GridBagConstraints.CENTER;
        p.add(bt, c);
        return p;
    }

    /** Construye el panel de inicio de sesión. */
    private JPanel buildLoginPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6,6,6,6);

        c.gridx=0; c.gridy=0; c.anchor = GridBagConstraints.LINE_END;
        p.add(new JLabel("Usuario:"), c);
        c.gridy=1; p.add(new JLabel("Contraseña:"), c);

        c.gridx=1; c.gridy=0; c.anchor = GridBagConstraints.LINE_START;
        p.add(logUser, c);
        c.gridy=1; p.add(logPass, c);

        JButton bt = new JButton("Entrar");
        bt.addActionListener(e -> doLogin());
        c.gridx=1; c.gridy=2; c.anchor = GridBagConstraints.CENTER;
        p.add(bt, c);
        return p;
    }

    /** Gestiona el registro: PBKDF2 -> RSA -> envolver privada con AES-GCM -> enviar al servidor. */
    private void doRegister() {
        String u = regUser.getText().trim();
        char[] p = regPass.getPassword();

        if (u.isEmpty() || p.length==0) { msg("Rellena usuario y contraseña"); wipe(p); return; }

        try {
            // 0) Comprobar en servidor si existe
            if (ServerStore.exists(u)) { msg("Ese usuario ya existe"); wipe(p); return; }

            // 1) Derivar clave con PBKDF2 (salt + dk)
            PasswordHasher.Hash h = PasswordHasher.hash(p);

            // 2) Generar par RSA
            KeyPair kp = KeyService.newRsa();

            // 3) Cifrar la privada (PKCS#8) con AES-GCM usando PBKDF2.dk
            KeyService.EncryptedPrivateKey enc = KeyService.wrapPrivate(kp.getPrivate().getEncoded(), h.dk);

            // 4) Enviar al servidor (persistencia remota) sin dk
            ServerStore.save(new ServerStore.UserRecord(
                    u, h.salt, kp.getPublic(), enc.ciphertext, enc.iv
            ));

            wipe(p);
            msg("Usuario creado en servidor: " + u);
        } catch (Exception ex) {
            wipe(p);
            ex.printStackTrace();
            msg("Error creando usuario: " + ex.getMessage());
        }
    }

    /** Gestiona el login: obtener del servidor -> verificar PBKDF2 -> abrir privada (AES-GCM). */
    private void doLogin() {
        String u = logUser.getText().trim();
        char[] p = logPass.getPassword();

        if (u.isEmpty() || p.length==0) { msg("Rellena usuario y contraseña"); wipe(p); return; }

        try {
            // 0) Iniciar auth: obtener nonce. Para claves/salt usa /user (parser ya probado)
            String start = ServerStore.authStart(u);
            String nonceB64 = extract(start, "nonceB64");
            var recOpt = ServerStore.load(u);
            if (recOpt.isEmpty()) { msg("Usuario no existe en servidor"); wipe(p); return; }
            var rec = recOpt.get();

            byte[] dk = PasswordHasher.derive(p, rec.salt);
            byte[] pkcs8 = KeyService.unwrapPrivate(new KeyService.EncryptedPrivateKey(rec.iv, rec.encPriv), dk);
            PrivateKey priv = buildPrivateFromPkcs8(pkcs8);
            PublicKey pub = rec.publicKey;

            // Firmar el nonce con RSA-PSS
            byte[] nonce = java.util.Base64.getDecoder().decode(nonceB64);
            java.security.Signature s = java.security.Signature.getInstance("RSASSA-PSS");
            s.setParameter(new java.security.spec.PSSParameterSpec(
                    "SHA-256", "MGF1", new java.security.spec.MGF1ParameterSpec("SHA-256"), 32, 1));
            s.initSign(priv);
            s.update(nonce);
            String sigB64 = java.util.Base64.getEncoder().encodeToString(s.sign());

            // Finalizar auth y recibir token/rol
            String[] tk = ServerStore.authFinish(u, nonceB64, sigB64);

            // Guardar estado
            this.currentUsername = u;
            this.currentPublicKey = pub;
            this.currentPrivateKey = priv;
            this.bearerToken = tk[0];
            this.currentRole = tk[1];

            wipe(p);
            msg("Login OK como '" + u + "' (" + currentRole + ")");
            refreshFilesList();
        } catch (Exception ex) {
            wipe(p);
            ex.printStackTrace();
            msg("Error en login: " + ex.getMessage());
        }
    }

    /** Extrae un valor de JSON plano "key":"value". */
    private static String extract(String json, String key) {
        String pat = "\""+key+"\":\"";
        int i = json.indexOf(pat);
        if (i<0) return null;
        int s = i + pat.length();
        int e = json.indexOf('"', s);
        if (e<0) return null;
        return json.substring(s, e);
    }

    /** Reconstruye una PrivateKey RSA desde bytes PKCS#8. */
    private static PrivateKey buildPrivateFromPkcs8(byte[] pkcs8) throws Exception {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    /** Muestra un diálogo modal con un mensaje. */
    private static void msg(String s){ JOptionPane.showMessageDialog(null, s); }

    /** Limpia de memoria arrays de caracteres sensibles. */
    private static void wipe(char[] arr){ java.util.Arrays.fill(arr, '\0'); }
    // Comentario de lo que hace el metodo main:
    // Este método es el punto de entrada de la aplicación.
    // Utiliza SwingUtilities.invokeLater para ejecutar la creación y visualización de la ventana principal de la aplicación.
    // Crea una instancia de AuthApp y la hace visible.
    /** Punto de entrada: inicia la interfaz Swing. */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new AuthApp().setVisible(true));
    }

    // --- Ficheros (MVP) --- DIEGO -------------------------------------------------------
    private final DefaultListModel<String> filesModel = new DefaultListModel<>();
    private final JList<String> filesList = new JList<>(filesModel);
    private final java.util.Map<String,String> idxToId = new java.util.LinkedHashMap<>(); // índice -> id
    private final JLabel sessionLabel = new JLabel("No autenticado");

    private final DefaultListModel<String> sharedModel = new DefaultListModel<>();
    private final JList<String> sharedList = new JList<>(sharedModel);
    private final java.util.Map<String,String[]> sharedIdxToOwnerId = new java.util.LinkedHashMap<>(); // índice -> [owner,id]

    private final DefaultListModel<String> usersModel = new DefaultListModel<>();
    private final JList<String> usersList = new JList<>(usersModel);
    // Comentario de lo que hace el metodo buildFilesPanel:
    // Este método se encarga de construir el panel de archivos.
    // Primero crea un panel con un layout de borde (BorderLayout).
    // Luego crea un panel superior con un layout de flujo (FlowLayout) para el label de sesión y el botón de subida de archivos.
    // Añade el label de sesión y el botón de subida de archivos al panel superior.
    // Añade el panel superior al panel principal.
    // Añade el panel de archivos al panel principal.
    // Retorna el panel principal.
    /** Construye la pestaña de ficheros con sesión, botón de subida y lista. */
    private JPanel buildFilesPanel() {
        JPanel p = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Sesión: "));
        top.add(sessionLabel);
        JButton upload = new JButton("Subir archivo");
        upload.addActionListener(e -> doUploadFile());
        JButton download = new JButton("Descargar");
        download.addActionListener(e -> doDownloadSelected());
        JButton share = new JButton("Compartir");
        share.addActionListener(e -> doShareSelected());
        top.add(upload);
        top.add(download);
        top.add(share);
        p.add(top, BorderLayout.NORTH);

        p.add(new JScrollPane(filesList), BorderLayout.CENTER);
        return p;
    }

    /** Construye la pestaña "Compartidos conmigo". */
    private JPanel buildSharedPanel() {
        JPanel p = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton download = new JButton("Descargar");
        download.addActionListener(e -> doDownloadShared());
        top.add(download);
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(sharedList), BorderLayout.CENTER);
        return p;
    }

    /** Construye la pestaña de administración (solo ADMIN). */
    private JPanel buildAdminPanel() {
        JPanel p = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refresh = new JButton("Refrescar usuarios");
        refresh.addActionListener(e -> refreshUsers());
        JButton setRole = new JButton("Cambiar rol...");
        setRole.addActionListener(e -> doChangeRole());
        top.add(refresh);
        top.add(setRole);
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(usersList), BorderLayout.CENTER);
        return p;
    }
    // Comentario de lo que hace el metodo refreshFilesList:
    // Este método se encarga de actualizar la lista de archivos disponibles para el usuario.
    // Primero verifica si el usuario está autenticado.
    // Si no está autenticado, actualiza el label de sesión y limpia la lista de archivos.
    // Si está autenticado, llama al método listFiles del servidor para obtener la lista de archivos.
    // Actualiza la lista de archivos disponibles para el usuario.
    /** Carga los ficheros del usuario desde el servidor y refresca la lista. */
    private void refreshFilesList() {
        if (currentUsername == null) {
            sessionLabel.setText("No autenticado");
            filesModel.clear();
            return;
        }
        sessionLabel.setText(currentUsername + (currentRole!=null? " ("+currentRole+")":""));
        try {
            String[][] files = ServerStore.listFiles(currentUsername, bearerToken);
            filesModel.clear();
            idxToId.clear();
            for (int i=0;i<files.length;i++) {
                String[] it = files[i];
                filesModel.addElement(it[1]);
                idxToId.put(String.valueOf(i), it[0]);
            }
            // refresh shared
            sharedModel.clear();
            sharedIdxToOwnerId.clear();
            String[][] shared = ServerStore.listShared(currentUsername, bearerToken);
            for (int i=0;i<shared.length;i++) {
                String owner = shared[i][0];
                String id = shared[i][1];
                String name = shared[i][2];
                sharedModel.addElement(owner + " / " + name);
                sharedIdxToOwnerId.put(String.valueOf(i), new String[]{owner, id});
            }
            // refresh admin users if ADMIN
            usersModel.clear();
            if ("ADMIN".equalsIgnoreCase(currentRole)) {
                String[][] users = ServerStore.listAllUsers(bearerToken);
                for (String[] u : users) {
                    usersModel.addElement(u[0] + " (" + u[1] + ")");
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            msg("Error listando ficheros: " + ex.getMessage());
        }
    }
    // Comentario de lo que hace el metodo doUploadFile:
    // Este método se encarga de subir un archivo al servidor.
    // Primero verifica si el usuario está autenticado y tiene una clave pública válida.
    // Luego muestra un cuadro de diálogo para seleccionar el archivo a subir.
    // Lee el contenido del archivo y lo cifra usando AES-GCM.
    // Envolve la clave de cifrado (CEK) con la clave pública del usuario usando RSA-OAEP.
    // Llama al método uploadFile del servidor para guardar el archivo en la base de datos.
    // Actualiza la lista de archivos disponibles para el usuario.
    /** Abre selector, cifra localmente, envuelve la CEK y sube el fichero. */
    private void doUploadFile() {
        if (currentUsername == null || currentPublicKey == null) { msg("Inicia sesión primero"); return; }
        JFileChooser ch = new JFileChooser();
        int r = ch.showOpenDialog(this);
        if (r != JFileChooser.APPROVE_OPTION) return;
        java.io.File f = ch.getSelectedFile();
        try {
            byte[] data = java.nio.file.Files.readAllBytes(f.toPath());
            // Generar CEK y cifrar contenido
            byte[] cek = KeyService.newAes256Key();
            KeyService.EncryptedBytes enc = KeyService.encryptAesGcm(data, cek);
            // Envolver CEK para el propio usuario con su pública
            byte[] cekWrapped = KeyService.rsaOaepWrap(cek, currentPublicKey);
            ServerStore.uploadFile(currentUsername, f.getName(), enc.iv, cekWrapped, enc.ciphertext, bearerToken);
            msg("Fichero subido: " + f.getName());
            refreshFilesList();
        } catch (Exception ex) {
            ex.printStackTrace();
            msg("Error subiendo fichero: " + ex.getMessage());
        }
    }

    /** Descarga el fichero seleccionado, lo descifra con la privada y lo guarda. */
    private void doDownloadSelected() {
        if (currentUsername == null || currentPrivateKey == null) { msg("Inicia sesión primero"); return; }
        int idx = filesList.getSelectedIndex();
        if (idx < 0) { msg("Selecciona un fichero"); return; }
        String id = idxToId.get(String.valueOf(idx));
        if (id == null) { msg("No se pudo resolver el id del fichero"); return; }
        try {
            ServerStore.EncryptedFile ef = ServerStore.downloadFile(currentUsername, id, bearerToken);
            // Desenrollar CEK y descifrar
            byte[] cek = KeyService.rsaOaepUnwrap(ef.cekWrapped, currentPrivateKey);
            byte[] plain = KeyService.decryptAesGcm(new KeyService.EncryptedBytes(ef.iv, ef.ciphertext), cek);
            // Guardar
            JFileChooser ch = new JFileChooser();
            ch.setSelectedFile(new java.io.File(ef.filename));
            int r = ch.showSaveDialog(this);
            if (r != JFileChooser.APPROVE_OPTION) return;
            java.nio.file.Files.write(ch.getSelectedFile().toPath(), plain);
            msg("Fichero guardado: " + ch.getSelectedFile().getName());
        } catch (Exception ex) {
            ex.printStackTrace();
            msg("Error descargando/descifrando: " + ex.getMessage());
        }
    }

    /** Descarga un fichero compartido conmigo. */
    private void doDownloadShared() {
        if (currentUsername == null || currentPrivateKey == null) { msg("Inicia sesión primero"); return; }
        int idx = sharedList.getSelectedIndex();
        if (idx < 0) { msg("Selecciona un fichero"); return; }
        String[] pair = sharedIdxToOwnerId.get(String.valueOf(idx));
        if (pair == null) { msg("No se pudo resolver el fichero"); return; }
        String owner = pair[0]; String id = pair[1];
        try {
            ServerStore.EncryptedFile ef = ServerStore.downloadFileAs(owner, id, currentUsername, bearerToken);
            byte[] cek = KeyService.rsaOaepUnwrap(ef.cekWrapped, currentPrivateKey);
            byte[] plain = KeyService.decryptAesGcm(new KeyService.EncryptedBytes(ef.iv, ef.ciphertext), cek);
            JFileChooser ch = new JFileChooser();
            ch.setSelectedFile(new java.io.File(ef.filename));
            int r = ch.showSaveDialog(this);
            if (r != JFileChooser.APPROVE_OPTION) return;
            java.nio.file.Files.write(ch.getSelectedFile().toPath(), plain);
            msg("Fichero guardado: " + ch.getSelectedFile().getName());
        } catch (Exception ex) {
            ex.printStackTrace();
            msg("Error descargando/descifrando: " + ex.getMessage());
        }
    }

    /** Comparte el fichero seleccionado con otro usuario (envolviendo su CEK). */
    private void doShareSelected() {
        if (currentUsername == null || currentPrivateKey == null) { msg("Inicia sesión primero"); return; }
        int idx = filesList.getSelectedIndex();
        if (idx < 0) { msg("Selecciona un fichero"); return; }
        String id = idxToId.get(String.valueOf(idx));
        if (id == null) { msg("No se pudo resolver el id del fichero"); return; }
        String target = JOptionPane.showInputDialog(this, "Usuario destino:");
        if (target == null || target.isBlank()) return;
        try {
            // Obtener el fichero cifrado como owner para recuperar CEK propia
            ServerStore.EncryptedFile ef = ServerStore.downloadFile(currentUsername, id, bearerToken);
            byte[] cek = KeyService.rsaOaepUnwrap(ef.cekWrapped, currentPrivateKey);
            // Cargar pública del destinatario (desde /user)
            var opt = ServerStore.load(target);
            if (opt.isEmpty()) { msg("El usuario destino no existe"); return; }
            var rec = opt.get();
            byte[] cekForTarget = KeyService.rsaOaepWrap(cek, rec.publicKey);
            if ("WORKER".equalsIgnoreCase(currentRole) || "AUDITOR".equalsIgnoreCase(currentRole)) {
                msg("Tu rol no permite compartir");
                return;
            }
            ServerStore.shareFile(currentUsername, id, target, cekForTarget, bearerToken);
            msg("Compartido con " + target);
        } catch (Exception ex) {
            ex.printStackTrace();
            msg("Error compartiendo: " + ex.getMessage());
        }
    }

    /** Refresca la lista de usuarios (ADMIN). */
    private void refreshUsers() {
        if (!"ADMIN".equalsIgnoreCase(currentRole)) { msg("Solo ADMIN"); return; }
        try {
            usersModel.clear();
            String[][] users = ServerStore.listAllUsers(bearerToken);
            for (String[] u : users) usersModel.addElement(u[0] + " (" + u[1] + ")");
        } catch (Exception ex) {
            ex.printStackTrace();
            msg("Error listando usuarios: " + ex.getMessage());
        }
    }

    /** Cambia el rol de un usuario seleccionado (ADMIN). */
    private void doChangeRole() {
        if (!"ADMIN".equalsIgnoreCase(currentRole)) { msg("Solo ADMIN"); return; }
        int idx = usersList.getSelectedIndex(); if (idx<0) { msg("Selecciona un usuario"); return; }
        String entry = usersModel.get(idx); // formato: username (ROLE)
        String username = entry.substring(0, entry.indexOf(' ')).trim();
        String newRole = (String) JOptionPane.showInputDialog(this, "Nuevo rol:", "Cambiar rol",
                JOptionPane.PLAIN_MESSAGE, null, new String[]{"ADMIN","USER","WORKER","AUDITOR"}, "USER");
        if (newRole == null) return;
        try {
            ServerStore.setUserRole(username, newRole, bearerToken);
            refreshUsers();
            msg("Rol actualizado");
        } catch (Exception ex) {
            ex.printStackTrace();
            msg("Error cambiando rol: " + ex.getMessage());
        }
    }
}
