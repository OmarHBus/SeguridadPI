# Fichero de ayuda

## Prueba 1

### Proyecto SeguridadPI — Cambios realizados (MVP cliente/servidor con cifrado E2EE, roles y TLS)

#### Resumen

- Arquitectura cliente/servidor en Java (Swing + HttpServer/HttpsServer).
- Registro y login seguro por desafío/firma (RSA‑PSS) sin enviar la contraseña ni la clave derivada (`dk`) al servidor.
- Gestión de ficheros cifrados extremo a extremo (AES‑GCM con CEK por fichero).
- Compartición multiusuario re‑envolviendo la CEK con RSA‑OAEP (por destinatario).
- TLS opcional con `server_keystore.p12` y cliente configurado para HTTPS (modo desarrollo trust‑all).
- RBAC con roles: ADMIN, USER, WORKER, AUDITOR y panel de administración para listar/cambiar roles.

---

#### Componentes y archivos relevantes

- `src/AuthApp.java`: cliente Swing. Registro, login (challenge+firma), pestañas de Ficheros, Compartidos conmigo y Administración.
- `src/ServerMain.java`: servidor HTTP/HTTPS. Endpoints de usuarios, auth, ficheros, compartición y administración.
- `src/ServerStore.java`: cliente HTTP. Envía/recibe JSON y adjunta token de sesión.
- `src/PasswordHasher.java`: PBKDF2‑HMAC‑SHA256. Añadido `derive(...)` para obtener `dk` localmente.
- `src/KeyService.java`: RSA + AES‑GCM. Helpers para cifrado/descifrado y envoltura con RSA‑OAEP.
- `server_users/`: almacén de usuarios (`.properties`). Añadido campo `role`.
- `server_files/`: metadatos y ciphertext por fichero (`.properties`).

---

#### Seguridad: cambios clave

- Eliminado el envío/almacenamiento de `dk` en servidor. La `dk` se deriva y usa solo en el cliente.
- Login migrado a reto/firma:
  1) Cliente pide `/auth/start` y recibe `nonceB64`.
  2) Cliente obtiene `salt/encPrivate/iv/publicKey` vía `/user/{username}` y abre su privada con AES‑GCM usando `dk=PBKDF2(password,salt)`.
  3) Firma el `nonce` con RSA‑PSS y envía a `/auth/finish`.
  4) Servidor verifica con la pública y emite `token` + `role`.
- TLS opcional: si existe `server_keystore.p12`, servidor arranca en `https://localhost:8443`; si no, en `http://localhost:8080`.
- Cliente usa `https` y, en desarrollo, un trust‑all temporal (deshabilitable al importar el certificado al truststore del JRE).

---

#### Gestión de ficheros (E2EE)

- Subida (cliente):
  - Genera CEK AES‑256 aleatoria → cifra fichero con AES‑GCM (IV aleatorio).
  - Envuela CEK con la pública del propietario (RSA‑OAEP‑SHA‑256).
  - Envía JSON a `/upload/{user}` con: `filename`, `ivB64`, `cekWrappedB64`, `ctB64`.
- Descarga: el servidor devuelve `ivB64`, `cekWrappedB64`, `ctB64`; el cliente desenrolla CEK con su privada y descifra.
- Compartición: owner desenrolla su CEK, la re‑envuelve con la pública del destinatario y llama a `/share/{owner}/{id}` para guardar `wrap.<user>`.

---

#### Endpoints (servidor)

- Usuarios
  - `GET /exists/{user}`
  - `GET /user/{user}` → `{ username, saltB64, publicKeyB64, encPrivateB64, ivB64, role }`
  - `POST /register` → `{ username, saltB64, publicKeyB64, encPrivateB64, ivB64, [role?] }`
- Autenticación
  - `POST /auth/start` → `{ nonceB64 }` (el cliente obtiene el resto vía `/user/{user}`)
  - `POST /auth/finish` → `{ ok, token, role, username }`
- Ficheros
  - `POST /upload/{user}` (Auth: ADMIN o `user`)
  - `GET /files/{user}` (Auth: ADMIN o `user`)
  - `GET /file/{owner}/{id}` o `/file/{owner}/{id}/{recipient}` (Auth: ADMIN, owner o destinatario)
  - `POST /share/{owner}/{id}` (Auth: ADMIN/owner; WORKER y AUDITOR denegados)
  - `GET /files/shared/{user}` (Auth: ADMIN o `user`)
- Administración (solo ADMIN)
  - `GET /admin/users` → lista `{ username, role }`
  - `POST /admin/setRole` → body `{ username, role }`

Todos los endpoints protegidos usan `Authorization: Bearer <token>`.

---

#### Roles y permisos

| Rol     | Subir propios | Compartir propios | Ver/descargar compartidos | Admin usuarios | Borrar/forzar |
|---------|----------------|-------------------|---------------------------|----------------|---------------|
| ADMIN   | Sí (cualquiera)| Sí (cualquiera)   | Sí                        | Sí             | Sí            |
| USER    | Sí (propios)   | Sí (propios)      | Sí                        | No             | No            |
| WORKER  | Sí (propios)   | No                | Sí                        | No             | No            |
| AUDITOR | No             | No                | Sí                        | No             | No            |

La UI deshabilita “Compartir” en WORKER y AUDITOR; el servidor valida igualmente.

---

#### Cambios UI (cliente)

- Pestaña “Ficheros”: muestra sesión como `usuario (ROL)`, subir/descargar/compartir.
- Pestaña “Compartidos conmigo”: lista `owner / filename`, descarga usando `wrap.<usuario>`.
- Pestaña “Administración” (solo ADMIN): lista usuarios y permite cambiar roles.

---

#### Cómo ejecutar (Windows / PowerShell)

1) Compilar:

``` java
javac -encoding UTF-8 -d bin -cp src src\AuthApp.java src\KeyService.java src\PasswordHasher.java src\ServerMain.java src\ServerStore.java
```

1) Arrancar servidor:

``` java
java -cp bin ServerMain
```

1) Arrancar cliente:

``` java
java -cp bin AuthApp
```

1) TLS (opcional): generar keystore (contraseña `changeit` por defecto en este MVP)

``` java
keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -storetype PKCS12 \
  -keystore server_keystore.p12 -storepass changeit -keypass changeit \
  -dname "CN=localhost, OU=Dev, O=Demo, L=City, S=State, C=ES" -validity 3650
```

Si existe `server_keystore.p12`, el servidor usa `https://localhost:8443`. El cliente está configurado para confiar en desarrollo.

---

#### Pendiente / próximos pasos sugeridos

- Borrado de ficheros (owner/Admin) y auditoría de acciones (subir/compartir/descargar/cambiar rol).
- Cuotas, tamaño máximo y/o streaming para ficheros grandes.
- Sustituir trust‑all por importar el certificado de `server_keystore.p12` al truststore.
- Tokens con expiración y persistencia de sesiones.
