# Bloque 1 · Endurecer parsing y validaciones

## Cambios aplicados
- Se ha incorporado `JsonUtil`, un parser propio sin dependencias externas que soporta objetos y arrays JSON, reemplazando los `indexOf` inseguros en `ServerMain` y `ServerStore`.
- El servidor valida ahora usuarios, roles, nombres de fichero y campos Base64 con límites de tamaño, respuestas HTTP acordes (400/413) y cuerpos con tamaño acotado antes de procesar.
- El cliente Java (`ServerStore` y `AuthApp`) reutiliza el nuevo parser; se elimina el parsing manual, se limpia y valida la entrada de usuario y se evita generar payloads mal formados.
- Se añadió validación previa del nombre de usuario y del destinatario al compartir ficheros, reduciendo errores evitables en cliente y reforzando la experiencia de uso.

## Impacto en el proyecto
- El plano de ataque por inyección JSON o sobrecarga de cuerpo queda mitigado; cualquier entrada fuera de especificación se rechaza tempranamente y de forma trazable.
- Los tokens, roles y metadatos dependen ahora de un único formato JSON saneado, simplificando la futura incorporación de registros o logs de auditoría.
- El cliente detecta antes los errores de formato, evitando viajes innecesarios a red y alineando la validación con las políticas del backend.

# Bloque 2 · Sesiones seguras y monitorización

## Cambios aplicados
- Los tokens de sesión ahora se emiten con HMAC-SHA256, vencen a los 20 minutos y se vinculan a la IP del cliente; se invalida cualquier token previo del mismo usuario.
- Se añadió un sistema de rate limiting basado en conteo de fallos: tras 5 errores en 10 minutos la cuenta queda bloqueada durante 5 minutos, exponiendo el mensaje al cliente.
- Se incorporó un registro de auditoría (`logs/security.log`) con sello temporal e IP para operaciones sensibles (registro, login, subida/descarga, compartición, cambios de rol) y se propaga la causa de error al cliente.
- El cliente interpreta las respuestas 4xx del servidor y muestra mensajes amigables cuando el back-end rechaza la autenticación o bloquea temporalmente una cuenta.

## Impacto en el proyecto
- El refuerzo de tokens reduce el riesgo de secuestro de sesión y facilita futuras políticas de renovación/rotación.
- El bloqueo temporal ante múltiples intentos fallidos desalienta ataques de fuerza bruta sin comprometer la experiencia de usuarios legítimos.
- El rastro de auditoría crea evidencia forense y simplifica el cumplimiento de requisitos de supervisión en la segunda fase del proyecto.
- Los mensajes enriquecidos mejoran la usabilidad: el cliente entiende los bloqueos y permite actuar sin necesidad de depurar tráfico HTTP manualmente.

# Bloque 3 · Integridad de metadatos y ficheros

## Cambios aplicados
- Cada registro `.properties` (usuarios y ficheros) se firma con HMAC-SHA256 (`metaHmac`); al leerlos se valida y, si falta la firma por ser legacy, se regenera automáticamente.
- Las operaciones sensibles (`/user`, `/auth/*`, `/files`, `/file`, `/share`, `/admin/*`) abortan con error y registran `INTEGRITY_FAIL` si la comprobación no cuadra.
- La compartición y los cambios de rol recalculan la firma inmediatamente tras modificar metadatos, evitando que queden registros inconsistentes.

## Impacto en el proyecto
- Protege contra manipulación accidental o maliciosa de los almacenes planos, requisito clave antes de pasar a un almacenamiento más sofisticado en la fase 2.
- Facilita la detección temprana de corrupción en ficheros cifrados: cualquier descarga que no pase la verificación se rechaza sin exponer datos.
- Deja la puerta lista para añadir etiquetas adicionales (versión, timestamp firmado) o migrar a un backend autenticado sin perder compatibilidad con los datos existentes.
