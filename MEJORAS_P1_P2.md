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
