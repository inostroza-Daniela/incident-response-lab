# Playbook: webshell_proceso_hijo_servidor_web

**Regla**: `webshell_proceso_hijo_servidor_web`  ·  **ID**: `5a4684f6-32e6-4f40-97b9-c4fb456459b7`
**Técnica ATT&CK**: T1505.003 — Webshell
**Nivel**: high  ·  **Simulación**: `webshell`

Alerta que lo gatilla: La cuenta del servidor web (www-data, apache, nginx) ejecuta una shell, intérprete o herramienta de red (auditd).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `webshell_proceso_hijo_servidor_web` (ID `5a4684f6-32e6-4f40-97b9-c4fb456459b7`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `webshell` y se confirma con `make verify SIM=webshell`.

## Análisis y triaje

- Identificar el proceso lanzado (`data.audit.exe`) y el usuario web (`data.audit.uid`).
- Correlacionar con accesos recientes en los logs del servidor web para ubicar el archivo sospechoso.
- Buscar archivos escritos recientemente en el directorio público (webroot).

## Contención

- Aislar el host del lab y, si es viable, poner el servicio web en mantenimiento.
- Terminar los procesos hijos sospechosos del servidor web.

## Erradicación

- Localizar y eliminar el archivo de webshell en el webroot; comparar contra una copia limpia.
- Revisar persistencia adicional y cuentas creadas desde la webshell.

## Recuperación

- Restaurar el contenido web desde una fuente de confianza y parchear la vulnerabilidad de carga.

## Lecciones aprendidas

- Restringir permisos de escritura del webroot y los binarios que la cuenta web puede ejecutar.

## Referencias

- https://attack.mitre.org/techniques/T1505/003/
