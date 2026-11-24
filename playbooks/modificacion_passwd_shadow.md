# Playbook: modificacion_passwd_shadow

**Regla**: `modificacion_passwd_shadow`  ·  **ID**: `b0ba4bb6-e170-4b63-8cd5-28b3e489f635`
**Técnica ATT&CK**: T1003.008, T1098 — Volcado de credenciales en disco
**Nivel**: high  ·  **Simulación**: `modificacion_credenciales`

Alerta que lo gatilla: Lectura de /etc/shadow o escritura directa de /etc/passwd por un proceso que no es herramienta de cuentas ni de autenticación (auditd, watch -p rwa).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `modificacion_passwd_shadow` (ID `b0ba4bb6-e170-4b63-8cd5-28b3e489f635`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `modificacion_credenciales` y se confirma con `make verify SIM=modificacion_credenciales`.

## Análisis y triaje

- Identificar el proceso y la cuenta (`data.audit.exe`, `data.audit.auid`).
- Una lectura de shadow por `cat`, un editor o una shell indica volcado de hashes.
- Determinar si hubo exfiltración posterior (DNS, red saliente).

## Contención

- Aislar el host del lab de la red para cortar una posible exfiltración.
- Terminar el proceso y la sesión asociados.

## Erradicación

- Asumir los hashes comprometidos: forzar rotación de contraseñas de todas las cuentas del host.
- Revisar persistencia y accesos creados por el mismo actor.

## Recuperación

- Restablecer contraseñas con nueva política y revisar la integridad de /etc/passwd y /etc/shadow.

## Lecciones aprendidas

- El acceso a shadow debe ser excepcional y auditado; revisar qué cuentas lo necesitan de forma legítima.

## Referencias

- https://attack.mitre.org/techniques/T1003/008/
- https://attack.mitre.org/techniques/T1098/
