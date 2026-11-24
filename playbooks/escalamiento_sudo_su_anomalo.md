# Playbook: escalamiento_sudo_su_anomalo

**Regla**: `escalamiento_sudo_su_anomalo`  ·  **ID**: `636965d1-130a-4890-b42c-11678501d5a7`
**Técnica ATT&CK**: T1548.003 — Abuso de sudo/su
**Nivel**: medium  ·  **Simulación**: `escalamiento_sudo`

Alerta que lo gatilla: Uso anómalo de sudo o su: shell root, intentos rechazados o su a root desde una cuenta de servicio (auth).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `escalamiento_sudo_su_anomalo` (ID `636965d1-130a-4890-b42c-11678501d5a7`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `escalamiento_sudo` y se confirma con `make verify SIM=escalamiento_sudo`.

## Análisis y triaje

- Identificar la cuenta de origen (`data.srcuser`) y el destino (`data.dstuser`).
- Una cuenta de servicio (www-data, postgres) escalando a root es altamente sospechosa.
- Revisar rechazos repetidos (`user NOT in sudoers`, intentos de clave) como señal de tanteo.

## Contención

- Terminar la sesión escalada y revisar los procesos lanzados como root.
- Restringir el acceso de la cuenta de servicio (shell nologin, revisar sudoers).

## Erradicación

- Corregir configuraciones de sudo que permitan el salto indebido.
- Buscar persistencia creada durante la sesión root.

## Recuperación

- Validar la política de sudo y las cuentas de servicio tras el cierre.

## Lecciones aprendidas

- Las cuentas de servicio no deberían poder escalar a root; endurecer sudoers.

## Referencias

- https://attack.mitre.org/techniques/T1548/003/
