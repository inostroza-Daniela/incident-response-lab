# Playbook: borrado_logs_historial

**Regla**: `borrado_logs_historial`  ·  **ID**: `5c70de3c-2734-4b96-84ec-239f70c97400`
**Técnica ATT&CK**: T1070.002, T1070.003 — Borrado de indicadores
**Nivel**: high  ·  **Simulación**: `borrado_historial`

Alerta que lo gatilla: Eliminación o truncado de logs del sistema/auditoría, o limpieza del historial de la shell (auditd).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `borrado_logs_historial` (ID `5c70de3c-2734-4b96-84ec-239f70c97400`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `borrado_historial` y se confirma con `make verify SIM=borrado_historial`.

## Análisis y triaje

- Identificar qué log o historial se tocó (`data.audit.file.name` o `cmdline`) y por qué proceso.
- El borrado de logs suele ser una fase tardía: buscar la actividad que el atacante intenta ocultar.

## Contención

- Preservar de inmediato las fuentes de evidencia restantes (copiar logs y journald a almacenamiento separado del lab).

## Erradicación

- Reconstruir la línea de tiempo con las alertas ya enviadas al manager (que no dependen del log local borrado).
- Erradicar el acceso del actor y la persistencia asociada.

## Recuperación

- Restaurar la configuración de logging y verificar que auditd y rsyslog estén activos.

## Lecciones aprendidas

- Enviar los logs a un destino central (como este manager) en tiempo real: el borrado local no elimina la evidencia ya remitida.

## Referencias

- https://attack.mitre.org/techniques/T1070/002/
- https://attack.mitre.org/techniques/T1070/003/
