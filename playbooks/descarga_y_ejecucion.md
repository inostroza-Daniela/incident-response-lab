# Playbook: descarga_y_ejecucion

**Regla**: `descarga_y_ejecucion`  ·  **ID**: `e4ee2dcf-633b-4f68-8b80-428f9ba2d320`
**Técnica ATT&CK**: T1105, T1059.004 — Descarga y ejecución
**Nivel**: high  ·  **Simulación**: `descarga_ejecucion`

Alerta que lo gatilla: Descarga con curl o wget seguida de ejecución inmediata (tubería a shell, sustitución o descarga a /tmp + chmod) (auditd).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `descarga_y_ejecucion` (ID `e4ee2dcf-633b-4f68-8b80-428f9ba2d320`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `descarga_ejecucion` y se confirma con `make verify SIM=descarga_ejecucion`.

## Análisis y triaje

- Identificar la URL de origen (en el lab, el nodo operador) y el archivo descargado.
- Determinar qué se ejecutó y con qué privilegios.

## Contención

- Aislar el host del lab y cortar el acceso saliente.
- Terminar los procesos derivados de la descarga.

## Erradicación

- Eliminar el artefacto descargado (habitualmente en /tmp, /dev/shm o /var/tmp) y cualquier persistencia que haya instalado.

## Recuperación

- Verificar integridad del host y, ante ejecución privilegiada, reconstruir desde imagen limpia.

## Lecciones aprendidas

- Bloquear egreso a destinos no aprobados; alertar sobre `curl|sh` en hosts de producción.

## Referencias

- https://attack.mitre.org/techniques/T1105/
- https://attack.mitre.org/techniques/T1059/004/
