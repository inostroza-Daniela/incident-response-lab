# Playbook: persistencia_cron

**Regla**: `persistencia_cron`  ·  **ID**: `c060f6fb-c45e-4827-806f-166691d83958`
**Técnica ATT&CK**: T1053.003 — Tarea programada (cron)
**Nivel**: medium  ·  **Simulación**: `persistencia_cron`

Alerta que lo gatilla: Escritura en un directorio o archivo de cron del sistema o de usuario (auditd).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `persistencia_cron` (ID `c060f6fb-c45e-4827-806f-166691d83958`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `persistencia_cron` y se confirma con `make verify SIM=persistencia_cron`.

## Análisis y triaje

- Identificar el archivo de cron tocado (`data.audit.file.name`) y su contenido.
- Distinguir una tarea legítima (despliegue, paquete) de una entrada maliciosa.
- Revisar a qué comando o script apunta la tarea.

## Contención

- Deshabilitar la tarea sospechosa comentándola o moviéndola fuera de los directorios de cron.

## Erradicación

- Eliminar la entrada de cron maliciosa y el script o binario al que invoca.
- Buscar otras entradas creadas por el mismo actor en cron de usuario (`/var/spool/cron/`).

## Recuperación

- Verificar que no queden tareas programadas no autorizadas: `for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null; done`.

## Lecciones aprendidas

- Inventariar las tareas cron legítimas para reducir el ruido y detectar lo anómalo más rápido.

## Referencias

- https://attack.mitre.org/techniques/T1053/003/
