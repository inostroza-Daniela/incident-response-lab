# Playbook: persistencia_systemd

**Regla**: `persistencia_systemd`  ·  **ID**: `0bd028cb-d6d3-4bce-9ae5-74d0cdf61f68`
**Técnica ATT&CK**: T1543.002 — Servicio del sistema (systemd)
**Nivel**: medium  ·  **Simulación**: `persistencia_systemd`

Alerta que lo gatilla: Creación o modificación de una unidad systemd (.service/.timer/.socket/.path) fuera de un gestor de paquetes (auditd).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `persistencia_systemd` (ID `0bd028cb-d6d3-4bce-9ae5-74d0cdf61f68`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `persistencia_systemd` y se confirma con `make verify SIM=persistencia_systemd`.

## Análisis y triaje

- Identificar la unidad creada (`data.audit.file.name`) y revisar su `ExecStart`.
- Confirmar si proviene de una instalación legítima de software.

## Contención

- Detener y deshabilitar la unidad sospechosa: `systemctl stop <unidad>` y `systemctl disable <unidad>`.

## Erradicación

- Eliminar el archivo de la unidad y recargar systemd: `rm <ruta>.service && systemctl daemon-reload`.
- Eliminar el binario o script que la unidad ejecutaba.

## Recuperación

- Listar unidades habilitadas y contrastar con el inventario: `systemctl list-unit-files --state=enabled`.

## Lecciones aprendidas

- Monitorear cambios en los directorios de systemd; una unidad nueva fuera de un paquete merece revisión.

## Referencias

- https://attack.mitre.org/techniques/T1543/002/
