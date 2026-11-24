# Playbook: cuenta_local_creada_o_agregada_a_sudo

**Regla**: `cuenta_local_creada_o_agregada_a_sudo`  ·  **ID**: `ea7d86be-f211-40c4-b91b-c502128792e3`
**Técnica ATT&CK**: T1136.001, T1098 — Creación de cuenta y manipulación de acceso
**Nivel**: high  ·  **Simulación**: `cuenta_sudo`

Alerta que lo gatilla: Alta de cuenta local y/o incorporación de un usuario a sudo/wheel/admin, o escritura en /etc/sudoers (auditd).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `cuenta_local_creada_o_agregada_a_sudo` (ID `ea7d86be-f211-40c4-b91b-c502128792e3`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `cuenta_sudo` y se confirma con `make verify SIM=cuenta_sudo`.

## Análisis y triaje

- Identificar la cuenta creada o modificada y quién la ejecutó (`data.audit.auid`, `data.audit.exe`).
- Determinar si corresponde a un aprovisionamiento legítimo (Ansible, cloud-init) o es inesperado.
- Revisar el momento: una cuenta nueva fuera de ventana de mantenimiento es sospechosa.

## Contención

- Deshabilitar la cuenta sospechosa: `usermod -L <usuario>` y `usermod -s /usr/sbin/nologin <usuario>`.
- Revertir la membresía a sudo: `gpasswd -d <usuario> sudo`.

## Erradicación

- Eliminar la cuenta si no es legítima: `userdel -r <usuario>`.
- Revisar y limpiar entradas añadidas en `/etc/sudoers.d/`.

## Recuperación

- Validar la lista de cuentas con sudo contra el inventario autorizado.

## Lecciones aprendidas

- Centralizar la creación de cuentas en un flujo auditado; alertar sobre altas fuera de ese flujo.

## Referencias

- https://attack.mitre.org/techniques/T1136/001/
- https://attack.mitre.org/techniques/T1098/
