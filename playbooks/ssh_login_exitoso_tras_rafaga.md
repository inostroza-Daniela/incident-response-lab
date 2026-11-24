# Playbook: ssh_login_exitoso_tras_rafaga

**Regla**: `ssh_login_exitoso_tras_rafaga`  ·  **ID**: `ee3a5b04-0680-4e8b-ac58-9faf9aa7308d`
**Técnica ATT&CK**: T1110.001, T1078 — Fuerza bruta y cuentas válidas
**Nivel**: high  ·  **Simulación**: `login_tras_rafaga`

Alerta que lo gatilla: Login SSH exitoso desde una IP que generó una ráfaga de fallos en los 10 minutos previos (correlación ordenada).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `ssh_login_exitoso_tras_rafaga` (ID `ee3a5b04-0680-4e8b-ac58-9faf9aa7308d`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `login_tras_rafaga` y se confirma con `make verify SIM=login_tras_rafaga`.

## Análisis y triaje

- Tratar como compromiso probable de credenciales: la fuerza bruta funcionó o se adivinó una clave válida.
- Identificar la cuenta comprometida (`data.dstuser`) y la IP de origen.
- Revisar qué hizo la sesión tras el login: procesos, nuevas cuentas, cambios de persistencia.

## Contención

- Cerrar la sesión activa del atacante en el host del lab: `pkill -KILL -u <usuario>` o terminar el PID de la sesión sshd.
- Bloquear la IP de origen y deshabilitar la cuenta comprometida (`usermod -L <usuario>`).

## Erradicación

- Rotar la credencial comprometida y revocar llaves SSH no reconocidas en `~/.ssh/authorized_keys`.
- Buscar persistencia dejada en la sesión (cron, systemd, cuentas nuevas) y erradicarla con los playbooks correspondientes.

## Recuperación

- Reactivar la cuenta con credenciales nuevas y, si es posible, MFA.
- Revisar accesos posteriores legítimos para confirmar normalidad.

## Lecciones aprendidas

- Priorizar MFA en cuentas expuestas; una sola correlación de este tipo justifica respuesta inmediata.

## Referencias

- https://attack.mitre.org/techniques/T1110/001/
- https://attack.mitre.org/techniques/T1078/
