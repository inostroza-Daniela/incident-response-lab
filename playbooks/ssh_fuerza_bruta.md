# Playbook: ssh_fuerza_bruta

**Regla**: `ssh_fuerza_bruta`  ·  **ID**: `9c191180-315f-4a64-9a4e-e58685d11a46`
**Técnica ATT&CK**: T1110.001 — Fuerza bruta de contraseñas
**Nivel**: medium  ·  **Simulación**: `fuerza_bruta_ssh`

Alerta que lo gatilla: Diez o más fallos de autenticación SSH desde una misma IP en dos minutos (correlación sobre `ssh_fallo_autenticacion`).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `ssh_fuerza_bruta` (ID `9c191180-315f-4a64-9a4e-e58685d11a46`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `fuerza_bruta_ssh` y se confirma con `make verify SIM=fuerza_bruta_ssh`.

## Análisis y triaje

- Identificar la IP de origen (`data.srcip`) y si es interna o externa; en el lab, el origen simulado usa el rango de documentación 203.0.113.0/24.
- Revisar si algún fallo fue contra una cuenta válida existente (`data.dstuser`) o solo usuarios inexistentes (`data.srcuser`).
- Comprobar si tras la ráfaga hubo un login exitoso desde la misma IP: si lo hay, escalar al playbook de `ssh_login_exitoso_tras_rafaga`.

## Contención

- Bloquear la IP de origen en el firewall del host monitoreado (dentro del lab): `iptables -A INPUT -s <ip> -j DROP`.
- Si la cuenta objetivo es de servicio, deshabilitar temporalmente su acceso SSH por clave.

## Erradicación

- Confirmar que no se obtuvo acceso: revisar `authentication_success` para esa IP y usuario en la ventana.
- Rotar la contraseña de cualquier cuenta que haya sido objetivo repetido.

## Recuperación

- Retirar el bloqueo de IP una vez confirmado el cierre del incidente.
- Forzar autenticación por clave pública y deshabilitar `PasswordAuthentication` en sshd si aplica.

## Lecciones aprendidas

- Evaluar fail2ban o un umbral de bloqueo automático para exposición real.
- Ajustar el umbral de la correlación (10/2m) según el perfil de la red.

## Referencias

- https://attack.mitre.org/techniques/T1110/001/
