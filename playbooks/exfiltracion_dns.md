# Playbook: exfiltracion_dns

**Regla**: `exfiltracion_dns`  ·  **ID**: `2c5285ac-3bb6-4c60-a1b7-eac644e3b1cc`
**Técnica ATT&CK**: T1048.003, T1071.004 — Exfiltración por canal alternativo (DNS)
**Nivel**: high  ·  **Simulación**: `exfiltracion_dns`

Alerta que lo gatilla: Consulta DNS con primer label largo y codificado (base32/64/hex), tipo NULL o TXT codificado (Suricata, dns).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `exfiltracion_dns` (ID `2c5285ac-3bb6-4c60-a1b7-eac644e3b1cc`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `exfiltracion_dns` y se confirma con `make verify SIM=exfiltracion_dns`.

## Análisis y triaje

- Identificar el dominio de destino y el host de origen (`data.src_ip`).
- Estimar el volumen de consultas: la exfiltración por DNS genera muchas consultas al mismo dominio.
- Correlacionar con un acceso previo a datos sensibles (p. ej. lectura de shadow).

## Contención

- Bloquear el dominio de exfiltración en el resolver del lab y, si es posible, el egreso DNS del host.

## Erradicación

- Identificar y detener el proceso que genera las consultas (iodine, dnscat2 o script propio).
- Erradicar el vector que permitió instalar la herramienta de túnel.

## Recuperación

- Evaluar qué datos pudieron salir y gestionar el incidente de datos según corresponda.

## Lecciones aprendidas

- Forzar el uso de resolvers internos y monitorear dominios con entropía alta en los labels.

## Referencias

- https://attack.mitre.org/techniques/T1048/003/
- https://attack.mitre.org/techniques/T1071/004/
