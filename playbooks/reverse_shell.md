# Playbook: reverse_shell

**Regla**: `reverse_shell`  ·  **ID**: `b0ddbaa6-a2b7-468c-8959-84f96267bb99`
**Técnica ATT&CK**: T1059.004, T1095 — Shell reversa
**Nivel**: critical  ·  **Simulación**: `reverse_shell`

Alerta que lo gatilla: Línea de comando con un patrón de shell reversa: /dev/tcp, netcat con -e, socat exec, mkfifo encadenado o intérprete con socket (auditd).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `reverse_shell` (ID `b0ddbaa6-a2b7-468c-8959-84f96267bb99`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `reverse_shell` y se confirma con `make verify SIM=reverse_shell`.

## Análisis y triaje

- Identificar el proceso y su destino (en el lab, el nodo operador 10.20.0.10); tratar como ejecución remota activa.
- Determinar la cuenta y el proceso padre para ubicar el vector de entrada (webshell, descarga, sesión SSH).

## Contención

- Aislar el host del lab de la red de inmediato para cortar el canal C2.
- Terminar el proceso de la shell reversa y su cadena de procesos.

## Erradicación

- Erradicar el vector de entrada (webshell, binario descargado) y toda persistencia asociada.
- Buscar conexiones salientes adicionales y herramientas dejadas en /tmp, /dev/shm, /var/tmp.

## Recuperación

- Reconstruir el host desde una imagen de confianza si hubo ejecución de código como root.

## Lecciones aprendidas

- Egreso restringido por defecto: limitar las conexiones salientes del host reduce el impacto de una shell reversa.

## Referencias

- https://attack.mitre.org/techniques/T1059/004/
- https://attack.mitre.org/techniques/T1095/
