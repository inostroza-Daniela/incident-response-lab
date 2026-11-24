# Playbook: escaneo_red_saliente

**Regla**: `escaneo_red_saliente`  ·  **ID**: `fd72cbc3-d895-4d43-8841-9f2b9411d91f`
**Técnica ATT&CK**: T1046 — Descubrimiento de servicios de red
**Nivel**: high  ·  **Simulación**: `escaneo_puertos`

Alerta que lo gatilla: Un origen interno intenta conectarse a 20 o más puertos distintos sin respuesta en un minuto (correlación sobre `conexion_saliente_sin_respuesta`).

> Todas las acciones aplican dentro del laboratorio aislado. Los comandos son de
> referencia para el nodo monitoreado del lab; adaptarlos antes de usarlos en
> cualquier otro entorno.

## Detección

- La alerta proviene de la regla `escaneo_red_saliente` (ID `fd72cbc3-d895-4d43-8841-9f2b9411d91f`) desplegada en Wazuh.
- Se reproduce en el lab con la simulación `escaneo_puertos` y se confirma con `make verify SIM=escaneo_puertos`.

## Análisis y triaje

- Identificar el host de origen (`data.src_ip`) y el rango de destino escaneado.
- Un escaneo saliente desde un host interno suele indicar descubrimiento tras un compromiso.
- Descartar escáneres autorizados (inventario, vulnerabilidades) por su IP.

## Contención

- Aislar el host de origen de la red del lab mientras se investiga.

## Erradicación

- Identificar y detener el proceso que escanea (nmap, masscan o script) y su vector de entrada.

## Recuperación

- Reincorporar el host tras confirmar que no quedan herramientas ni persistencia.

## Lecciones aprendidas

- Segmentar la red para limitar el movimiento lateral y excluir los escáneres autorizados de la regla.

## Referencias

- https://attack.mitre.org/techniques/T1046/
