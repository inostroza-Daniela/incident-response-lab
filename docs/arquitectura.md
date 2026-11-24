# Arquitectura

El laboratorio levanta una red interna de Docker con el SIEM, un nodo monitoreado
y un nodo operador desde el que se lanzan las simulaciones. Todo el tráfico del
laboratorio ocurre en una red `internal`; el único puerto publicado es el del
dashboard, y solo en `127.0.0.1`.

```
                            red interna de Docker (irlab, internal)
  ┌───────────────────────────────────────────────────────────────────────────┐
  │                                                                             │
  │   ┌───────────────┐      logs/alertas     ┌───────────────┐                 │
  │   │   operador    │──────telemetría──────▶│ nodo-monitoreado│               │
  │   │  (irlab CLI)  │   (volumen compartido) │  agente Wazuh  │               │
  │   └──────┬────────┘                        │   + auditd     │               │
  │          │ lee alertas                     └───────┬────────┘               │
  │          │ (volumen ro)                            │ eventos (1514/tcp)     │
  │          ▼                                         ▼                        │
  │   ┌───────────────┐   indexa   ┌───────────────┐  filebeat ┌──────────────┐ │
  │   │ wazuh.manager │───────────▶│ wazuh.indexer │◀──────────│   (alertas)  │ │
  │   │ (analysisd +  │            │  (OpenSearch) │           └──────────────┘ │
  │   │  reglas irlab)│            └──────┬────────┘                            │
  │   └───────────────┘                   │                                     │
  │                                        │ consulta                           │
  │                               ┌────────▼────────┐                           │
  │                               │ wazuh.dashboard │─── 127.0.0.1:8443 ──▶ host │
  │                               └─────────────────┘                           │
  └───────────────────────────────────────────────────────────────────────────┘
```

## Componentes

| Servicio | Imagen (fijada) | Rol |
|---|---|---|
| `wazuh.indexer` | `wazuh/wazuh-indexer:4.14.9` | Almacena y consulta alertas (OpenSearch). |
| `wazuh.manager` | `wazuh/wazuh-manager:4.14.9` | Decodifica eventos y evalúa las reglas convertidas. |
| `wazuh.dashboard` | `wazuh/wazuh-dashboard:4.14.9` | Interfaz web (solo en loopback). |
| `nodo-monitoreado` | `wazuh/wazuh-agent:4.14.9` | Agente Wazuh + política auditd; vigila la telemetría del lab. |
| `operador` | imagen local (python:3.12-slim) | Lanza las simulaciones y verifica las alertas. |
| certificados | OpenSSL en el host (`scripts/generar-certs.sh`) | Genera los certificados internos (una vez, sin descargas). |

La versión 4.14.9 es la primera serie estable con imagen oficial `linux/arm64`
del manager, el indexer, el dashboard y el agente, por lo que la topología levanta
igual en un Mac Apple Silicon y en un host amd64.

## Flujo de una simulación

1. `operador` genera la telemetría normalizada de la técnica (esquema de alertas
   de Wazuh, el mismo del `detection-engineering-lab`) y la escribe, envuelta en
   el espacio de nombres `irlab`, en el archivo que vigila el nodo monitoreado.
2. El agente del nodo monitoreado envía esos eventos al manager.
3. El manager evalúa las reglas convertidas (`local_rules.xml`) y genera la
   alerta correspondiente, que queda en el indexer y en `alerts.json`.
4. `operador` lee `alerts.json` y confirma que apareció la alerta de la regla
   esperada (`irlab verify`).
5. Cada alerta tiene su **playbook de respuesta** (`playbooks/<regla>.md`) con la
   estructura de la ANCI.

## Por qué telemetría normalizada y no ataques reales

Las simulaciones son **generadores de telemetría**: reproducen los eventos que
cada técnica dejaría en el nodo monitoreado, acotados a la red del laboratorio y
sin ejecutar payloads ofensivos reales. Esto mantiene el laboratorio como un
entorno defensivo y reproducible:

- La corrección de la detección se valida de forma determinista contra el motor
  del repo de reglas (ver `tests/`), sin depender de que un exploit "funcione".
- La telemetría sale en el esquema exacto del `detection-engineering-lab`, así que
  alimenta sus `samples/` sin conversión (`irlab export`).
- No se versiona ni se distribuye ninguna herramienta de ataque reutilizable.

El nodo monitoreado trae la política auditd real (`config/auditd/irlab.rules`,
la misma que alimenta las reglas del repo de detección) para desplegar el lab
sobre hosts reales como ampliación; en el laboratorio contenedorizado la ruta de
detección que se verifica de extremo a extremo es la ingesta de telemetría
normalizada, que no depende de auditd dentro de un contenedor (poco fiable en
Docker Desktop sobre Apple Silicon).
