# Base de Kubernetes (`k8s/base`)

Porte a Kubernetes del stack Docker Compose de `incident-response-lab`. Todos los
recursos viven en el namespace `irlab` y las imágenes están fijadas a `4.14.9`
(el operador usa `irlab-operador:0.1.0`).

## Contenido

| Grupo | Archivos | Función |
|---|---|---|
| Namespace | `namespace.yaml` | `irlab`, etiquetado `name: irlab`. |
| Red | `networkpolicy.yaml` | Default-deny de ingress/egress + Allow-list interna (DNS a `kube-system` incluido). |
| Configuración | `configmap-*.yml` | Copia literal de `config/wazuh/**` y `config/auditd/irlab.rules`. |
| Secretos | `secret-certs.yaml`, `secret-credentials.yaml` | Certificados reales codificados en base64 y credenciales por defecto de `.env.example`. |
| Almacenamiento | `pvc-*.yaml` | Datos del indexer y manager (RWO), telemetría y alertas (RWX). |
| Carga de trabajo | `deployment-*.yaml`, `job-init-telemetria.yaml` | Indexer, manager, dashboard, agente, operador y el Job inicial. |
| Servicios | `service-*.yaml` | ClusterIP internos para indexer (9200), manager (1514/55000) y dashboard (5601). |

## Uso

Esta base no se aplica directamente: se consume desde los overlays
`k8s/overlays/{dev,staging,prod}` con `kubectl apply -k`. Ver
`k8s/docs/README.md` para prerequisites, despliegue y operación.

## Notas

- `deployment-manager.yaml` incluye un ConfigMap `irlab-local-rules-placeholder`:
  es un marcador de posición, no las reglas reales.
- Los archivos de configuración se copiaron verbatim del repositorio; los nombres
  con punto (`wazuh.indexer`, `wazuh.manager`) vienen del Compose y requieren
  resolución DNS equivalente en el clúster (ver documentación).
- `networkpolicy.yaml` mantiene la semántica `internal: true` de la red del lab.
