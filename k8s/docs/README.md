# Kubernetes / Kustomize del incident-response-lab

## Qué es

Es el porte a Kubernetes del laboratorio Docker Compose de Wazuh
(`docker-compose.yml`): indexer, manager, dashboard, un agente en el
`nodo-monitoreado`, el `operador` que lanza simulaciones y un Job que inicializa
el archivo de telemetría compartido. Mantiene la semántica de red interna del
Compose (`internal: true`) mediante `NetworkPolicy`, usa los mismos archivos de
configuración y certificados del repositorio, y fija todas las imágenes de Wazuh
a `4.14.9` (nunca `latest`).

## Estructura

```
k8s/
├── base/                   # manifiestos comunes (namespace, red, configs, secretos, PVCs, deployments, servicios)
│   └── kustomization.yaml
├── overlays/
│   ├── dev/                # heap 512m, sin límites, dashboard NodePort 30443
│   ├── staging/            # recursos estándar + Ingress con autenticación básica
│   └── prod/               # requests/limits completos, egress estricto, PDBs
└── docs/README.md          # este documento
```

## Quickstart

Flujo mínimo desde la raíz del repositorio (entorno `dev`):

```bash
# 1. Generar certificados
bash scripts/generar-certs.sh

# 2. Crear el .env con las credenciales (requerido por kustomize)
cp .env.example .env

# 3. Previsualizar
kubectl kustomize k8s/overlays/dev

# 4. Desplegar
kubectl apply -k k8s/overlays/dev

# 5. Esperar a que termine el Job de inicialización
kubectl wait --for=condition=complete job/init-telemetria -n irlab

# 6. Simular
kubectl exec -it deploy/operador -n irlab -- python -m irlab simulate todas

# 7. Verificar
kubectl exec -it deploy/operador -n irlab -- python -m irlab verify todas
```

## Prerrequisitos

- `kubectl` con soporte built-in de Kustomize, o el binario `kustomize` (v4+).
  Para previsualizar: `kubectl kustomize k8s/overlays/dev` o `kustomize build k8s/overlays/dev`.
- Un clúster con CNI que aplique `NetworkPolicy` (Calico, Cilium, etc.); si no,
  el default-deny no tendrá efecto.
- `vm.max_map_count >= 262144` en los nodos donde corra el indexer:
  `sudo sysctl -w vm.max_map_count=262144`.
- Certificados ya generados en `config/wazuh/certs/` (`bash scripts/generar-certs.sh`).
- El archivo `.env` debe existir en la raíz del repositorio (crearlo con
  `cp .env.example .env`): `kustomize` usa `secretGenerator envs: ../../.env` para
  las credenciales, por lo que `kustomize build` (y `kubectl apply -k`) fallará si
  `.env` no está presente.
- Una `StorageClass` con `ReadWriteMany` para `irlab-telemetria` e `irlab-alertas`
  (p. ej. NFS). Las PVC de datos del indexer y manager son `ReadWriteOnce`.
- La imagen `irlab-operador:0.1.0` disponible en los nodos (o en un registry; ver abajo).
- Opcional para staging: controlador `ingress-nginx`, un host real y el Secret
  `irlab-dashboard-basic-auth`.

## Aplicar

```bash
# Previsualizar
kubectl kustomize k8s/overlays/dev

# Desplegar cada entorno
kubectl apply -k k8s/overlays/dev
kubectl apply -k k8s/overlays/staging
kubectl apply -k k8s/overlays/prod

# Limpiar el mismo entorno
kubectl delete -k k8s/overlays/dev
```

Solo se aplica un overlay a la vez: todos usan el namespace `irlab`.

### Dev

Reduce el heap de OpenSearch a `-Xms512m -Xmx512m`, elimina los `limits` de CPU y
memoria y publica el dashboard como `NodePort 30443` para acceso desde el host.

### Staging

Mantiene los recursos estándar (heap `1g/1g`) y añade un `Ingress` para el
dashboard con `backend-protocol: HTTPS` y autenticación básica. Crear antes:

```bash
htpasswd -c auth admin
kubectl create secret generic irlab-dashboard-basic-auth --from-file=auth -n irlab
```

Editar `host` y `secretName` TLS en `k8s/overlays/staging/ingress-dashboard.yaml`.

### Prod

Fija `requests`/`limits` completos, conserva el heap `1g/1g`, restringe el DNS a
los pods de CoreDNS y el ingreso al dashboard al operador, y añade PDBs con
`minAvailable: 1` para indexer y manager (con una réplica esto bloquea el drenaje
voluntario del nodo, decisión deliberada en el laboratorio).

## Imagen del operador

La imagen del Compose se construye desde la raíz del repositorio:

```bash
docker build -t irlab-operador:0.1.0 -f config/operador/Dockerfile .
```

En clústeres locales (kind/minikube) la imagen **debe cargarse en los nodos** del
clúster; si no, los pods quedarán en `ImagePullBackOff`:

```bash
kind load docker-image irlab-operador:0.1.0
# or
minikube image load irlab-operador:0.1.0
```

Para un clúster real, subirla a un registry y **actualizar la imagen en el
overlay** (sin tocar la base), añadiendo por ejemplo a
`k8s/overlays/<entorno>/kustomization.yaml`:

```yaml
images:
  - name: irlab-operador
    newName: registry.example.com/irlab/irlab-operador
    newTag: 0.1.0
```

`/lab` es un `emptyDir`: un `initContainer` siembra `src/`, `simulations/`,
`pyproject.toml` y `README.md` desde la imagen; el resto del repositorio
(`estado/`, `site/`, `reglas-upstream/`, `reglas-wazuh/`, `playbooks/`) debe
sincronizarse, por ejemplo:

```bash
POD=$(kubectl get pod -n irlab -l app=operador -o jsonpath='{.items[0].metadata.name}')
tar -cf - --exclude=.git --exclude=k8s . | kubectl exec -i -n irlab "$POD" -- tar -xf - -C /lab
```

Las variables de `src/irlab/rutas.py` están fijadas para que `IRLAB_RAIZ=/lab`,
telemetría en `/var/log/lab/telemetria.jsonl` y alertas en `/alertas/alerts.json`.

## Certificados

Generar los certificados locales:

```bash
bash scripts/generar-certs.sh
```

Esto crea 10 archivos en `config/wazuh/certs/` (`.pem` y `.key`). Ese directorio está en `.gitignore`, por lo que **no se commitea** material de llaves privadas.

El `kustomization.yaml` de base usa `secretGenerator` con `files:` para leer esos 10 archivos locales y crear el Secret `irlab-certs` en el clúster:

```yaml
secretGenerator:
  - name: irlab-certs
    files:
      - ../../config/wazuh/certs/root-ca.pem
      # ... (resto de certs y llaves)
    options:
      disableNameSuffixHash: true
```

Los certificados ya incluyen SAN con los nombres con punto (`wazuh.indexer`, `wazuh.manager`), pero los Servicios de Kubernetes usan nombres con guion (`wazuh-indexer`, `wazuh-manager`). Por eso el manager usa `FILEBEAT_SSL_VERIFICATION_MODE: "certificate"` (valida la CA, no el hostname), para que no falle la conexión TLS entre componentes.

Si se regeneran los certificados, el Secret se recrea automáticamente al volver a aplicar el overlay (Kustomize detecta el cambio de contenido de los archivos). No es necesario editar ningún manifest.

Las credenciales por defecto de `.env.example` se inyectan en el clúster mediante `secretGenerator envs: ../../.env` (crear `.env` con `cp .env.example .env` antes de construir). Si se cambian las contraseñas, actualizar también los hashes de `internal_users.yml` (`make hash-pass`) y su ConfigMap.

## Acceso al dashboard

```bash
kubectl port-forward service/wazuh-dashboard 8443:5601 -n irlab
# abrir https://localhost:8443
```

En dev también está disponible en `https://<IP-del-nodo>:30443`; en staging, a
través del host del Ingress (con autenticación básica).

## Notas operativas

1. **Orden de arranque:** el Job `init-telemetria` debe terminar antes de que
   arranque el agente; el `initContainer` `wait-for-telemetria` del
   `nodo-monitoreado` espera a que exista `/var/log/lab/telemetria.jsonl`.
   Lanzar las simulaciones solo cuando el operador y el agente estén listos:

   ```bash
   kubectl apply -k k8s/overlays/dev
   kubectl wait --for=condition=complete job/init-telemetria -n irlab
   kubectl exec -it deploy/operador -n irlab -- python -m irlab simulate todas
   kubectl exec -it deploy/operador -n irlab -- python -m irlab verify todas
   ```

2. **Reglas locales:** `deployment-manager.yaml` monta un ConfigMap
   `irlab-local-rules-placeholder`, no las reglas reales. Hay que ejecutar
   `irlab convert` (equivalente a `make convert`) y sustituirlo con el contenido
   de `reglas-wazuh/local_rules.xml`, equivalente K8s de `make load-rules`:

   ```bash
   POD=$(kubectl get pod -n irlab -l app=operador -o jsonpath='{.items[0].metadata.name}')
   kubectl exec -n irlab "$POD" -- python -m irlab convert
   kubectl create configmap irlab-local-rules-real \
     --from-file=local_rules.xml=reglas-wazuh/local_rules.xml -n irlab \
     --dry-run=client -o yaml | kubectl apply -f -
   # Cambiar `configMap.name` del volumen `local-rules` a `irlab-local-rules-real`
   # y reiniciar el manager:
   kubectl rollout restart deploy/wazuh-manager -n irlab
   ```

   Helper concreto (equivalente a `make convert` + `make load-rules`) para
   generar el ConfigMap real de reglas y reiniciar el manager en un solo bloque:

    ```bash
    POD=$(kubectl get pod -n irlab -l app=operador -o jsonpath='{.items[0].metadata.name}')
    kubectl exec -n irlab "$POD" -- python -m irlab convert
    kubectl create configmap irlab-local-rules-real --from-file=local_rules.xml=reglas-wazuh/local_rules.xml -n irlab --dry-run=client -o yaml | kubectl apply -f -
    kubectl rollout restart deploy/wazuh-manager -n irlab
    ```

   Recuerda cambiar `configMap.name` del volumen `local-rules` a
   `irlab-local-rules-real` en `deployment-manager.yaml` antes de reiniciar.

3. **Imágenes fijadas:** Wazuh `4.14.9` en indexer, manager, dashboard, Job y
   agente; `irlab-operador:0.1.0` para el operador. No usar `latest`.

## Limitaciones y diferencias respecto al Compose

- El bind `127.0.0.1:8443:5601` del Compose se traduce a un Service `ClusterIP`
  en la base más `kubectl port-forward` (o NodePort/Ingress en los overlays).
- La configuración se copió **verbatim**: referencias con punto (`wazuh.indexer`,
  `wazuh.manager`) y el `node.name` del indexer vienen del Compose. Los Services
  de Kubernetes usan nombres con guion (`wazuh-indexer`, `wazuh-manager`); para
  que esos nombres con punto resuelvan hace falta un alias DNS equivalente
  (p. ej. reglas `rewrite` de CoreDNS) o adaptar los archivos de configuración
  al desplegar. No se modificaron los archivos fuente del repositorio.
- Los `ulimits` (`memlock=-1`, `nofile=65536`) no son campos del PodSpec: se
  documentan como anotación y se aproximan con la capability `IPC_LOCK`.
- Las reglas de `config/auditd/irlab.rules` se montan en el agente con fines
  ilustrativos: **auditd no funciona dentro de contenedores** (necesita el
  subsistema de auditoría del kernel del host). La detección del lab entra por
  la telemetría JSON, como se indica en `docs/arquitectura.md`.
- Los dashboards y el manager usan certificados con nombres de archivo distintos
  a los del Compose; el mapeo está en los `items:` de cada volumen `secret`.
