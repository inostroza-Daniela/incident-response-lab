# Guía de uso

> Laboratorio de uso exclusivo en entorno aislado. No exponer a internet ni
> apuntar a sistemas de terceros.

## Requisitos

- Docker y Docker Compose (Docker Desktop en macOS / Windows, Docker Engine en
  Linux).
- Al menos 8 GB de RAM asignados a Docker y `vm.max_map_count` ≥ 262144 (en
  Linux: `sudo sysctl -w vm.max_map_count=262144`; en Docker Desktop se ajusta en
  la VM).
- Python 3.11+ en el host solo para las tareas locales (conversión, lint, tests);
  dentro del lab, la conversión corre en el contenedor `operador`.

## Puesta en marcha

```bash
cp .env.example .env            # credenciales SOLO de laboratorio
python scripts/obtener-reglas.py   # descarga las reglas del repo de detección
make certs                      # genera los certificados internos (una vez)
make up                         # levanta toda la topología
make load-rules                 # convierte y carga las reglas en el manager
```

El dashboard queda en `https://localhost:8443` (usuario `admin`, contraseña del
`.env`). La primera vez el indexer tarda un par de minutos en inicializar.

## Correr simulaciones

```bash
make simulate SIM=reverse_shell   # una simulación
make simulate SIM=todas           # todas
make verify SIM=todas             # confirma que aparecieron las alertas
make report                       # genera el informe y el sitio (site/index.html)
```

Para dejar el laboratorio limpio entre pruebas:

```bash
make revert SIM=reverse_shell     # revierte una simulación
make revert                       # revierte toda la telemetría
```

## Catálogo de simulaciones

```bash
make simulate SIM=todas   # o: docker compose exec operador python -m irlab listar
```

| Simulación | Técnica ATT&CK | Regla |
|---|---|---|
| `fuerza_bruta_ssh` | T1110.001 | `ssh_fuerza_bruta` |
| `login_tras_rafaga` | T1110.001 / T1078 | `ssh_login_exitoso_tras_rafaga` |
| `cuenta_sudo` | T1136.001 / T1098 | `cuenta_local_creada_o_agregada_a_sudo` |
| `escalamiento_sudo` | T1548.003 | `escalamiento_sudo_su_anomalo` |
| `modificacion_credenciales` | T1003.008 / T1098 | `modificacion_passwd_shadow` |
| `persistencia_cron` | T1053.003 | `persistencia_cron` |
| `persistencia_systemd` | T1543.002 | `persistencia_systemd` |
| `webshell` | T1505.003 | `webshell_proceso_hijo_servidor_web` |
| `reverse_shell` | T1059.004 / T1095 | `reverse_shell` |
| `descarga_ejecucion` | T1105 / T1059.004 | `descarga_y_ejecucion` |
| `exfiltracion_dns` | T1048.003 / T1071.004 | `exfiltracion_dns` |
| `borrado_historial` | T1070.002 / T1070.003 | `borrado_logs_historial` |
| `escaneo_puertos` | T1046 | `escaneo_red_saliente` |

## Alimentar de vuelta el repo de detección

```bash
make export-samples   # escribe estado/muestras-reales/<simulacion>.jsonl
```

Los archivos salen en el esquema del `detection-engineering-lab` y se pueden
copiar a sus `samples/reales/` sin conversión.

## Desarrollo local (sin Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts/obtener-reglas.py
pip install -e ".[verificacion]"   # motor del repo de reglas para los tests
make lint
make test
```

Qué corre en CI y qué es local:

- **CI (`.github/workflows/ci.yml`)**: lint, tipos y pruebas en una matriz
  ubuntu/macOS × Python 3.11/3.12, más la validación del `docker-compose` y de
  los YAML de configuración. Las pruebas que cruzan la telemetría contra el motor
  del repo de reglas corren si la descarga de reglas tiene red; si no, se saltan.
- **Local / a demanda (`.github/workflows/e2e-docker.yml`)**: el end-to-end con
  Docker (levantar la topología, cargar reglas, simular y verificar). Es pesado;
  se dispara manualmente.
