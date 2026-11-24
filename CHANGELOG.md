# Changelog

Todas las novedades relevantes de este proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el
proyecto adhiere a [Versionado Semántico](https://semver.org/lang/es/).

## [0.1.0] - 2026-11-19

### Agregado

- Topología del laboratorio en `docker-compose.yml`: stack Wazuh (manager,
  indexer, dashboard) + nodo monitoreado con agente y auditd + nodo operador, en
  red interna, con solo el dashboard publicado en loopback. Imágenes fijadas a
  4.14.9 (arm64 + amd64).
- Paquete `irlab`: generación de telemetría, conversión de reglas Sigma a reglas
  locales de Wazuh, orquestación e informe.
- 13 simulaciones de telemetría (`simulations/`), una por técnica ATT&CK, mapeadas
  a las reglas del `detection-engineering-lab`.
- 13 playbooks de respuesta (`playbooks/`) con la estructura de la ANCI.
- CLI `irlab` (`listar`, `convert`, `simulate`, `verify`, `revert`, `export`,
  `report`) y `Makefile` para el ciclo de vida de la topología.
- Suite de pruebas (pytest) con validación de la telemetría contra el motor del
  repo de detección, sin depender de Docker; lint con ruff y tipos con mypy.
- CI: lint, tipos y pruebas en matriz ubuntu/macOS × Python 3.11/3.12, validación
  del compose y de los YAML; workflow de end-to-end con Docker a demanda.

[0.1.0]: https://github.com/inostroza-Daniela/incident-response-lab/releases/tag/v0.1.0
