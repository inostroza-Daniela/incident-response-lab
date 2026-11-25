# Contribuir

## Entorno

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts/obtener-reglas.py
pip install -e ".[verificacion]"
pre-commit install
```

## Antes de abrir un PR

- `make lint` — ruff (lint + formato) y mypy en modo estricto sin errores.
- `make test` — la suite completa en verde.
- Si agregas una simulación: registrala en `simulations/`, sumá su entrada al
  catálogo (`src/irlab/catalogo.py`) y creá su playbook en `playbooks/`. Los tests
  de consistencia exigen que cada simulación tenga regla y playbook.
- Nada apunta fuera de la red del laboratorio: las simulaciones solo generan
  telemetría acotada al lab.

## Reglas de detección

No se escriben reglas de detección en este repo: se reutilizan del
`detection-engineering-lab`. Para cambiar la detección, trabajá en ese repo y
actualizá el commit fijado en `scripts/obtener-reglas.py`.

## Estilo

Código y documentación en español (los campos estándar de Sigma y Wazuh se dejan
en su forma original). Sin dependencias comerciales ni APIs externas.
