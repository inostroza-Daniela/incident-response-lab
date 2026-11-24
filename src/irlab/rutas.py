"""Rutas del laboratorio, configurables por variables de entorno.

Valores por defecto pensados para ejecutar desde la raíz del repo. En los
contenedores, el `docker-compose` monta estas rutas en las ubicaciones que espera
cada servicio (ver `docker-compose.yml`).
"""

from __future__ import annotations

import os
from pathlib import Path


def _ruta(variable: str, defecto: str) -> Path:
    return Path(os.environ.get(variable, defecto)).expanduser()


def raiz() -> Path:
    return _ruta("IRLAB_RAIZ", str(Path(__file__).resolve().parents[2]))


def estado() -> Path:
    return _ruta("IRLAB_ESTADO", str(raiz() / "estado"))


def telemetria() -> Path:
    """Archivo JSONL que vigila el agente del nodo monitoreado."""
    return _ruta("IRLAB_TELEMETRIA", str(estado() / "telemetria.jsonl"))


def corridas() -> Path:
    """Registro de simulaciones ejecutadas (para `report` y para revertir)."""
    return _ruta("IRLAB_CORRIDAS", str(estado() / "corridas.jsonl"))


def alertas() -> Path:
    """`alerts.json` del manager, montado como volumen para la verificación."""
    return _ruta("IRLAB_ALERTAS", str(estado() / "alertas" / "alerts.json"))


def reglas_upstream() -> Path:
    """Reglas Sigma del detection-engineering-lab (las descarga `obtener-reglas`)."""
    return _ruta("IRLAB_REGLAS", str(raiz() / "reglas-upstream" / "rules"))


def reglas_wazuh() -> Path:
    return _ruta("IRLAB_REGLAS_WAZUH", str(raiz() / "reglas-wazuh"))


def sitio() -> Path:
    return _ruta("IRLAB_SITIO", str(raiz() / "site"))
