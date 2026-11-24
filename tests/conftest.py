from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rules"


@pytest.fixture
def base_tiempo() -> datetime:
    return datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def reglas_fixture() -> Path:
    return FIXTURES


@pytest.fixture
def reglas_reales() -> Path:
    ruta = RAIZ / "reglas-upstream" / "rules"
    if not ruta.is_dir():
        pytest.skip("reglas-upstream no disponible (ejecutar scripts/obtener-reglas.py)")
    return ruta


@pytest.fixture
def lab(tmp_path: Path) -> dict[str, Path]:
    return {
        "telemetria": tmp_path / "telemetria.jsonl",
        "corridas": tmp_path / "corridas.jsonl",
        "alertas": tmp_path / "alertas" / "alerts.json",
        "reglas_wazuh": tmp_path / "reglas-wazuh",
    }


@pytest.fixture
def motor_disponible():
    pytest.importorskip("detectionlab", reason="extra 'verificacion' no instalado")


def _copiar(origen: Path, destino: Path) -> None:
    destino.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(origen, destino)
