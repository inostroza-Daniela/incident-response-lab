from __future__ import annotations

import io
from pathlib import Path

from irlab import cli


def _correr(argv, monkeypatch, env=None):
    for clave, valor in (env or {}).items():
        monkeypatch.setenv(clave, str(valor))
    salida = io.StringIO()
    codigo = cli.main(argv, salida=salida)
    return codigo, salida.getvalue()


def test_listar(monkeypatch):
    codigo, texto = _correr(["listar"], monkeypatch)
    assert codigo == 0
    assert "reverse_shell" in texto
    assert "13 simulaciones" in texto


def test_simulate_y_report(monkeypatch, tmp_path: Path):
    env = {
        "IRLAB_TELEMETRIA": tmp_path / "t.jsonl",
        "IRLAB_CORRIDAS": tmp_path / "c.jsonl",
        "IRLAB_ALERTAS": tmp_path / "a.json",
        "IRLAB_SITIO": tmp_path / "site",
        "IRLAB_ESTADO": tmp_path / "estado",
    }
    codigo, _ = _correr(["simulate", "persistencia_cron"], monkeypatch, env)
    assert codigo == 0
    codigo, _ = _correr(["report", "--sitio", str(tmp_path / "site")], monkeypatch, env)
    assert codigo == 0
    assert (tmp_path / "site" / "index.html").is_file()


def test_simulacion_desconocida(monkeypatch):
    codigo, _ = _correr(["simulate", "no_existe"], monkeypatch)
    assert codigo == 2


def test_convert_sin_reglas(monkeypatch, tmp_path: Path):
    codigo, _ = _correr(["convert", "--reglas", str(tmp_path / "vacio")], monkeypatch)
    assert codigo == 2


def test_convert_con_fixtures(monkeypatch, tmp_path: Path):
    fixtures = Path(__file__).resolve().parent / "fixtures" / "rules"
    codigo, _ = _correr(
        ["convert", "--reglas", str(fixtures), "--destino", str(tmp_path / "out")], monkeypatch
    )
    assert codigo == 0
    assert (tmp_path / "out" / "local_rules.xml").is_file()
