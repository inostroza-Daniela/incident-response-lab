from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from irlab import PREFIJO_INGESTA
from irlab import orquestacion as orq


def _lineas(ruta: Path) -> list[dict]:
    return [json.loads(x) for x in ruta.read_text().splitlines() if x.strip()]


def test_simular_escribe_telemetria_envuelta(lab, base_tiempo: datetime):
    corrida = orq.simular("reverse_shell", lab["telemetria"], lab["corridas"], base_tiempo)
    lineas = _lineas(lab["telemetria"])
    assert len(lineas) == corrida.eventos == 1
    assert PREFIJO_INGESTA in lineas[0]
    assert lineas[0]["_sim"] == "reverse_shell"
    assert lineas[0]["_run"] == corrida.run_id


def test_revertir_quita_solo_la_simulacion_indicada(lab, base_tiempo: datetime):
    orq.simular("reverse_shell", lab["telemetria"], lab["corridas"], base_tiempo)
    orq.simular("persistencia_cron", lab["telemetria"], lab["corridas"], base_tiempo)
    quitadas = orq.revertir(lab["telemetria"], lab["corridas"], "reverse_shell")
    assert quitadas == 1
    restantes = _lineas(lab["telemetria"])
    assert all(r["_sim"] == "persistencia_cron" for r in restantes)


def test_revertir_todo(lab, base_tiempo: datetime):
    orq.simular("reverse_shell", lab["telemetria"], lab["corridas"], base_tiempo)
    orq.simular("webshell", lab["telemetria"], lab["corridas"], base_tiempo)
    orq.revertir(lab["telemetria"], lab["corridas"])
    assert _lineas(lab["telemetria"]) == []
    assert orq.leer_corridas(lab["corridas"]) == []


def test_exportar_muestras_usa_esquema_del_repo(lab, base_tiempo: datetime, tmp_path):
    orq.simular("fuerza_bruta_ssh", lab["telemetria"], lab["corridas"], base_tiempo)
    destino = tmp_path / "muestras"
    conteo = orq.exportar_muestras(lab["telemetria"], destino)
    assert conteo["fuerza_bruta_ssh"] == 12
    eventos = _lineas(destino / "fuerza_bruta_ssh.jsonl")
    # esquema del repo de reglas: nivel superior sin envoltorio irlab
    assert PREFIJO_INGESTA not in eventos[0]
    assert eventos[0]["decoder"]["name"] == "sshd"


def test_verificar_detecta_alerta(lab, base_tiempo: datetime):
    lab["alertas"].parent.mkdir(parents=True, exist_ok=True)
    alerta = {
        "timestamp": "2026-11-19T12:00:05.000-0300",
        "rule": {
            "id": "100218",
            "level": 13,
            "description": "[irlab] Reverse shell",
            "groups": ["irlab", "sigma_reverse_shell", "t1059.004"],
        },
    }
    lab["alertas"].write_text(json.dumps(alerta) + "\n")
    res = orq.verificar("reverse_shell", lab["alertas"])
    assert res["detectada"] is True
    assert res["alertas"] == 1
    assert "100218" in res["sids"]


def test_verificar_sin_alertas(lab):
    res = orq.verificar("reverse_shell", lab["alertas"])
    assert res["detectada"] is False


def test_convertir_reglas_escribe_salidas(lab, reglas_reales: Path):
    conteo = orq.convertir_reglas(reglas_reales, lab["reglas_wazuh"])
    assert (lab["reglas_wazuh"] / "local_rules.xml").is_file()
    mapa = json.loads((lab["reglas_wazuh"] / "mapa.json").read_text())
    assert len(mapa) == 16
    assert conteo["sigma_correlaciones"] == 3
