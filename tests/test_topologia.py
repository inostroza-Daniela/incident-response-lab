from __future__ import annotations

from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[1]


def _compose() -> dict:
    return yaml.safe_load((RAIZ / "docker-compose.yml").read_text(encoding="utf-8"))


def test_imagenes_fijadas_sin_latest():
    compose = _compose()
    for nombre, servicio in compose["services"].items():
        imagen = servicio.get("image")
        if imagen is None:
            assert "build" in servicio, f"{nombre} sin image ni build"
            continue
        assert ":" in imagen, f"{nombre}: imagen sin versión fijada"
        assert not imagen.endswith(":latest"), f"{nombre}: usa latest"


def test_imagenes_wazuh_en_version_con_arm64():
    compose = _compose()
    for nombre, servicio in compose["services"].items():
        imagen = servicio.get("image", "")
        if imagen.startswith("wazuh/") and "certs-generator" not in imagen:
            assert imagen.endswith(":4.14.9"), f"{nombre}: {imagen} no es 4.14.9 (arm64)"


def test_red_del_laboratorio_es_interna():
    compose = _compose()
    assert compose["networks"]["irlab"]["internal"] is True


def test_solo_el_dashboard_publica_puerto_en_loopback():
    compose = _compose()
    for nombre, servicio in compose["services"].items():
        puertos = servicio.get("ports", [])
        if nombre == "wazuh.dashboard":
            assert puertos == ["127.0.0.1:8443:5601"]
        else:
            assert not puertos, f"{nombre} publica puertos: {puertos}"


def test_compose_bien_formado():
    compose = _compose()
    assert "operador" in compose["services"]
    assert "nodo-monitoreado" in compose["services"]
