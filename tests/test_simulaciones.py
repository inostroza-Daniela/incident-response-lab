from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
import simulations

from irlab import catalogo
from irlab.telemetria import Reloj


def test_cada_simulacion_genera_eventos(base_tiempo: datetime):
    for entrada in catalogo.CATALOGO:
        eventos = simulations.generador(entrada.simulacion)(Reloj(base=base_tiempo))
        assert eventos, f"{entrada.simulacion} no generó eventos"
        for evento in eventos:
            assert "timestamp" in evento
            assert "data" in evento
            assert evento["decoder"]["name"]


def test_simulaciones_son_reproducibles(base_tiempo: datetime):
    for entrada in catalogo.CATALOGO:
        a = simulations.generador(entrada.simulacion)(Reloj(base=base_tiempo))
        b = simulations.generador(entrada.simulacion)(Reloj(base=base_tiempo))
        assert a == b


def _ips(evento: dict) -> list[str]:
    data = evento.get("data", {})
    salida = [str(data.get(c, "")) for c in ("src_ip", "dest_ip", "srcip", "dstip")]
    return [x for x in salida if x]


def _es_del_lab(ip: str) -> bool:
    # Rango del lab (10.20.0.0/24) o rangos de documentación RFC 5737 usados como
    # origen simulado (no son direcciones enrutables de terceros).
    return ip.startswith("10.20.0.") or ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_telemetria_no_apunta_fuera_del_lab(base_tiempo: datetime):
    for entrada in catalogo.CATALOGO:
        eventos = simulations.generador(entrada.simulacion)(Reloj(base=base_tiempo))
        for evento in eventos:
            for ip in _ips(evento):
                assert _es_del_lab(ip), f"IP externa en {entrada.simulacion}: {ip}"
            cmdline = evento.get("data", {}).get("audit", {}).get("execve", {}).get("cmdline", "")
            if "http://" in cmdline or "https://" in cmdline:
                assert "10.20.0." in cmdline, f"destino externo en {entrada.simulacion}"
            rrname = evento.get("data", {}).get("dns", {}).get("rrname", "")
            if rrname:
                assert rrname.endswith(".lab"), f"dominio externo en {entrada.simulacion}"


@pytest.mark.parametrize("entrada", catalogo.CATALOGO, ids=lambda e: e.simulacion)
def test_telemetria_dispara_la_regla_esperada(
    entrada, base_tiempo, motor_disponible, reglas_reales: Path
):
    from detectionlab.motor import evaluar
    from detectionlab.reglas import cargar_reglas

    coleccion = cargar_reglas(reglas_reales)
    eventos = simulations.generador(entrada.simulacion)(Reloj(base=base_tiempo))
    disparadas = evaluar(coleccion, eventos).nombres_disparados()
    assert entrada.regla in disparadas, (
        f"{entrada.simulacion} no disparó {entrada.regla}; disparadas={disparadas}"
    )
