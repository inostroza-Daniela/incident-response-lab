from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import pytest
import simulations

from irlab import PREFIJO_INGESTA, catalogo
from irlab.conversion import (
    ErrorConversion,
    a_xml,
    convertir_directorio,
)
from irlab.simulador_wazuh import evaluar as evaluar_wazuh
from irlab.telemetria import Reloj


def test_convierte_fixtures(reglas_fixture: Path):
    res = convertir_directorio(reglas_fixture)
    assert res.mapa["fixture_exec"]["tipo"] == "base"
    assert res.mapa["fixture_fuerza_bruta"]["tipo"] == "correlacion"
    # fixture_exec: sel (endswith nc/ncat + contains -e) and not filtro(php)
    # -> 2 términos (uno por alternativa de exe) con el filtro negado
    assert len(res.mapa["fixture_exec"]["sids"]) == 1


def test_campos_llevan_prefijo_de_ingesta(reglas_fixture: Path):
    res = convertir_directorio(reglas_fixture)
    xml = a_xml(res.reglas)
    arbol = ET.fromstring(_sin_comentario(xml))
    campos = [f.get("name") for f in arbol.iter("field")]
    assert campos, "no se emitieron campos"
    for nombre in campos:
        assert nombre.startswith(f"{PREFIJO_INGESTA}."), nombre


def test_filtro_negado_se_emite_como_negate(reglas_fixture: Path):
    res = convertir_directorio(reglas_fixture)
    xml = a_xml(res.reglas)
    arbol = ET.fromstring(_sin_comentario(xml))
    negados = [f for f in arbol.iter("field") if f.get("negate") == "yes"]
    assert negados, "el filtro negado no produjo negate=yes"
    assert any("php" in (f.text or "") for f in negados)


def test_correlacion_event_count_tiene_frecuencia(reglas_fixture: Path):
    res = convertir_directorio(reglas_fixture)
    xml = a_xml(res.reglas)
    arbol = ET.fromstring(_sin_comentario(xml))
    sid = str(res.mapa["fixture_fuerza_bruta"]["sids"][0])
    regla = next(r for r in arbol.iter("rule") if r.get("id") == sid)
    # frequency y timeframe son atributos de <rule> en Wazuh, no elementos hijos.
    assert regla.get("frequency") == "5"
    assert regla.get("timeframe") == "120"
    assert regla.findtext("same_field") == f"{PREFIJO_INGESTA}.data.srcip"
    assert regla.find("if_matched_sid") is not None


def test_routing_por_logsource(reglas_fixture: Path):
    res = convertir_directorio(reglas_fixture)
    por_nombre = {}
    for r in res.reglas:
        por_nombre.setdefault(r.descripcion, r)
    # fixture_exec es auditd
    exec_rule = next(
        r
        for r in res.reglas
        if any(
            p.campo == f"{PREFIJO_INGESTA}.decoder.name" and "auditd" in p.regex
            for p in r.predicados
        )
    )
    assert exec_rule


def test_xml_bien_formado(reglas_fixture: Path):
    res = convertir_directorio(reglas_fixture)
    ET.fromstring(_sin_comentario(a_xml(res.reglas)))


def test_tipo_pcre2_en_campos(reglas_fixture: Path):
    res = convertir_directorio(reglas_fixture)
    arbol = ET.fromstring(_sin_comentario(a_xml(res.reglas)))
    for f in arbol.iter("field"):
        assert f.get("type") == "pcre2"


def test_reglas_reales_se_convierten(reglas_reales: Path):
    res = convertir_directorio(reglas_reales)
    # 13 base + 3 correlaciones del repo de detección
    assert len(res.mapa) == 16
    assert sum(1 for v in res.mapa.values() if v["tipo"] == "correlacion") == 3
    ET.fromstring(_sin_comentario(a_xml(res.reglas)))


def test_sids_no_se_repiten(reglas_reales: Path):
    res = convertir_directorio(reglas_reales)
    sids = [r.sid for r in res.reglas]
    assert len(sids) == len(set(sids))


def test_directorio_vacio_falla(tmp_path: Path):
    with pytest.raises(ErrorConversion):
        convertir_directorio(tmp_path)


def test_patrones_pcre2_compilan_en_python(reglas_fixture: Path):
    # Los patrones deben ser válidos (flag (?i) al inicio, no por rama): si re los
    # compila, pcre2 también, y además quedan testeables.
    res = convertir_directorio(reglas_fixture)
    for regla in res.reglas:
        for pred in regla.predicados:
            re.compile(pred.patron())


def test_ninguna_frecuencia_invalida(reglas_fixture: Path):
    # Wazuh solo admite <frequency> de 2 a 9999.
    res = convertir_directorio(reglas_fixture)
    for regla in res.reglas:
        if regla.frecuencia is not None:
            assert 2 <= regla.frecuencia <= 9999


def test_emulador_dispara_correlacion_fixture(reglas_fixture: Path, base_tiempo: datetime):
    from irlab.telemetria import evento_sshd

    res = convertir_directorio(reglas_fixture)
    reloj = Reloj(base=base_tiempo)
    eventos = [
        evento_sshd(
            reloj,
            srcip="203.0.113.9",
            srcport=40000 + i,
            usuario="x",
            exito=False,
            usuario_valido=True,
        )
        for i in range(5)
    ]
    disparadas = evaluar_wazuh(res.reglas, eventos)
    assert "fixture_fallo" in disparadas
    assert "fixture_fuerza_bruta" in disparadas


@pytest.mark.parametrize("entrada", catalogo.CATALOGO, ids=lambda e: e.simulacion)
def test_cada_simulacion_dispara_su_regla_convertida(entrada, base_tiempo, reglas_reales):
    # Red de seguridad del path de conversión: las reglas Wazuh generadas, no solo
    # las Sigma de origen, deben disparar lo que cada simulación produce.
    res = convertir_directorio(reglas_reales)
    eventos = simulations.generador(entrada.simulacion)(Reloj(base=base_tiempo))
    disparadas = evaluar_wazuh(res.reglas, eventos)
    assert entrada.regla in disparadas, (
        f"{entrada.simulacion} no disparó {entrada.regla} en Wazuh; disparadas={sorted(disparadas)}"
    )


def test_ninguna_frecuencia_invalida_en_reglas_reales(reglas_reales: Path):
    res = convertir_directorio(reglas_reales)
    for regla in res.reglas:
        if regla.frecuencia is not None:
            assert 2 <= regla.frecuencia <= 9999


def _sin_comentario(xml: str) -> str:
    return "\n".join(linea for linea in xml.splitlines() if not linea.strip().startswith("<!--"))
