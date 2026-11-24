from __future__ import annotations

from pathlib import Path

import simulations

from irlab import catalogo

RAIZ = Path(__file__).resolve().parents[1]


def test_toda_simulacion_del_catalogo_tiene_generador():
    registradas = set(simulations.registradas())
    for entrada in catalogo.CATALOGO:
        assert entrada.simulacion in registradas


def test_todo_generador_esta_en_el_catalogo():
    nombres = {e.simulacion for e in catalogo.CATALOGO}
    for nombre in simulations.registradas():
        assert nombre in nombres


def test_toda_regla_de_alerta_tiene_playbook():
    for entrada in catalogo.CATALOGO:
        playbook = RAIZ / "playbooks" / f"{entrada.regla}.md"
        assert playbook.is_file(), f"falta el playbook de {entrada.regla}"


def test_ids_de_regla_son_unicos():
    ids = [e.regla_id for e in catalogo.CATALOGO]
    assert len(ids) == len(set(ids))


def test_toda_entrada_tiene_tecnica_attack():
    for entrada in catalogo.CATALOGO:
        assert entrada.tecnicas
        for tecnica in entrada.tecnicas:
            assert tecnica.startswith("T")
