from __future__ import annotations

from pathlib import Path

import pytest

from irlab import catalogo

RAIZ = Path(__file__).resolve().parents[1]
SECCIONES = [
    "## Detección",
    "## Análisis y triaje",
    "## Contención",
    "## Erradicación",
    "## Recuperación",
    "## Lecciones aprendidas",
]


@pytest.mark.parametrize("entrada", catalogo.CATALOGO, ids=lambda e: e.regla)
def test_playbook_tiene_estructura_anci(entrada):
    texto = (RAIZ / "playbooks" / f"{entrada.regla}.md").read_text(encoding="utf-8")
    for seccion in SECCIONES:
        assert seccion in texto, f"falta {seccion} en {entrada.regla}"


@pytest.mark.parametrize("entrada", catalogo.CATALOGO, ids=lambda e: e.regla)
def test_playbook_referencia_la_regla_por_id(entrada):
    texto = (RAIZ / "playbooks" / f"{entrada.regla}.md").read_text(encoding="utf-8")
    assert entrada.regla_id in texto
    assert entrada.regla in texto
    for tecnica in entrada.tecnicas:
        assert tecnica in texto


def test_no_hay_playbooks_huerfanos():
    reglas = {e.regla for e in catalogo.CATALOGO}
    for archivo in (RAIZ / "playbooks").glob("*.md"):
        assert archivo.stem in reglas, f"playbook sin regla: {archivo.name}"
