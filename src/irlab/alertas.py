"""Lectura de las alertas que produce el manager de Wazuh.

La verificación lee el `alerts.json` del manager (montado como volumen) y busca
la alerta de la regla convertida que cada simulación debe gatillar. Cada regla
convertida lleva en su grupo la etiqueta `sigma_<nombre>`, así que una detección
se reconoce por esa etiqueta en `rule.groups`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class Alerta:
    regla_sigma: str
    sid: str
    descripcion: str
    nivel: int
    timestamp: str
    crudo: dict[str, Any]


ETIQUETA = "sigma_"


def _grupos(alerta: dict[str, Any]) -> list[str]:
    grupos = alerta.get("rule", {}).get("groups", [])
    return grupos if isinstance(grupos, list) else []


def regla_sigma(alerta: dict[str, Any]) -> str | None:
    for grupo in _grupos(alerta):
        if grupo.startswith(ETIQUETA):
            return grupo[len(ETIQUETA) :]
    return None


def leer(ruta: Path) -> list[Alerta]:
    if not ruta.exists():
        return []
    alertas: list[Alerta] = []
    for fila in ruta.read_text(encoding="utf-8").splitlines():
        texto = fila.strip()
        if not texto:
            continue
        try:
            cruda = json.loads(texto)
        except json.JSONDecodeError:
            continue
        nombre = regla_sigma(cruda)
        if nombre is None:
            continue
        regla = cruda.get("rule", {})
        alertas.append(
            Alerta(
                regla_sigma=nombre,
                sid=str(regla.get("id", "")),
                descripcion=regla.get("description", ""),
                nivel=int(regla.get("level", 0)),
                timestamp=cruda.get("timestamp", ""),
                crudo=cruda,
            )
        )
    return alertas


def buscar(ruta: Path, regla: str, desde: datetime | None = None) -> list[Alerta]:
    encontradas = [a for a in leer(ruta) if a.regla_sigma == regla]
    if desde is not None:
        encontradas = [a for a in encontradas if _posterior(a.timestamp, desde)]
    return encontradas


def _posterior(marca: str, desde: datetime) -> bool:
    try:
        instante = datetime.fromisoformat(marca)
    except ValueError:
        return True
    if instante.tzinfo is None:
        return instante >= desde.replace(tzinfo=None)
    if desde.tzinfo is None:
        return instante.timestamp() >= desde.timestamp()
    return instante >= desde
