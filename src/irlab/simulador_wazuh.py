"""Emulador liviano del matching de Wazuh sobre las reglas convertidas.

Reproduce cómo Wazuh evaluaría las reglas locales (`ReglaWazuh`) contra la
telemetría del laboratorio: envuelve cada evento en `{"irlab": <evento>}`, aplana
las claves a notación de puntos (como hace el decoder JSON de Wazuh para un
`localfile`), evalúa los campos `pcre2` (con AND entre campos, `negate`, y
coincidencia por elemento en los arreglos) y resuelve las correlaciones
(`frequency`/`timeframe`/`same_field`/`different_field`, y la secuencia ordenada
con `if_matched_sid` + `if_sid`).

No sustituye al Wazuh real —algunos detalles de runtime hay que verificarlos con
`wazuh-logtest` en el e2e— pero permite probar en CI, sin Docker, que las reglas
convertidas disparan lo que deben. Es la red de seguridad del path de conversión.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from irlab import PREFIJO_INGESTA
from irlab.conversion import Predicado, ReglaWazuh

Campos = dict[str, Any]
Disparo = tuple[float, Campos]


def _aplanar(obj: Any, prefijo: str, destino: Campos) -> None:
    if isinstance(obj, dict):
        for clave, valor in obj.items():
            _aplanar(valor, f"{prefijo}.{clave}" if prefijo else clave, destino)
    else:
        destino[prefijo] = obj


def _campos(evento: dict) -> Campos:
    destino: Campos = {}
    _aplanar({PREFIJO_INGESTA: evento}, "", destino)
    return destino


def _instante(evento: dict) -> float:
    try:
        return datetime.fromisoformat(evento["timestamp"]).timestamp()
    except (KeyError, ValueError):
        return 0.0


def _coincide_predicado(campos: Campos, pred: Predicado) -> bool:
    valor = campos.get(pred.campo)
    if valor is None:
        coincide = False
    else:
        patron = re.compile(pred.patron())
        candidatos = valor if isinstance(valor, list) else [valor]
        coincide = any(patron.search(str(c)) for c in candidatos)
    return not coincide if pred.negado else coincide


def _coincide_regla(campos: Campos, regla: ReglaWazuh) -> bool:
    return bool(regla.predicados) and all(_coincide_predicado(campos, p) for p in regla.predicados)


def _sigma(regla: ReglaWazuh) -> str:
    for grupo in regla.grupos:
        if grupo.startswith("sigma_"):
            return grupo[len("sigma_") :]
    return ""


def evaluar(reglas: list[ReglaWazuh], eventos: list[dict]) -> set[str]:
    """Nombres de reglas Sigma (etiqueta `sigma_<nombre>`) que dispararían."""
    secuencia = sorted(((_instante(e), _campos(e)) for e in eventos), key=lambda x: x[0])
    disparos: dict[int, list[Disparo]] = {}
    nombres: set[str] = set()

    for regla in reglas:
        if regla.predicados:
            propios = [(ts, c) for ts, c in secuencia if _coincide_regla(c, regla)]
        else:
            propios = _correlacionar(regla, disparos)
        disparos[regla.sid] = propios
        if propios:
            nombres.add(_sigma(regla))
    return nombres


def _correlacionar(regla: ReglaWazuh, disparos: dict[int, list[Disparo]]) -> list[Disparo]:
    base = disparos.get(regla.if_matched_sid or -1, [])
    ventana = regla.timeframe or 0
    if regla.different_field is not None:
        return _value_count(base, regla, ventana)
    if regla.frecuencia is not None:
        return _event_count(base, regla, ventana)
    return _temporal(regla, disparos, ventana)


def _grupo(campos: Campos, campo: str | None) -> Any:
    return campos.get(campo) if campo else None


def _event_count(base: list[Disparo], regla: ReglaWazuh, ventana: float) -> list[Disparo]:
    umbral = regla.frecuencia or 0
    salida: list[Disparo] = []
    por_grupo: dict[Any, list[Disparo]] = {}
    for ts, campos in base:
        por_grupo.setdefault(_grupo(campos, regla.same_field), []).append((ts, campos))
    for eventos in por_grupo.values():
        for i, (ts, campos) in enumerate(eventos):
            dentro = [e for e in eventos[: i + 1] if ts - e[0] <= ventana]
            if len(dentro) >= umbral:
                salida.append((ts, campos))
                break
    return salida


def _value_count(base: list[Disparo], regla: ReglaWazuh, ventana: float) -> list[Disparo]:
    umbral = regla.frecuencia or 0
    salida: list[Disparo] = []
    por_grupo: dict[Any, list[Disparo]] = {}
    for ts, campos in base:
        por_grupo.setdefault(_grupo(campos, regla.same_field), []).append((ts, campos))
    for eventos in por_grupo.values():
        for i, (ts, campos) in enumerate(eventos):
            distintos = {
                _grupo(e[1], regla.different_field)
                for e in eventos[: i + 1]
                if ts - e[0] <= ventana
            }
            if len(distintos) >= umbral:
                salida.append((ts, campos))
                break
    return salida


def _temporal(
    regla: ReglaWazuh, disparos: dict[int, list[Disparo]], ventana: float
) -> list[Disparo]:
    previos = disparos.get(regla.if_matched_sid or -1, [])
    posteriores = disparos.get(regla.if_sid or -1, [])
    salida: list[Disparo] = []
    for ts_b, campos_b in posteriores:
        grupo_b = _grupo(campos_b, regla.same_field)
        if any(
            _grupo(c_a, regla.same_field) == grupo_b and 0 <= ts_b - ts_a <= ventana
            for ts_a, c_a in previos
        ):
            salida.append((ts_b, campos_b))
    return salida
