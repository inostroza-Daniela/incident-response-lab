"""Registro de generadores de telemetría.

Cada simulación es un generador idempotente que, dado un reloj, devuelve la lista
de eventos normalizados que la técnica produciría dentro del laboratorio. Los
generadores no ejecutan acciones ofensivas: reproducen la telemetría que el nodo
monitoreado emitiría, acotada a los recursos del lab y sin tocar nada externo.
"""

from __future__ import annotations

from collections.abc import Callable

from irlab.telemetria import Reloj

Generador = Callable[[Reloj], list[dict]]

_REGISTRO: dict[str, Generador] = {}


def registrar(nombre: str) -> Callable[[Generador], Generador]:
    def decorador(func: Generador) -> Generador:
        if nombre in _REGISTRO:
            raise ValueError(f"simulación duplicada: {nombre}")
        _REGISTRO[nombre] = func
        return func

    return decorador


def generador(nombre: str) -> Generador:
    try:
        return _REGISTRO[nombre]
    except KeyError:
        raise KeyError(f"simulación desconocida: {nombre}") from None


def registradas() -> list[str]:
    return sorted(_REGISTRO)
