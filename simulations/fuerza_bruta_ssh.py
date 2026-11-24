# ATT&CK T1110.001 - Brute Force: Password Guessing
"""Ráfaga de autenticaciones SSH fallidas desde una misma IP de origen.

Dispara la correlación `ssh_fuerza_bruta` (>= 10 fallos en 2 minutos). Doce
fallos consecutivos con medio segundo entre ellos, todos desde la misma IP de
documentación, sin que ninguno tenga éxito.
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_sshd
from simulations._registro import registrar

ORIGEN = "203.0.113.45"
USUARIOS = ("ubuntu", "admin", "root", "dani", "postgres", "git")


@registrar("fuerza_bruta_ssh")
def generar(reloj: Reloj) -> list[dict]:
    eventos = []
    for i in range(12):
        usuario = USUARIOS[i % len(USUARIOS)]
        eventos.append(
            evento_sshd(
                reloj,
                srcip=ORIGEN,
                srcport=42000 + i,
                usuario=usuario,
                exito=False,
                usuario_valido=usuario in ("root", "dani", "postgres"),
            )
        )
    return eventos
