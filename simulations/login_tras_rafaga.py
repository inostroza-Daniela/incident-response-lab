# ATT&CK T1110.001 / T1078 - Brute Force seguido de Valid Accounts
"""Login SSH exitoso dentro de la ventana posterior a una ráfaga de fallos.

Reproduce una ráfaga de fallos desde una IP y, pocos segundos después, un login
exitoso desde la misma IP. Dispara la correlación `ssh_login_exitoso_tras_rafaga`
(ráfaga + éxito, mismo origen, dentro de 10 minutos).
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_sshd
from simulations._registro import registrar

ORIGEN = "203.0.113.45"


@registrar("login_tras_rafaga")
def generar(reloj: Reloj) -> list[dict]:
    eventos = [
        evento_sshd(
            reloj, srcip=ORIGEN, srcport=43000 + i, usuario="dani", exito=False, usuario_valido=True
        )
        for i in range(12)
    ]
    eventos.append(evento_sshd(reloj, srcip=ORIGEN, srcport=43100, usuario="dani", exito=True))
    return eventos
