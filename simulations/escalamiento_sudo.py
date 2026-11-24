# ATT&CK T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching
"""Elevación a root por su desde una cuenta de servicio.

La cuenta del servidor web (www-data) ejecuta `su` hacia root: un salto que una
cuenta de servicio no debería dar. Dispara `escalamiento_sudo_su_anomalo`.
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_auth
from simulations._registro import registrar


@registrar("escalamiento_sudo")
def generar(reloj: Reloj) -> list[dict]:
    return [
        evento_auth(
            reloj,
            decoder="su",
            data={"srcuser": "www-data", "dstuser": "root"},
            full_log="su: (to root) www-data on pts/1",
            groups=["pam", "su", "authentication_success"],
        )
    ]
