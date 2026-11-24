# ATT&CK T1070.002 / T1070.003 - Indicator Removal: Clear Logs / Clear Command History
"""Borrado de logs del sistema y limpieza del historial de la shell.

Dos eventos: eliminación de /var/log/auth.log y `history -c`. Dispara
`borrado_logs_historial`.
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_auditd
from simulations._registro import registrar


@registrar("borrado_historial")
def generar(reloj: Reloj) -> list[dict]:
    return [
        evento_auditd(
            reloj,
            exe="/usr/bin/rm",
            cmdline="rm -f /var/log/auth.log",
            key="evasion",
            comando="rm",
        ),
        evento_auditd(
            reloj,
            exe="/usr/bin/bash",
            cmdline="history -c",
            key="evasion",
            comando="bash",
        ),
    ]
