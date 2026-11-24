# ATT&CK T1053.003 - Scheduled Task/Job: Cron
"""Persistencia por cron: escritura en /etc/cron.d.

Se crea un archivo en /etc/cron.d que ejecutaría una tarea periódica. Dispara
`persistencia_cron`.
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_auditd
from simulations._registro import registrar


@registrar("persistencia_cron")
def generar(reloj: Reloj) -> list[dict]:
    return [
        evento_auditd(
            reloj,
            exe="/usr/bin/tee",
            cmdline="tee /etc/cron.d/soporte-lab",
            ruta="/etc/cron.d/soporte-lab",
            key="cron",
        )
    ]
