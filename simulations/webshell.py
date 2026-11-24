# ATT&CK T1505.003 - Server Software Component: Web Shell
"""La cuenta del servidor web lanza un proceso de sistema.

www-data ejecutando una shell interactiva es la huella típica de una webshell:
un servidor web sano sirve contenido, no abre shells. Dispara
`webshell_proceso_hijo_servidor_web`.
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_auditd
from simulations._registro import registrar


@registrar("webshell")
def generar(reloj: Reloj) -> list[dict]:
    return [
        evento_auditd(
            reloj,
            exe="/usr/bin/id",
            cmdline="id",
            key="webshell",
            uid="www-data",
            auid="4294967295",
            comando="id",
        )
    ]
