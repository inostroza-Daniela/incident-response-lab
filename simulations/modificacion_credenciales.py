# ATT&CK T1003.008 / T1098 - OS Credential Dumping: /etc/passwd and /etc/shadow
"""Lectura directa de /etc/shadow fuera de las herramientas de autenticación.

Un `cat` sobre /etc/shadow: volcado de hashes para romperlos offline. Dispara
`modificacion_passwd_shadow` (requiere el watch -p rwa sobre shadow en auditd).
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_auditd
from simulations._registro import registrar


@registrar("modificacion_credenciales")
def generar(reloj: Reloj) -> list[dict]:
    return [
        evento_auditd(
            reloj,
            exe="/usr/bin/cat",
            cmdline="cat /etc/shadow",
            ruta="/etc/shadow",
            key="credenciales",
        )
    ]
