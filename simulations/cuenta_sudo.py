# ATT&CK T1136.001 / T1098 - Create Account seguido de Account Manipulation
"""Alta de una cuenta local e incorporación a un grupo con sudo.

Dos eventos: creación de la cuenta con useradd y adición al grupo sudo con
usermod. Dispara `cuenta_local_creada_o_agregada_a_sudo`.
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_auditd
from simulations._registro import registrar


@registrar("cuenta_sudo")
def generar(reloj: Reloj) -> list[dict]:
    return [
        evento_auditd(
            reloj,
            exe="/usr/sbin/useradd",
            cmdline="useradd -m -s /bin/bash soporte",
            key="identidad",
        ),
        evento_auditd(
            reloj,
            exe="/usr/sbin/usermod",
            cmdline="usermod -aG sudo soporte",
            key="identidad",
        ),
    ]
