# ATT&CK T1543.002 - Create or Modify System Process: Systemd Service
"""Persistencia por unidad systemd fuera de un gestor de paquetes.

Se escribe una unidad .service en /etc/systemd/system con tee. Dispara
`persistencia_systemd`.
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_auditd
from simulations._registro import registrar


@registrar("persistencia_systemd")
def generar(reloj: Reloj) -> list[dict]:
    return [
        evento_auditd(
            reloj,
            exe="/usr/bin/tee",
            cmdline="tee /etc/systemd/system/soporte-lab.service",
            ruta="/etc/systemd/system/soporte-lab.service",
            key="systemd",
        )
    ]
