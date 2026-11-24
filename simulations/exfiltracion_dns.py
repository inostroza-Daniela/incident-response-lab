# ATT&CK T1048.003 / T1071.004 - Exfiltration Over Alternative Protocol / DNS
"""Exfiltración por DNS: consulta con un primer label largo y codificado.

El resolver destino es el del laboratorio (10.20.0.53) y el dominio es del lab.
Dispara `exfiltracion_dns`.
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_dns
from simulations._registro import registrar

LABEL = "mf2wk3tlnruwg33on5wg6zdfn5xgoltfmrsw4ylbnruw"


@registrar("exfiltracion_dns")
def generar(reloj: Reloj) -> list[dict]:
    return [
        evento_dns(reloj, consulta=f"{LABEL}.exfil.lab", rrtype="A"),
    ]
