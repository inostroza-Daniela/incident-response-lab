# ATT&CK T1046 - Network Service Discovery
"""Escaneo de puertos saliente: muchas conexiones sin respuesta.

Veintidós flujos TCP desde el mismo origen interno hacia puertos distintos del
mismo destino, ninguno con respuesta. Cada flujo dispara la regla base
`conexion_saliente_sin_respuesta`; el conjunto dispara la correlación
`escaneo_red_saliente` (>= 20 puertos distintos en 1 minuto).
"""

from __future__ import annotations

from irlab.telemetria import Reloj, evento_flujo
from simulations._registro import registrar

PUERTOS = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
)


@registrar("escaneo_puertos")
def generar(reloj: Reloj) -> list[dict]:
    return [evento_flujo(reloj, dest_port=puerto) for puerto in PUERTOS]
