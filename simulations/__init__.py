"""Paquete de simulaciones de telemetría del laboratorio.

Importar este paquete registra todos los generadores. El registro vive en
`_registro` y la orquestación lo consulta con `generador(nombre)`.
"""

from __future__ import annotations

from simulations import (
    borrado_historial,
    cuenta_sudo,
    descarga_ejecucion,
    escalamiento_sudo,
    escaneo_puertos,
    exfiltracion_dns,
    fuerza_bruta_ssh,
    login_tras_rafaga,
    modificacion_credenciales,
    persistencia_cron,
    persistencia_systemd,
    reverse_shell,
    webshell,
)
from simulations._registro import generador, registradas

__all__ = ["generador", "registradas"]

_MODULOS = (
    borrado_historial,
    cuenta_sudo,
    descarga_ejecucion,
    escalamiento_sudo,
    escaneo_puertos,
    exfiltracion_dns,
    fuerza_bruta_ssh,
    login_tras_rafaga,
    modificacion_credenciales,
    persistencia_cron,
    persistencia_systemd,
    reverse_shell,
    webshell,
)
