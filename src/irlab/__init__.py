"""incident-response-lab: respuesta a incidentes como código sobre Wazuh."""

__version__ = "0.1.0"

PREFIJO_INGESTA = "irlab"
"""Espacio de nombres bajo el que se ingesta la telemetría del laboratorio en Wazuh.

Cada evento canónico (esquema de alertas de Wazuh, el mismo del
detection-engineering-lab) se envuelve en ``{"irlab": <evento>}`` antes de
escribirse en el archivo que vigila el agente. Así los campos del evento quedan
bajo ``irlab.*`` y no chocan con los campos reservados que Wazuh asigna a sus
propias alertas (``rule``, ``agent``, ``manager``, ``id``, ``timestamp``).
"""
