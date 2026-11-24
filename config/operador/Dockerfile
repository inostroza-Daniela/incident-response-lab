# Imagen del nodo operador: trae las dependencias del paquete irlab para poder
# correr las simulaciones y la conversión de reglas sin acceso a internet (la red
# del laboratorio es interna). El código se monta como volumen en /lab.
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/irlab
COPY pyproject.toml README.md ./
COPY src ./src
COPY simulations ./simulations
RUN pip install --no-cache-dir .

WORKDIR /lab
