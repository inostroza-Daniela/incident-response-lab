"""Orquestación de las simulaciones y de la conversión de reglas.

Estas funciones no tocan Docker: operan sobre los archivos de estado del
laboratorio (telemetría, registro de corridas, reglas convertidas) y sobre las
alertas que deja el manager. El `Makefile` se encarga de levantar la topología,
copiar las reglas al manager y reiniciarlo.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import simulations

from irlab import PREFIJO_INGESTA, catalogo
from irlab.alertas import buscar
from irlab.conversion import a_xml, convertir_directorio
from irlab.telemetria import Reloj


@dataclass
class Corrida:
    run_id: str
    simulacion: str
    regla: str
    regla_id: str
    instante: str
    eventos: int


def _asegurar(ruta: Path) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)


def simular(nombre: str, telemetria: Path, corridas: Path, base: datetime | None = None) -> Corrida:
    entrada = catalogo.entrada(nombre)
    base = base or datetime.now(UTC)
    eventos = simulations.generador(nombre)(Reloj(base=base))
    run_id = uuid.uuid4().hex[:12]

    _asegurar(telemetria)
    with telemetria.open("a", encoding="utf-8") as fh:
        for evento in eventos:
            linea = {PREFIJO_INGESTA: evento, "_sim": nombre, "_run": run_id}
            fh.write(json.dumps(linea, ensure_ascii=False) + "\n")

    corrida = Corrida(
        run_id=run_id,
        simulacion=nombre,
        regla=entrada.regla,
        regla_id=entrada.regla_id,
        instante=datetime.now(UTC).isoformat(timespec="seconds"),
        eventos=len(eventos),
    )
    _asegurar(corridas)
    with corridas.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(corrida), ensure_ascii=False) + "\n")
    return corrida


def leer_corridas(corridas: Path) -> list[Corrida]:
    if not corridas.exists():
        return []
    salida = []
    for linea in corridas.read_text(encoding="utf-8").splitlines():
        if linea.strip():
            salida.append(Corrida(**json.loads(linea)))
    return salida


def revertir(telemetria: Path, corridas: Path, nombre: str | None = None) -> int:
    """Elimina de la telemetría y del registro las corridas indicadas.

    Sin `nombre`, revierte todo el laboratorio. Devuelve cuántas líneas de
    telemetría se quitaron. No toca ningún recurso fuera del lab.
    """
    objetivo = {
        c.run_id for c in leer_corridas(corridas) if nombre is None or c.simulacion == nombre
    }
    quitadas = 0
    if telemetria.exists():
        conservadas = []
        for linea in telemetria.read_text(encoding="utf-8").splitlines():
            if not linea.strip():
                continue
            if json.loads(linea).get("_run") in objetivo:
                quitadas += 1
            else:
                conservadas.append(linea)
        telemetria.write_text(
            "\n".join(conservadas) + ("\n" if conservadas else ""), encoding="utf-8"
        )
    if corridas.exists():
        restantes = [c for c in leer_corridas(corridas) if c.run_id not in objetivo]
        corridas.write_text(
            "".join(json.dumps(asdict(c), ensure_ascii=False) + "\n" for c in restantes),
            encoding="utf-8",
        )
    return quitadas


def convertir_reglas(origen: Path, destino: Path) -> dict:
    resultado = convertir_directorio(origen)
    destino.mkdir(parents=True, exist_ok=True)
    (destino / "local_rules.xml").write_text(a_xml(resultado.reglas), encoding="utf-8")
    (destino / "mapa.json").write_text(
        json.dumps(resultado.mapa, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    base = sum(1 for v in resultado.mapa.values() if v["tipo"] == "base")
    corr = sum(1 for v in resultado.mapa.values() if v["tipo"] == "correlacion")
    return {"reglas_wazuh": len(resultado.reglas), "sigma_base": base, "sigma_correlaciones": corr}


def verificar(nombre: str, alertas: Path, desde: datetime | None = None) -> dict:
    entrada = catalogo.entrada(nombre)
    encontradas = buscar(alertas, entrada.regla, desde)
    return {
        "simulacion": nombre,
        "regla": entrada.regla,
        "regla_id": entrada.regla_id,
        "detectada": bool(encontradas),
        "alertas": len(encontradas),
        "sids": sorted({a.sid for a in encontradas}),
    }


def exportar_muestras(telemetria: Path, destino: Path) -> dict:
    """Vuelca la telemetría a `destino/<simulacion>.jsonl` en el esquema del
    repo de reglas, sin el envoltorio del laboratorio. Alimenta sus `samples/`."""
    if not telemetria.exists():
        return {}
    por_sim: dict[str, list[str]] = {}
    for linea in telemetria.read_text(encoding="utf-8").splitlines():
        if not linea.strip():
            continue
        registro = json.loads(linea)
        evento = registro.get(PREFIJO_INGESTA)
        sim = registro.get("_sim", "sin-nombre")
        if evento is not None:
            por_sim.setdefault(sim, []).append(json.dumps(evento, ensure_ascii=False))
    destino.mkdir(parents=True, exist_ok=True)
    conteo = {}
    for sim, lineas in por_sim.items():
        (destino / f"{sim}.jsonl").write_text("\n".join(lineas) + "\n", encoding="utf-8")
        conteo[sim] = len(lineas)
    return conteo
