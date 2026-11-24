"""Interfaz de línea de comandos del laboratorio.

Comandos:
  listar            muestra el catálogo de simulaciones y sus reglas
  convert           convierte las reglas Sigma a reglas locales de Wazuh
  simulate <sim>    genera la telemetría de una simulación (o `todas`)
  verify <sim>      comprueba que la alerta esperada apareció en el manager
  revert [sim]      revierte la telemetría de una simulación (o de todo el lab)
  export <dir>      exporta la telemetría al esquema del repo de reglas
  report            genera el informe (Markdown, JSON y sitio)

La orquestación de Docker (`up`, `down`, `load-rules`) vive en el Makefile.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from irlab import __version__, catalogo, reporte, rutas
from irlab import orquestacion as orq


def main(argv: Sequence[str] | None = None, salida: TextIO | None = None) -> int:
    salida = salida or sys.stdout
    args = _parser().parse_args(argv)
    if args.comando is None:
        _parser().print_help(salida)
        return 1
    try:
        return int(args.funcion(args, salida))
    except (KeyError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="irlab", description=__doc__)
    parser.add_argument("--version", action="version", version=f"irlab {__version__}")
    sub = parser.add_subparsers(dest="comando")

    p = sub.add_parser("listar", help="catálogo de simulaciones y reglas")
    p.set_defaults(funcion=cmd_listar)

    p = sub.add_parser("convert", help="convierte las reglas Sigma a reglas de Wazuh")
    p.add_argument("--reglas", type=Path, default=None)
    p.add_argument("--destino", type=Path, default=None)
    p.set_defaults(funcion=cmd_convert)

    p = sub.add_parser("simulate", help="genera la telemetría de una simulación")
    p.add_argument("simulacion", help="nombre de la simulación o 'todas'")
    p.set_defaults(funcion=cmd_simulate)

    p = sub.add_parser("verify", help="comprueba la alerta esperada en el manager")
    p.add_argument("simulacion", help="nombre de la simulación o 'todas'")
    p.add_argument("--alertas", type=Path, default=None)
    p.set_defaults(funcion=cmd_verify)

    p = sub.add_parser("revert", help="revierte la telemetría de una simulación o de todo")
    p.add_argument("simulacion", nargs="?", default=None)
    p.set_defaults(funcion=cmd_revert)

    p = sub.add_parser("export", help="exporta la telemetría al esquema del repo de reglas")
    p.add_argument("destino", type=Path)
    p.set_defaults(funcion=cmd_export)

    p = sub.add_parser("report", help="genera el informe del laboratorio")
    p.add_argument("--md", type=Path, default=None)
    p.add_argument("--json", type=Path, default=None)
    p.add_argument("--sitio", type=Path, default=None)
    p.set_defaults(funcion=cmd_report)
    return parser


def cmd_listar(args: argparse.Namespace, salida: TextIO) -> int:
    for e in catalogo.CATALOGO:
        print(
            f"{e.simulacion:28s} {','.join(e.tecnicas):20s} {e.regla:40s} [{e.nivel}]", file=salida
        )
    print(f"\n{len(catalogo.CATALOGO)} simulaciones", file=salida)
    return 0


def cmd_convert(args: argparse.Namespace, salida: TextIO) -> int:
    origen = args.reglas or rutas.reglas_upstream()
    destino = args.destino or rutas.reglas_wazuh()
    if not origen.exists():
        raise FileNotFoundError(
            f"no están las reglas en {origen}; ejecutá primero "
            f"`make obtener-reglas` (o scripts/obtener-reglas.py)"
        )
    conteo = orq.convertir_reglas(origen, destino)
    print(
        f"Reglas Wazuh generadas: {conteo['reglas_wazuh']} "
        f"(de {conteo['sigma_base']} base + {conteo['sigma_correlaciones']} "
        f"correlaciones Sigma)",
        file=salida,
    )
    print(f"Escritas en {destino / 'local_rules.xml'}", file=salida)
    return 0


def _simulaciones(nombre: str) -> list[str]:
    if nombre == "todas":
        return catalogo.nombres()
    catalogo.entrada(nombre)
    return [nombre]


def cmd_simulate(args: argparse.Namespace, salida: TextIO) -> int:
    for nombre in _simulaciones(args.simulacion):
        corrida = orq.simular(nombre, rutas.telemetria(), rutas.corridas())
        print(
            f"{nombre:28s} {corrida.eventos:3d} eventos  "
            f"-> {corrida.regla}  (run {corrida.run_id})",
            file=salida,
        )
    return 0


def cmd_verify(args: argparse.Namespace, salida: TextIO) -> int:
    alertas = args.alertas or rutas.alertas()
    pendientes = 0
    for nombre in _simulaciones(args.simulacion):
        res = orq.verificar(nombre, alertas)
        marca = "OK  " if res["detectada"] else "FALTA"
        print(f"{marca} {nombre:28s} {res['regla']:40s} alertas={res['alertas']}", file=salida)
        if not res["detectada"]:
            pendientes += 1
    if pendientes:
        print(f"\n{pendientes} simulación(es) sin alerta detectada", file=salida)
        return 1
    return 0


def cmd_revert(args: argparse.Namespace, salida: TextIO) -> int:
    quitadas = orq.revertir(rutas.telemetria(), rutas.corridas(), args.simulacion)
    alcance = args.simulacion or "todo el laboratorio"
    print(f"Revertido {alcance}: {quitadas} eventos quitados de la telemetría", file=salida)
    return 0


def cmd_export(args: argparse.Namespace, salida: TextIO) -> int:
    conteo = orq.exportar_muestras(rutas.telemetria(), args.destino)
    total = sum(conteo.values())
    print(f"Exportados {total} eventos en {len(conteo)} archivos a {args.destino}", file=salida)
    return 0


def cmd_report(args: argparse.Namespace, salida: TextIO) -> int:
    info = reporte.datos(rutas.corridas(), rutas.alertas())
    md = args.md if args.md is not None else rutas.estado() / "informe.md"
    js = args.json if args.json is not None else rutas.estado() / "informe.json"
    sitio = args.sitio if args.sitio is not None else rutas.sitio()
    reporte.escribir(info, md, js, sitio)
    t = info["totales"]
    print(
        f"Informe generado: {t['detectadas']}/{t['simulaciones']} detectadas, "
        f"{t['corridas']} corridas",
        file=salida,
    )
    print(f"  Markdown: {md}\n  JSON: {js}\n  Sitio: {sitio / 'index.html'}", file=salida)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
