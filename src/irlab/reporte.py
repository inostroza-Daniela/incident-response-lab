"""Informe del laboratorio: resumen de simulaciones, reglas y detecciones.

Genera tres salidas desde el catálogo, el registro de corridas y las alertas del
manager: Markdown (para leer en la terminal o en el repo), JSON (para integrar) y
un sitio estático (`site/index.html`) con la tabla de simulaciones.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path

from irlab import __version__, catalogo
from irlab.alertas import leer
from irlab.orquestacion import leer_corridas


def _resumen(corridas_path: Path, alertas_path: Path) -> list[dict]:
    corridas = leer_corridas(corridas_path)
    alertas = leer(alertas_path)
    por_sim_corridas: dict[str, int] = {}
    for c in corridas:
        por_sim_corridas[c.simulacion] = por_sim_corridas.get(c.simulacion, 0) + 1
    detectadas = {a.regla_sigma for a in alertas}
    filas = []
    for e in catalogo.CATALOGO:
        filas.append(
            {
                "simulacion": e.simulacion,
                "tecnicas": list(e.tecnicas),
                "tecnica_nombre": e.tecnica_nombre,
                "regla": e.regla,
                "regla_id": e.regla_id,
                "nivel": e.nivel,
                "playbook": f"playbooks/{e.regla}.md",
                "corridas": por_sim_corridas.get(e.simulacion, 0),
                "detectada": e.regla in detectadas,
            }
        )
    return filas


def datos(corridas_path: Path, alertas_path: Path) -> dict:
    filas = _resumen(corridas_path, alertas_path)
    return {
        "generado": datetime.now(UTC).isoformat(timespec="seconds"),
        "version": __version__,
        "totales": {
            "simulaciones": len(filas),
            "corridas": sum(f["corridas"] for f in filas),
            "detectadas": sum(1 for f in filas if f["detectada"]),
        },
        "simulaciones": filas,
    }


def markdown(info: dict) -> str:
    lineas = [
        "# Informe del laboratorio de respuesta a incidentes",
        "",
        f"Generado: {info['generado']}  ·  versión {info['version']}",
        "",
        (
            f"Simulaciones: {info['totales']['simulaciones']}  ·  "
            f"Corridas: {info['totales']['corridas']}  ·  "
            f"Detectadas: {info['totales']['detectadas']}/{info['totales']['simulaciones']}"
        ),
        "",
        "| Simulación | Técnica ATT&CK | Regla | Nivel | Playbook | Corridas | Detectada |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in info["simulaciones"]:
        tecnicas = ", ".join(f["tecnicas"])
        estado = "sí" if f["detectada"] else "—"
        lineas.append(
            f"| `{f['simulacion']}` | {tecnicas} · {f['tecnica_nombre']} | "
            f"`{f['regla']}` | {f['nivel']} | [playbook]({f['playbook']}) | "
            f"{f['corridas']} | {estado} |"
        )
    return "\n".join(lineas) + "\n"


def sitio_html(info: dict) -> str:
    filas = []
    for f in info["simulaciones"]:
        tecnicas = ", ".join(html.escape(t) for t in f["tecnicas"])
        estado = "sí" if f["detectada"] else "—"
        clase = "ok" if f["detectada"] else "pend"
        filas.append(
            f"<tr><td><code>{html.escape(f['simulacion'])}</code></td>"
            f'<td><span class="tec">{tecnicas}</span><br>{html.escape(f["tecnica_nombre"])}</td>'
            f"<td><code>{html.escape(f['regla'])}</code></td>"
            f'<td class="nivel {html.escape(f["nivel"])}">{html.escape(f["nivel"])}</td>'
            f"<td>{f['corridas']}</td>"
            f'<td class="{clase}">{estado}</td></tr>'
        )
    t = info["totales"]
    return _PLANTILLA.format(
        generado=html.escape(info["generado"]),
        version=html.escape(info["version"]),
        simulaciones=t["simulaciones"],
        corridas=t["corridas"],
        detectadas=t["detectadas"],
        filas="\n".join(filas),
    )


def escribir(
    info: dict, salida_md: Path | None, salida_json: Path | None, salida_sitio: Path | None
) -> None:
    if salida_md is not None:
        salida_md.parent.mkdir(parents=True, exist_ok=True)
        salida_md.write_text(markdown(info), encoding="utf-8")
    if salida_json is not None:
        salida_json.parent.mkdir(parents=True, exist_ok=True)
        salida_json.write_text(
            json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    if salida_sitio is not None:
        salida_sitio.mkdir(parents=True, exist_ok=True)
        (salida_sitio / "index.html").write_text(sitio_html(info), encoding="utf-8")


_PLANTILLA = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>incident-response-lab</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #0d1117; color: #e6edf3; }}
  header {{ padding: 2rem 1.5rem 1rem; border-bottom: 1px solid #30363d; }}
  h1 {{ margin: 0 0 .3rem; font-size: 1.4rem; }}
  .meta {{ color: #8b949e; font-size: .85rem; }}
  .tarjetas {{ display: flex; gap: 1rem; flex-wrap: wrap; padding: 1rem 1.5rem; }}
  .tarjeta {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
             padding: 1rem 1.3rem; min-width: 7rem; }}
  .tarjeta b {{ display: block; font-size: 1.6rem; }}
  table {{ width: calc(100% - 3rem); margin: 0 1.5rem 2rem; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #21262d;
           font-size: .9rem; vertical-align: top; }}
  th {{ color: #8b949e; font-weight: 600; }}
  code {{ background: #161b22; padding: .1rem .35rem; border-radius: 4px; font-size: .85em; }}
  .tec {{ color: #58a6ff; }}
  .nivel {{ font-weight: 600; }}
  .nivel.critical {{ color: #f85149; }}
  .nivel.high {{ color: #db6d28; }}
  .nivel.medium {{ color: #d29922; }}
  .ok {{ color: #3fb950; font-weight: 600; }}
  .pend {{ color: #8b949e; }}
</style>
</head>
<body>
<header>
  <h1>incident-response-lab</h1>
  <div class="meta">Detección &rarr; alerta &rarr; respuesta documentada
    · generado {generado} · versión {version}</div>
</header>
<section class="tarjetas">
  <div class="tarjeta"><b>{simulaciones}</b>simulaciones</div>
  <div class="tarjeta"><b>{corridas}</b>corridas</div>
  <div class="tarjeta"><b>{detectadas}</b>detectadas</div>
</section>
<table>
  <thead><tr>
    <th>Simulación</th><th>Técnica ATT&amp;CK</th><th>Regla</th>
    <th>Nivel</th><th>Corridas</th><th>Detectada</th>
  </tr></thead>
  <tbody>
{filas}
  </tbody>
</table>
</body>
</html>
"""
