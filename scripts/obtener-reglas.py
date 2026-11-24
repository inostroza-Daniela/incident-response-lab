#!/usr/bin/env python3
"""Descarga las reglas Sigma del detection-engineering-lab fijadas a un commit.

Las reglas no se versionan en este repo: se reutilizan del repo de detección. El
commit fijado garantiza que la conversión sea reproducible. Uso:

    python scripts/obtener-reglas.py [--ref COMMIT] [--destino DIR]
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = "https://github.com/inostroza-Daniela/detection-engineering-lab.git"
REF = "aafa11950cbb4bbfb71db61aa2c88a5d4b76657a"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default=REF, help="commit o tag a fijar")
    parser.add_argument("--repo", default=REPO)
    parser.add_argument(
        "--destino", type=Path, default=Path(__file__).resolve().parents[1] / "reglas-upstream"
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        clon = Path(tmp) / "repo"
        _git("clone", "--quiet", args.repo, str(clon))
        _git("-C", str(clon), "checkout", "--quiet", args.ref)
        origen = clon / "rules"
        if not origen.is_dir():
            print(f"error: el repo no tiene carpeta rules/ en {args.ref}", file=sys.stderr)
            return 1
        destino_rules = args.destino / "rules"
        if destino_rules.exists():
            shutil.rmtree(destino_rules)
        destino_rules.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(origen, destino_rules)
        (args.destino / "COMMIT").write_text(args.ref + "\n", encoding="utf-8")

    n = len(list((args.destino / "rules").rglob("*.yml")))
    print(f"Reglas descargadas: {n} en {args.destino / 'rules'} (ref {args.ref[:12]})")
    return 0


def _git(*argumentos: str) -> None:
    subprocess.run(["git", *argumentos], check=True)


if __name__ == "__main__":
    raise SystemExit(main())
