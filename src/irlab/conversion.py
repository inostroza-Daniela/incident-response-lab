"""Conversión de reglas Sigma del repo de detección a reglas locales de Wazuh.

El laboratorio ingesta la telemetría envuelta en el espacio de nombres `irlab`
(ver `irlab.PREFIJO_INGESTA`), de modo que cada campo del evento canónico `P`
queda disponible en Wazuh como `irlab.P`. El conversor recorre el árbol booleano
que pySigma ya dejó resuelto (el mismo que evalúa el motor del repo de reglas),
lo normaliza a forma normal disyuntiva (OR de términos AND) y emite una regla
Wazuh por término, porque una regla de Wazuh combina sus condiciones con AND.

Las correlaciones Sigma se traducen a reglas compuestas de Wazuh
(`if_matched_sid` + `frequency` + `timeframe` + `same_field`/`different_field`).
Las equivalencias no son exactas al 100 % (Wazuh no tiene conteo de valores
distintos nativo ni correlación ordenada arbitraria); las aproximaciones están
documentadas en `docs/conversion-reglas.md` y la corrección de la detección en sí
la garantizan las pruebas contra el motor del repo de reglas.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from xml.dom import minidom

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaExpansion,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from irlab import PREFIJO_INGESTA

SID_BASE = 100100
NIVEL_WAZUH = {
    "informational": 3,
    "low": 5,
    "medium": 7,
    "high": 10,
    "critical": 13,
}


class ErrorConversion(ValueError):
    pass


@dataclass
class Predicado:
    campo: str
    regex: str
    negado: bool = False
    insensible: bool = False

    def patron(self) -> str:
        """Patrón pcre2 final, con `(?i)` al frente si es insensible a mayúsculas.

        El flag va al inicio (no embebido por rama) para que sea válido tanto en
        PCRE2 (Wazuh) como en el módulo `re` de Python (tests)."""
        return f"(?i){self.regex}" if self.insensible else self.regex


@dataclass
class ReglaWazuh:
    sid: int
    nivel: int
    descripcion: str
    grupos: list[str]
    tecnicas: list[str]
    predicados: list[Predicado] = field(default_factory=list)
    if_matched_sid: int | None = None
    frecuencia: int | None = None
    timeframe: int | None = None
    same_field: str | None = None
    different_field: str | None = None
    if_sid: int | None = None


# --- Normalización del árbol a DNF -----------------------------------------


def _dnf(nodo: object) -> list[list[Predicado]]:
    """Devuelve una lista de términos; cada término es un AND de predicados."""
    if isinstance(nodo, ConditionAND):
        terminos: list[list[Predicado]] = [[]]
        for hijo in nodo.args:
            nuevos: list[list[Predicado]] = []
            for parcial in terminos:
                for sufijo in _dnf(hijo):
                    nuevos.append(parcial + sufijo)
            terminos = nuevos
        return terminos
    if isinstance(nodo, ConditionOR):
        hijos = [_dnf(hijo) for hijo in nodo.args]
        combinado = _combinar_or_mismo_campo(hijos)
        if combinado is not None:
            return combinado
        terminos = []
        for ramas in hijos:
            terminos.extend(ramas)
        return terminos
    if isinstance(nodo, ConditionNOT):
        return _negar(nodo.args[0])
    if isinstance(nodo, ConditionFieldEqualsValueExpression):
        return [[_predicado(nodo.field, nodo.value, negado=False)]]
    if isinstance(nodo, ConditionValueExpression):
        raise ErrorConversion("las búsquedas de texto libre no se convierten a Wazuh")
    raise ErrorConversion(f"nodo no soportado: {type(nodo).__name__}")


def _combinar_or_mismo_campo(
    hijos: list[list[list[Predicado]]],
) -> list[list[Predicado]] | None:
    """Si todas las ramas de un OR son un único predicado sobre el mismo campo,
    las fusiona en una sola alternancia pcre2 para no multiplicar términos."""
    predicados = []
    for ramas in hijos:
        if len(ramas) != 1 or len(ramas[0]) != 1 or ramas[0][0].negado:
            return None
        predicados.append(ramas[0][0])
    campos = {p.campo for p in predicados}
    sensibilidades = {p.insensible for p in predicados}
    if len(campos) != 1 or len(sensibilidades) != 1:
        return None
    patron = "|".join(f"(?:{p.regex})" for p in predicados)
    return [[Predicado(predicados[0].campo, patron, insensible=predicados[0].insensible)]]


def _negar(nodo: object) -> list[list[Predicado]]:
    """Aplica De Morgan para empujar la negación hasta las hojas."""
    if isinstance(nodo, ConditionNOT):
        return _dnf(nodo.args[0])
    if isinstance(nodo, ConditionAND):
        # not(A and B) = (not A) or (not B)
        terminos: list[list[Predicado]] = []
        for hijo in nodo.args:
            terminos.extend(_negar(hijo))
        return terminos
    if isinstance(nodo, ConditionOR):
        # not(A or B) = (not A) and (not B)
        terminos = [[]]
        for hijo in nodo.args:
            nuevos: list[list[Predicado]] = []
            for parcial in terminos:
                for sufijo in _negar(hijo):
                    nuevos.append(parcial + sufijo)
            terminos = nuevos
        return terminos
    if isinstance(nodo, ConditionFieldEqualsValueExpression):
        return [[_predicado(nodo.field, nodo.value, negado=True)]]
    raise ErrorConversion(f"negación no soportada sobre: {type(nodo).__name__}")


# --- Traducción de valores Sigma a regex pcre2 -----------------------------


def _predicado(campo: str, valor: object, *, negado: bool) -> Predicado:
    if isinstance(valor, SigmaExpansion):
        # Varios valores enlazados: se resuelven como alternancia en una hoja.
        alternativas = [_regex_valor(v) for v in valor.values]
        cuerpo = "|".join(f"(?:{regex})" for regex, _ in alternativas)
        sensibilidades = {ins for _, ins in alternativas}
        insensible = sensibilidades == {True}
        return Predicado(_campo_wazuh(campo), cuerpo, negado, insensible)
    regex, insensible = _regex_valor(valor)
    return Predicado(_campo_wazuh(campo), regex, negado, insensible)


def _campo_wazuh(campo: str) -> str:
    return f"{PREFIJO_INGESTA}.{campo}"


def _regex_valor(valor: object) -> tuple[str, bool]:
    """Devuelve (regex sin flag, insensible a mayúsculas)."""
    if isinstance(valor, SigmaString):
        cuerpo = "".join(_parte(p) for p in valor.s)
        return f"^{cuerpo}$", not isinstance(valor, SigmaCasedString)
    if isinstance(valor, SigmaNumber):
        return f"^{valor.number}$", False
    if isinstance(valor, SigmaBool):
        return ("^(yes|true|1)$", True) if valor.boolean else ("^(no|false|0)$", True)
    if isinstance(valor, SigmaRegularExpression):
        return str(valor.regexp), SigmaRegularExpressionFlag.IGNORECASE in valor.flags
    if isinstance(valor, SigmaCIDRExpression):
        return _cidr_a_regex(valor.cidr), False
    raise ErrorConversion(f"tipo de valor no soportado: {type(valor).__name__}")


def _parte(parte: object) -> str:
    if parte is SpecialChars.WILDCARD_MULTI:
        return ".*"
    if parte is SpecialChars.WILDCARD_SINGLE:
        return "."
    if isinstance(parte, str):
        return _escapar(parte)
    raise ErrorConversion(f"parte de cadena no soportada: {parte!r}")


_ESPECIALES = set(r".^$*+?()[]{}|\/")


def _escapar(texto: str) -> str:
    return "".join("\\" + c if c in _ESPECIALES else c for c in texto)


def _cidr_a_regex(cidr: str) -> str:
    red = ipaddress.ip_network(cidr, strict=False)
    if red.version == 6:
        if str(red) in ("::1/128", "::1"):
            return "^::1$"
        raise ErrorConversion(f"CIDR IPv6 no soportado en la conversión: {cidr}")
    octetos = cidr.split("/", maxsplit=1)[0].split(".")
    bits = red.prefixlen
    if bits == 8:
        return f"^{octetos[0]}\\."
    if bits == 16:
        return f"^{octetos[0]}\\.{octetos[1]}\\."
    if bits == 12 and octetos[0] == "172":
        return r"^172\.(1[6-9]|2[0-9]|3[01])\."
    if bits == 24:
        return f"^{octetos[0]}\\.{octetos[1]}\\.{octetos[2]}\\."
    raise ErrorConversion(f"prefijo CIDR no soportado en la conversión: {cidr}")


# --- Routing por logsource --------------------------------------------------


def _predicados_fuente(regla: SigmaRule) -> list[Predicado]:
    ls = regla.logsource
    campo_decoder = f"{PREFIJO_INGESTA}.decoder.name"
    campo_evento = f"{PREFIJO_INGESTA}.data.event_type"
    if ls.service == "sshd":
        return [Predicado(campo_decoder, "^sshd$")]
    if ls.service == "sudo":
        return [Predicado(campo_decoder, "^sudo$")]
    if ls.service == "su":
        return [Predicado(campo_decoder, "^su$")]
    if ls.service == "auth":
        return [Predicado(campo_decoder, "^(sshd|sudo|su|pam_unix|pam)$")]
    if ls.service == "auditd":
        return [Predicado(campo_decoder, "^auditd$")]
    if ls.category == "dns_query":
        return [Predicado(campo_decoder, "^json$"), Predicado(campo_evento, "^dns$")]
    if ls.category == "network_connection":
        return [Predicado(campo_decoder, "^json$"), Predicado(campo_evento, "^flow$")]
    raise ErrorConversion(
        f"logsource no soportado: product={ls.product} service={ls.service} category={ls.category}"
    )


# --- Compilación de una colección ------------------------------------------


@dataclass
class ResultadoConversion:
    reglas: list[ReglaWazuh]
    mapa: dict[str, dict]


def convertir(coleccion: SigmaCollection) -> ResultadoConversion:
    base = [r for r in coleccion if isinstance(r, SigmaRule)]
    correlaciones = [r for r in coleccion if isinstance(r, SigmaCorrelationRule)]
    base.sort(key=lambda r: r.name or "")
    correlaciones.sort(key=lambda r: r.name or "")

    reglas: list[ReglaWazuh] = []
    sids_por_nombre: dict[str, list[int]] = {}
    mapa: dict[str, dict] = {}
    sid = SID_BASE

    for regla in base:
        nombre = regla.name or ""
        nivel = NIVEL_WAZUH[regla.level.name.lower()] if regla.level else 7
        tecnicas = _tecnicas(regla)
        terminos = _terminos_base(regla)
        sids: list[int] = []
        for termino in terminos:
            reglas.append(
                ReglaWazuh(
                    sid=sid,
                    nivel=nivel,
                    descripcion=f"[irlab] {regla.title}",
                    grupos=_grupos(nombre, tecnicas),
                    tecnicas=tecnicas,
                    predicados=termino,
                )
            )
            sids.append(sid)
            sid += 1
        sids_por_nombre[nombre] = sids
        mapa[nombre] = {
            "id": str(regla.id) if regla.id else "",
            "sids": sids,
            "tipo": "base",
            "nivel": regla.level.name.lower() if regla.level else "",
        }

    info_corr: dict[str, dict] = {}
    for correlacion in _ordenar_correlaciones(correlaciones):
        nombre = correlacion.name or ""
        nivel = NIVEL_WAZUH[correlacion.level.name.lower()] if correlacion.level else 7
        tecnicas = _tecnicas(correlacion)
        rw = _regla_correlacion(correlacion, sid, nivel, tecnicas, sids_por_nombre, info_corr)
        reglas.append(rw)
        sids_por_nombre[nombre] = [sid]
        mapa[nombre] = {
            "id": str(correlacion.id) if correlacion.id else "",
            "sids": [sid],
            "tipo": "correlacion",
            "nivel": correlacion.level.name.lower() if correlacion.level else "",
        }
        sid += 1

    return ResultadoConversion(reglas=reglas, mapa=mapa)


def _ordenar_correlaciones(
    correlaciones: list[SigmaCorrelationRule],
) -> list[SigmaCorrelationRule]:
    """Ordena las correlaciones para que las referenciadas se emitan primero."""
    pendientes = list(correlaciones)
    nombres = {r.name for r in pendientes}
    ordenadas: list[SigmaCorrelationRule] = []
    emitidas: set[str] = set()
    while pendientes:
        progreso = False
        for regla in list(pendientes):
            refs = {str(r.reference) for r in (regla.rules or [])} & nombres
            if refs <= emitidas:
                ordenadas.append(regla)
                emitidas.add(regla.name or "")
                pendientes.remove(regla)
                progreso = True
        if not progreso:
            nombres_pend = [r.name for r in pendientes]
            raise ErrorConversion(f"ciclo entre correlaciones: {nombres_pend}")
    return ordenadas


def _terminos_base(regla: SigmaRule) -> list[list[Predicado]]:
    fuente = _predicados_fuente(regla)
    terminos: list[list[Predicado]] = []
    for condicion in regla.detection.parsed_condition:
        for termino in _dnf(condicion.parsed):
            terminos.append(fuente + termino)
    return terminos


def _regla_correlacion(
    regla: SigmaCorrelationRule,
    sid: int,
    nivel: int,
    tecnicas: list[str],
    sids_por_nombre: dict[str, list[int]],
    info_corr: dict[str, dict],
) -> ReglaWazuh:
    referencias = [str(r.reference) for r in (regla.rules or [])]
    faltantes = [r for r in referencias if not sids_por_nombre.get(r)]
    if faltantes:
        raise ErrorConversion(f"{regla.name} referencia reglas sin convertir: {faltantes}")
    group_by = [f"{PREFIJO_INGESTA}.{c}" for c in (regla.group_by or [])]
    timeframe = regla.timespan.seconds if regla.timespan else None
    tipo = regla.type.name.lower() if hasattr(regla.type, "name") else str(regla.type)
    condicion = cast(Any, regla.condition)
    rw = ReglaWazuh(
        sid=sid,
        nivel=nivel,
        descripcion=f"[irlab] {regla.title}",
        grupos=_grupos(regla.name or "", tecnicas),
        tecnicas=tecnicas,
        timeframe=timeframe,
    )
    nombre = regla.name or ""
    if tipo == "event_count":
        base = sids_por_nombre[referencias[0]][0]
        rw.if_matched_sid = base
        rw.frecuencia = condicion.count
        rw.same_field = group_by[0] if group_by else None
        info_corr[nombre] = {
            "base_sid": base,
            "frecuencia": condicion.count,
            "same_field": rw.same_field,
        }
    elif tipo == "value_count":
        rw.if_matched_sid = sids_por_nombre[referencias[0]][0]
        rw.frecuencia = condicion.count
        rw.same_field = group_by[0] if group_by else None
        rw.different_field = f"{PREFIJO_INGESTA}.{condicion.fieldref}"
    elif tipo == "temporal_ordered":
        # "Ráfaga y luego éxito": dispara con la última regla de la secuencia
        # (if_sid) exigiendo que la regla base de la primera correlación haya
        # matcheado `frequency` veces antes, mismo group-by, dentro de la ventana.
        # Se apoya en la regla base (no en la correlación) porque Wazuh exige
        # frequency >= 2 junto a if_matched_sid.
        previa = referencias[0]
        rw.if_sid = sids_por_nombre[referencias[-1]][0]
        if previa in info_corr:
            rw.if_matched_sid = info_corr[previa]["base_sid"]
            rw.frecuencia = info_corr[previa]["frecuencia"]
            rw.same_field = info_corr[previa]["same_field"] or (group_by[0] if group_by else None)
        else:
            rw.if_matched_sid = sids_por_nombre[previa][0]
            rw.frecuencia = 2
            rw.same_field = group_by[0] if group_by else None
    else:
        raise ErrorConversion(f"tipo de correlación no soportado: {tipo}")
    if rw.frecuencia is not None and rw.frecuencia < 2:
        rw.frecuencia = 2
    return rw


def _tecnicas(regla: object) -> list[str]:
    salida = []
    for tag in getattr(regla, "tags", []):
        t = str(tag)
        if t.startswith("attack.t"):
            salida.append(t.removeprefix("attack.").upper())
    return salida


def _grupos(nombre: str, tecnicas: list[str]) -> list[str]:
    grupos = ["irlab", f"sigma_{nombre}"]
    grupos.extend(t.lower() for t in tecnicas)
    return grupos


# --- Serialización a XML ----------------------------------------------------


def a_xml(reglas: list[ReglaWazuh]) -> str:
    raiz = ET.Element("group", {"name": "irlab,"})
    for rw in reglas:
        # frequency y timeframe son atributos de <rule> en Wazuh, no hijos.
        atributos_regla = {"id": str(rw.sid), "level": str(rw.nivel)}
        if rw.frecuencia is not None:
            atributos_regla["frequency"] = str(rw.frecuencia)
        if rw.timeframe is not None:
            atributos_regla["timeframe"] = str(rw.timeframe)
        el = ET.SubElement(raiz, "rule", atributos_regla)
        if rw.if_sid is not None:
            ET.SubElement(el, "if_sid").text = str(rw.if_sid)
        if rw.if_matched_sid is not None:
            ET.SubElement(el, "if_matched_sid").text = str(rw.if_matched_sid)
        if rw.same_field is not None:
            ET.SubElement(el, "same_field").text = rw.same_field
        if rw.different_field is not None:
            ET.SubElement(el, "different_field").text = rw.different_field
        for pred in rw.predicados:
            atributos = {"name": pred.campo, "type": "pcre2"}
            if pred.negado:
                atributos["negate"] = "yes"
            ET.SubElement(el, "field", atributos).text = pred.patron()
        ET.SubElement(el, "description").text = rw.descripcion
        for tecnica in rw.tecnicas:
            mitre = ET.SubElement(el, "mitre")
            ET.SubElement(mitre, "id").text = tecnica
        ET.SubElement(el, "group").text = ",".join(rw.grupos) + ","
    crudo = ET.tostring(raiz, encoding="unicode")
    bonito = minidom.parseString(crudo).toprettyxml(indent="  ")
    cuerpo = "\n".join(linea for linea in bonito.splitlines()[1:] if linea.strip())
    cabecera = (
        "<!-- Reglas locales generadas por irlab a partir del "
        "detection-engineering-lab. No editar a mano: se regeneran con "
        "`irlab convert` (o `make load-rules`). -->"
    )
    return f"{cabecera}\n{cuerpo}\n"


def convertir_directorio(directorio: Path) -> ResultadoConversion:
    textos = [f.read_text(encoding="utf-8") for f in sorted(directorio.rglob("*.yml"))]
    if not textos:
        raise ErrorConversion(f"no se encontraron reglas en {directorio}")
    coleccion = SigmaCollection.from_yaml("\n---\n".join(textos))
    return convertir(coleccion)
