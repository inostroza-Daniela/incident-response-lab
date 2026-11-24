"""Construcción de telemetría en el esquema de alertas de Wazuh.

Los eventos que producen las simulaciones tienen la misma forma que las alertas
de Wazuh (`/var/log/alerts/alerts.json`) y que las muestras del
detection-engineering-lab: campos de nivel superior `timestamp`, `agent`,
`rule`, `decoder`, `data` y `full_log`. Esa compatibilidad es deliberada: los
logs que genera este laboratorio entran en los `samples/` del repo de reglas
sin conversión, y el motor del repo de reglas los evalúa tal cual.

Ningún valor apunta fuera de la red del laboratorio. Las direcciones de origen
simulado usan rangos de documentación (RFC 5737) y los destinos son los nodos
internos del lab.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

ZONA_LAB = timezone(timedelta(hours=-3))

AGENTE_MONITOREADO = {"id": "001", "name": "nodo-monitoreado", "ip": "10.20.0.21"}
MANAGER = {"name": "wazuh.manager"}

RED_OPERADOR = "10.20.0.10"
RED_MONITOREADO = "10.20.0.21"


@dataclass
class Reloj:
    """Asigna marcas de tiempo e identificadores crecientes a los eventos.

    Con una base fija los eventos son reproducibles, lo que permite probar las
    simulaciones sin depender de la hora de ejecución.
    """

    base: datetime
    _paso: int = field(default=0, init=False)

    def siguiente(self, salto_segundos: float = 1.0) -> tuple[str, str]:
        instante = self.base + timedelta(seconds=self._paso * salto_segundos)
        self._paso += 1
        marca = instante.astimezone(ZONA_LAB).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        desfase = instante.astimezone(ZONA_LAB).strftime("%z")
        epoch = instante.timestamp()
        ident = f"{epoch:.3f}".replace(".", "") + f"{self._paso:03d}"[-3:]
        return f"{marca}{desfase}", ident


def _envoltorio(
    decoder: str,
    data: dict,
    full_log: str,
    location: str,
    reloj: Reloj,
    rule: dict | None = None,
    agent: dict | None = None,
) -> dict:
    timestamp, ident = reloj.siguiente()
    evento = {
        "timestamp": timestamp,
        "agent": agent or AGENTE_MONITOREADO,
        "manager": MANAGER,
        "id": ident,
        "decoder": {"name": decoder},
        "data": data,
        "full_log": full_log,
        "location": location,
    }
    if rule is not None:
        evento["rule"] = rule
    return evento


def evento_sshd(
    reloj: Reloj,
    *,
    srcip: str,
    srcport: int,
    usuario: str,
    exito: bool,
    usuario_valido: bool = True,
) -> dict:
    """Evento de autenticación SSH (éxito, fallo o usuario inexistente)."""
    if exito:
        groups = ["syslog", "sshd", "authentication_success"]
        descripcion = "sshd: authentication success."
        full_log = f"sshd[2001]: Accepted password for {usuario} from {srcip} port {srcport} ssh2"
        data = {"srcip": srcip, "srcport": str(srcport), "dstuser": usuario}
    elif usuario_valido:
        groups = ["syslog", "sshd", "authentication_failed"]
        descripcion = "sshd: authentication failed."
        full_log = f"sshd[2001]: Failed password for {usuario} from {srcip} port {srcport} ssh2"
        data = {"srcip": srcip, "srcport": str(srcport), "dstuser": usuario}
    else:
        groups = ["syslog", "sshd", "invalid_login", "authentication_failed"]
        descripcion = "sshd: Attempt to login using a non-existent user"
        full_log = f"sshd[2001]: Invalid user {usuario} from {srcip} port {srcport}"
        data = {"srcip": srcip, "srcport": str(srcport), "srcuser": usuario}
    rule = {"description": descripcion, "groups": groups}
    return _envoltorio("sshd", data, full_log, "/var/log/auth.log", reloj, rule=rule)


def evento_auth(
    reloj: Reloj, *, decoder: str, data: dict, full_log: str, groups: Iterable[str] | None = None
) -> dict:
    """Evento de sudo o su (decoder `sudo` / `su`)."""
    rule = {
        "description": f"{decoder}: evento de autenticación.",
        "groups": list(groups) if groups else [decoder],
    }
    return _envoltorio(decoder, data, full_log, "/var/log/auth.log", reloj, rule=rule)


def evento_auditd(
    reloj: Reloj,
    *,
    exe: str,
    cmdline: str,
    key: str,
    ruta: str | None = None,
    uid: str = "0",
    auid: str = "1000",
    euid: str = "0",
    exito: bool = True,
    comando: str | None = None,
) -> dict:
    """Evento de auditd (registro SYSCALL + EXECVE + PATH agregado por Wazuh).

    ``cmdline`` se incluye ya resuelto en ``data.audit.execve.cmdline``. El motor
    del repo de reglas respeta ese campo si viene presente, y Wazuh lo expone
    directo para las reglas convertidas; así no hace falta reconstruirlo desde
    los argumentos hexadecimales en la ruta de detección del laboratorio.
    """
    comando = comando or exe.rsplit("/", 1)[-1]
    audit = {
        "type": "SYSCALL",
        "arch": "aarch64",
        "success": "yes" if exito else "no",
        "exe": exe,
        "command": comando,
        "key": key,
        "uid": uid,
        "auid": auid,
        "euid": euid,
        "cwd": "/root",
        "execve": {"cmdline": cmdline},
    }
    if ruta is not None:
        audit["file"] = {"name": ruta}
    full_log = f'type=SYSCALL success={"yes" if exito else "no"} exe="{exe}" key="{key}"'
    return _envoltorio("auditd", {"audit": audit}, full_log, "/var/log/audit/audit.log", reloj)


def evento_dns(
    reloj: Reloj, *, consulta: str, rrtype: str = "A", src_ip: str = RED_MONITOREADO
) -> dict:
    """Evento DNS de Suricata (decoder json, event_type dns)."""
    data = {
        "event_type": "dns",
        "src_ip": src_ip,
        "dest_ip": "10.20.0.53",
        "proto": "UDP",
        "dns": {"type": "query", "rrname": consulta, "rrtype": rrtype},
    }
    full_log = f'{{"event_type":"dns","dns":{{"rrname":"{consulta}","rrtype":"{rrtype}"}}}}'
    return _envoltorio("json", data, full_log, "/var/log/suricata/eve.json", reloj)


def evento_flujo(
    reloj: Reloj, *, dest_port: int, src_ip: str = RED_MONITOREADO, dest_ip: str = "10.20.0.60"
) -> dict:
    """Evento de flujo TCP de Suricata sin respuesta (SYN sin retorno)."""
    data = {
        "event_type": "flow",
        "proto": "TCP",
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "flow": {"pkts_toserver": 1, "pkts_toclient": 0, "state": "new", "reason": "timeout"},
    }
    full_log = f'{{"event_type":"flow","dest_port":{dest_port},"flow":{{"pkts_toclient":0}}}}'
    return _envoltorio("json", data, full_log, "/var/log/suricata/eve.json", reloj)
