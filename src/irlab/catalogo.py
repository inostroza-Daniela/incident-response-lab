"""Catálogo que une simulación, regla del repo de detección y playbook.

Cada entrada enlaza una simulación con la regla que debe dispararse (por nombre
e ID estable del detection-engineering-lab), su técnica ATT&CK y el playbook de
respuesta. Es la fuente única que usan la orquestación, el informe y los tests
de consistencia (toda regla de alerta tiene playbook, toda simulación referencia
una regla existente).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Entrada:
    simulacion: str
    regla: str
    regla_id: str
    tecnicas: tuple[str, ...]
    tecnica_nombre: str
    nivel: str
    descripcion: str


CATALOGO: tuple[Entrada, ...] = (
    Entrada(
        "fuerza_bruta_ssh",
        "ssh_fuerza_bruta",
        "9c191180-315f-4a64-9a4e-e58685d11a46",
        ("T1110.001",),
        "Fuerza bruta de contraseñas",
        "medium",
        "Ráfaga de autenticaciones SSH fallidas desde una misma IP.",
    ),
    Entrada(
        "login_tras_rafaga",
        "ssh_login_exitoso_tras_rafaga",
        "ee3a5b04-0680-4e8b-ac58-9faf9aa7308d",
        ("T1110.001", "T1078"),
        "Fuerza bruta y cuentas válidas",
        "high",
        "Login SSH exitoso dentro de la ventana posterior a una ráfaga de fallos.",
    ),
    Entrada(
        "cuenta_sudo",
        "cuenta_local_creada_o_agregada_a_sudo",
        "ea7d86be-f211-40c4-b91b-c502128792e3",
        ("T1136.001", "T1098"),
        "Creación de cuenta y manipulación de acceso",
        "high",
        "Alta de cuenta local y/o incorporación a un grupo con sudo.",
    ),
    Entrada(
        "escalamiento_sudo",
        "escalamiento_sudo_su_anomalo",
        "636965d1-130a-4890-b42c-11678501d5a7",
        ("T1548.003",),
        "Abuso de sudo/su",
        "medium",
        "Apertura de shell root por sudo o su desde una cuenta de servicio.",
    ),
    Entrada(
        "modificacion_credenciales",
        "modificacion_passwd_shadow",
        "b0ba4bb6-e170-4b63-8cd5-28b3e489f635",
        ("T1003.008", "T1098"),
        "Volcado de credenciales en disco",
        "high",
        "Lectura de /etc/shadow o escritura directa de /etc/passwd fuera de herramientas.",
    ),
    Entrada(
        "persistencia_cron",
        "persistencia_cron",
        "c060f6fb-c45e-4827-806f-166691d83958",
        ("T1053.003",),
        "Tarea programada (cron)",
        "medium",
        "Escritura en un directorio o archivo de cron del sistema.",
    ),
    Entrada(
        "persistencia_systemd",
        "persistencia_systemd",
        "0bd028cb-d6d3-4bce-9ae5-74d0cdf61f68",
        ("T1543.002",),
        "Servicio del sistema (systemd)",
        "medium",
        "Creación de una unidad systemd fuera de un gestor de paquetes.",
    ),
    Entrada(
        "webshell",
        "webshell_proceso_hijo_servidor_web",
        "5a4684f6-32e6-4f40-97b9-c4fb456459b7",
        ("T1505.003",),
        "Webshell",
        "high",
        "La cuenta del servidor web lanza un proceso de sistema.",
    ),
    Entrada(
        "reverse_shell",
        "reverse_shell",
        "b0ddbaa6-a2b7-468c-8959-84f96267bb99",
        ("T1059.004", "T1095"),
        "Shell reversa",
        "critical",
        "Línea de comando con un patrón de shell reversa hacia el operador del lab.",
    ),
    Entrada(
        "descarga_ejecucion",
        "descarga_y_ejecucion",
        "e4ee2dcf-633b-4f68-8b80-428f9ba2d320",
        ("T1105", "T1059.004"),
        "Descarga y ejecución",
        "high",
        "Descarga de un recurso del lab y ejecución inmediata.",
    ),
    Entrada(
        "exfiltracion_dns",
        "exfiltracion_dns",
        "2c5285ac-3bb6-4c60-a1b7-eac644e3b1cc",
        ("T1048.003", "T1071.004"),
        "Exfiltración por canal alternativo (DNS)",
        "high",
        "Consulta DNS con label largo y codificado hacia el resolver del lab.",
    ),
    Entrada(
        "borrado_historial",
        "borrado_logs_historial",
        "5c70de3c-2734-4b96-84ec-239f70c97400",
        ("T1070.002", "T1070.003"),
        "Borrado de indicadores",
        "high",
        "Eliminación de logs del sistema o del historial de la shell.",
    ),
    Entrada(
        "escaneo_puertos",
        "escaneo_red_saliente",
        "fd72cbc3-d895-4d43-8841-9f2b9411d91f",
        ("T1046",),
        "Descubrimiento de servicios de red",
        "high",
        "Un origen interno toca muchos puertos sin respuesta en poco tiempo.",
    ),
)

_POR_SIMULACION = {e.simulacion: e for e in CATALOGO}
_POR_REGLA = {e.regla: e for e in CATALOGO}


def entrada(simulacion: str) -> Entrada:
    try:
        return _POR_SIMULACION[simulacion]
    except KeyError:
        raise KeyError(f"simulación desconocida: {simulacion}") from None


def nombres() -> list[str]:
    return [e.simulacion for e in CATALOGO]


def por_regla(regla: str) -> Entrada:
    return _POR_REGLA[regla]
