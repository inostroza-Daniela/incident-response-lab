# Conversión de reglas Sigma a Wazuh

Las reglas de detección no se escriben en este repo: se reutilizan del
`detection-engineering-lab` (commit fijado en `scripts/obtener-reglas.py`) y se
convierten a reglas locales de Wazuh con `irlab convert`. La conversión parte del
árbol booleano que pySigma ya deja resuelto —el mismo que evalúa el motor del
repo de reglas— así que no se reimplementa la gramática de Sigma.

## Espacio de nombres `irlab`

El laboratorio ingesta la telemetría envuelta en `{"irlab": <evento>}`. Wazuh
decodifica ese JSON y cada campo del evento canónico `P` queda disponible como
`irlab.P`. El envoltorio evita chocar con los campos reservados que Wazuh asigna a
sus propias alertas (`rule`, `agent`, `manager`, `id`, `timestamp`). Por eso toda
condición de campo se emite como `<field name="irlab.…">`.

## Reglas base

Cada regla Sigma se normaliza a forma normal disyuntiva (OR de términos AND),
porque una regla de Wazuh combina sus condiciones con AND. Cada término produce
una regla Wazuh; todas las reglas de una misma regla Sigma comparten el grupo
`sigma_<nombre>`, que es lo que la verificación busca en `rule.groups`.

| Construcción Sigma | Traducción a Wazuh |
|---|---|
| `campo: valor` | `<field name="irlab.campo" type="pcre2">^valor$</field>` |
| `campo\|contains` | `pcre2` sin anclas |
| `campo\|startswith` / `endswith` | `^valor` / `valor$` |
| `campo\|re` | `pcre2` tal cual |
| lista de valores (OR sobre un campo) | una sola alternancia `(?:a)|(?:b)` |
| `\|all` (AND sobre un campo) | varios `<field>` con el mismo nombre |
| `not <selección>` | `negate="yes"` en los campos (De Morgan hasta las hojas) |
| `campo\|cidr` | prefijo regex para loopback y rangos privados |
| routing por `logsource` | `<field name="irlab.decoder.name">` (+ `event_type` para Suricata) |

Las cadenas Sigma son insensibles a mayúsculas salvo las `cased`; se emite el
prefijo `(?i)` en consecuencia.

## Correlaciones

| Tipo Sigma | Traducción a Wazuh | Nota |
|---|---|---|
| `event_count` (≥N, group-by, ventana) | `if_matched_sid` + `frequency` + `timeframe` + `same_field` | Equivalencia directa. |
| `value_count` (N valores distintos) | `frequency` + `same_field` + `different_field` | Aproximada: Wazuh no cuenta valores distintos de forma nativa. |
| `temporal_ordered` (A → B) | regla sobre B con `if_matched_sid` de A, `same_field` y `timeframe` | Aproximada: Wazuh no modela secuencias ordenadas arbitrarias. |

Las aproximaciones de las correlaciones son el motivo por el que la **corrección
de la detección** se valida contra el motor del repo de reglas (tests
`test_telemetria_dispara_la_regla_esperada`), que sí implementa la semántica
exacta de Sigma. La conversión a Wazuh es la ruta de despliegue en el SIEM; el
motor es la referencia de verdad.

## A verificar en el e2e con Docker

La corrección de la detección se prueba en CI contra el motor del repo de reglas
y contra un emulador del matching de Wazuh (`irlab.simulador_wazuh`), ambos sin
Docker. Dos detalles dependen del runtime real de Wazuh y conviene confirmarlos
con `wazuh-logtest` la primera vez que se levanta el stack:

- **Campos de tipo arreglo** (`irlab.rule.groups`): tres reglas base matchean
  sobre ese arreglo de strings. El emulador coincide por elemento; hay que
  confirmar que Wazuh lo aplana igual. Si no, la alternativa es que esas reglas
  Sigma matcheen sobre un campo string (`full_log`) en vez de `rule.groups`.
- **Claves anidadas profundas** (`irlab.data.audit.execve.cmdline`): confirmar que
  el decoder JSON expone la notación de puntos esperada.

## Identificadores

Los `sid` de Wazuh se asignan de forma determinista a partir de `100100`,
ordenando las reglas por nombre. El mapa `nombre → {id Sigma, sids, tipo}` se
escribe en `reglas-wazuh/mapa.json` al convertir.

## Licencia de las reglas

Las reglas Sigma de origen están bajo Detection Rule License 1.1 (DRL-1.1), no
MIT. Este repo no las versiona: las descarga del repo de detección en tiempo de
build. El código de conversión y del laboratorio es MIT.
