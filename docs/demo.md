# Guión de demo — incident-response-lab

Recorrido paso a paso para **probar el laboratorio** y para **presentarlo** (en una
entrevista o una charla). Pensado para durar ~5 minutos en vivo.

---

## 0. Preparación (una sola vez, antes de la demo)

Conviene hacerlo con tiempo: la primera vez Wazuh tarda unos minutos en bajar
imágenes e inicializar. No dejarlo para el momento de la entrevista.

```bash
cp .env.example .env                 # credenciales solo de laboratorio
python scripts/obtener-reglas.py     # descarga las reglas del repo de detección
make certs                           # certificados internos del stack (una vez)
make up                              # levanta la topología (tarda la 1ª vez)
make load-rules                      # convierte las reglas Sigma y las carga en Wazuh
```

Comprobar que todo está arriba antes de seguir:

```bash
make estado                          # todos los contenedores "Up"
```

Abrir el dashboard en `https://localhost:8443` (usuario `admin`, contraseña del
`.env`) y dejar la pestaña lista.

> Si el dashboard no responde, revisar la nota de red en `docs/conversion-reglas.md`.
> Si una alerta no aparece, confirmar el matching con `wazuh-logtest`.

---

## 1. El pitch de apertura (30 segundos)

> "Este es un laboratorio de respuesta a incidentes como código. Con un comando
> levanta un SIEM —Wazuh— y una máquina monitoreada. Genero actividad sospechosa
> controlada, el SIEM la detecta con reglas Sigma, y cada detección tiene un
> playbook de respuesta. Es el ciclo completo de un SOC:
> **detección, alerta y respuesta documentada.** Y todo corre aislado, sin tocar
> ningún sistema real."

Mostrar el diagrama del README mientras se dice.

---

## 2. Mostrar el catálogo (30 segundos)

```bash
docker compose exec operador python -m irlab listar
```

> "Hay 13 simulaciones, cada una mapeada a una técnica de MITRE ATT&CK: fuerza
> bruta SSH, reverse shell, persistencia por cron, exfiltración por DNS, borrado
> de logs… Cada simulación referencia la regla que debería dispararse."

---

## 3. Lanzar una simulación (1 minuto)

Elegir una vistosa. Recomendada: `reverse_shell` (nivel crítico).

```bash
make simulate SIM=reverse_shell
```

> "Lo importante: esto **no ejecuta un ataque real**. Genera la telemetría —los
> rastros en los logs— que una reverse shell dejaría en la máquina monitoreada,
> acotada a la red del laboratorio. Es seguro y reversible."

---

## 4. Ver la alerta en Wazuh (1 minuto)

Cambiar al dashboard (`https://localhost:8443`) → módulo de alertas / Threat
Hunting. Filtrar por la regla o por el grupo `sigma_reverse_shell`.

> "Acá está la alerta en el SIEM real. Wazuh tomó la telemetría, la evaluó con la
> regla Sigma del repo de detección —convertida automáticamente a formato
> Wazuh— y levantó la alerta con su técnica ATT&CK asociada."

Y desde la terminal, la verificación automatizada:

```bash
make verify SIM=reverse_shell
```

> "Esto confirma de forma automatizable que la alerta esperada efectivamente
> apareció. Es lo que corre en las pruebas."

---

## 5. La respuesta: el playbook (1 minuto)

```bash
cat playbooks/reverse_shell.md
```

(o abrirlo en el editor para que se vea mejor)

> "Y acá está la otra mitad del trabajo de un analista: la respuesta. Cada
> detección tiene su playbook con la estructura de la ANCI —detección, análisis
> y triaje, contención, erradicación, recuperación y lecciones aprendidas—,
> referenciando la regla por su ID. No solo detecto: sé qué hacer cuando salta."

---

## 6. Cierre (30 segundos)

```bash
make report        # genera el informe y el sitio
make revert        # limpia la telemetría y deja el lab como estaba
```

> "El informe resume qué se simuló, qué se detectó y el playbook asociado. Y con
> un comando el laboratorio queda limpio. Todo esto está versionado, con tests y
> CI, y corre igual en un Mac Apple Silicon o en un host amd64."

---

## Preguntas que pueden hacer (y respuestas cortas)

- **¿Por qué telemetría y no ataques reales?** Porque el objetivo es probar la
  *detección* y la *respuesta*, no explotar nada. Así el lab es seguro, repetible
  y publicable, y la corrección se valida contra el motor del repo de detección.
- **¿Por qué Wazuh y no Splunk/Elastic?** Es open source, se usa mucho en SOC
  reales, y tiene manager + indexer + dashboard en un stack que levanta en Docker.
- **¿Cómo llegan las reglas Sigma a Wazuh?** Un conversor propio (`irlab convert`)
  traduce el árbol de condición de pySigma a reglas locales de Wazuh.
- **¿Qué pasa con las correlaciones?** Las de Wazuh (frequency/timeframe) cubren
  event_count directo; value_count y secuencia ordenada son aproximaciones
  documentadas, y la corrección exacta la garantiza el motor del repo de detección.
- **¿Y Windows?** Hoy es Linux-first; Windows/Sysmon está anotado como ampliación.

---

## Si no se puede levantar Docker

Igualmente se puede mostrar el valor sin el stack arriba:

```bash
make test                            # 90+ pruebas en verde
docker compose exec operador python -m irlab convert   # genera las reglas Wazuh
cat reglas-wazuh/local_rules.xml     # el resultado de la conversión
```

Mostrar un playbook, el diagrama de arquitectura y la tabla de simulaciones del
README. El relato es el mismo: detección → alerta → respuesta.
