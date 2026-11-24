COMPOSE ?= docker compose
EXEC_OPERADOR = $(COMPOSE) exec -T operador python -m irlab

.DEFAULT_GOAL := ayuda

.PHONY: ayuda
ayuda: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*## .*$$' $(MAKEFILE_LIST) \
	 | awk 'BEGIN {FS=":.*## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- Preparación ------------------------------------------------------------

.PHONY: obtener-reglas
obtener-reglas: ## Descarga las reglas Sigma del repo de detección (commit fijado)
	python3 scripts/obtener-reglas.py

.PHONY: certs
certs: ## Genera los certificados internos del stack con OpenSSL (una sola vez)
	bash scripts/generar-certs.sh

# --- Ciclo de vida de la topología -----------------------------------------

.PHONY: up
up: ## Levanta toda la topología (requiere certs y reglas ya generadas)
	$(COMPOSE) up -d --build
	@echo "Dashboard: https://localhost:8443 (usuario admin / ver .env)"

.PHONY: down
down: ## Detiene la topología y conserva los volúmenes
	$(COMPOSE) down

.PHONY: limpiar
limpiar: ## Detiene la topología y borra volúmenes (deja el lab limpio)
	$(COMPOSE) down -v

.PHONY: estado
estado: ## Muestra el estado de los contenedores
	$(COMPOSE) ps

.PHONY: logs
logs: ## Sigue los logs del manager
	$(COMPOSE) logs -f wazuh.manager

# --- Reglas -----------------------------------------------------------------

.PHONY: convert
convert: ## Convierte las reglas Sigma a reglas locales de Wazuh (en el operador)
	$(EXEC_OPERADOR) convert

.PHONY: load-rules
load-rules: convert ## Convierte y carga las reglas en el manager, y lo reinicia
	$(COMPOSE) cp reglas-wazuh/local_rules.xml wazuh.manager:/var/ossec/etc/rules/local_rules.xml
	$(COMPOSE) exec -T wazuh.manager chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
	$(COMPOSE) restart wazuh.manager
	@echo "Reglas cargadas y manager reiniciado."

# --- Simulaciones y verificación -------------------------------------------

SIM ?= todas

.PHONY: simulate
simulate: ## Lanza una simulación: make simulate SIM=reverse_shell (o SIM=todas)
	$(EXEC_OPERADOR) simulate $(SIM)

.PHONY: verify
verify: ## Verifica que la alerta esperada apareció: make verify SIM=todas
	$(EXEC_OPERADOR) verify $(SIM)

.PHONY: revert
revert: ## Revierte la telemetría: make revert SIM=reverse_shell (o sin SIM = todo)
	$(EXEC_OPERADOR) revert $(SIM)

.PHONY: report
report: ## Genera el informe y el sitio
	$(EXEC_OPERADOR) report

.PHONY: export-samples
export-samples: ## Exporta la telemetría al esquema del repo de reglas
	$(EXEC_OPERADOR) export /lab/estado/muestras-reales

# --- Calidad ----------------------------------------------------------------

.PHONY: lint
lint: ## Lint y formato (ruff) + tipos (mypy)
	ruff check .
	ruff format --check .
	mypy

.PHONY: test
test: ## Pruebas (se saltan las de Docker si no está disponible)
	pytest

.PHONY: hash-pass
hash-pass: ## Genera un hash bcrypt para una contraseña: make hash-pass PASS=...
	@python3 -c "import bcrypt,sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(rounds=12)).decode())" "$(PASS)"
