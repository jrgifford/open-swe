.PHONY: all format format-check lint typecheck test tests integration_tests help run dev start-k3 status-k3 logs-k3 stop-k3 destroy-k3

# Default target executed when no arguments are given to make.
all: help

######################
# DEVELOPMENT
######################

dev:
	uv run langgraph dev

run:
	uv run uvicorn agent.webapp:app --reload --port 8000

start-k3:
	mise install
	mise exec -- python scripts/k3_runtime.py start $(K3_FLAGS)

status-k3:
	mise exec -- python scripts/k3_runtime.py status

logs-k3:
	mise exec -- python scripts/k3_runtime.py logs

stop-k3:
	mise exec -- python scripts/k3_runtime.py stop

destroy-k3:
	mise exec -- python scripts/k3_runtime.py destroy $(K3_DESTROY_FLAGS)

install:
	uv sync --extra dev

######################
# TESTING
######################

TEST_FILE ?= tests/

test tests:
	@if [ -d "$(TEST_FILE)" ] || [ -f "$(TEST_FILE)" ]; then \
		uv run pytest -vvv $(TEST_FILE); \
	else \
		echo "Skipping tests: path not found: $(TEST_FILE)"; \
	fi

integration_tests:
	@if [ -d "tests/integration_tests/" ] || [ -f "tests/integration_tests/" ]; then \
		uv run pytest -vvv tests/integration_tests/; \
	else \
		echo "Skipping integration tests: path not found: tests/integration_tests/"; \
	fi

######################
# LINTING AND FORMATTING
######################

PYTHON_FILES=.

lint:
	uv run ruff check $(PYTHON_FILES)
	uv run ruff format $(PYTHON_FILES) --diff

format:
	uv run ruff format $(PYTHON_FILES)
	uv run ruff check --fix $(PYTHON_FILES)

format-check:
	uv run ruff format $(PYTHON_FILES) --check

typecheck:
	npx --yes basedpyright agent tests

######################
# HELP
######################

help:
	@echo '----'
	@echo 'dev                          - run LangGraph dev server'
	@echo 'run                          - run webhook server'
	@echo 'install                      - install dependencies (incl. dev extras)'
	@echo 'start-k3                     - build and reconcile the local k3d runtime'
	@echo 'status-k3                    - show local k3d runtime status'
	@echo 'logs-k3                      - show local runtime logs and sandbox events'
	@echo 'stop-k3                      - stop the cluster and retain state'
	@echo 'destroy-k3                   - delete the cluster after confirmation'
	@echo 'format                       - run code formatters'
	@echo 'lint                         - run linters'
	@echo 'typecheck                    - run basedpyright on agent/ and tests/'
	@echo 'test                         - run unit tests'
	@echo 'integration_tests            - run integration tests'
	@echo '----'
