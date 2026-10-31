.DEFAULT_GOAL := help
SHELL := /bin/bash
UV ?= uv
PYTEST ?= $(UV) run pytest
LAB_HOST ?= 127.0.0.1
LAB_PORT ?= 18080
SMOKE_PORT ?=

.PHONY: help sync lint format typecheck imports test unit policy integration lab-tests eval check coverage lab smoke clean

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

sync: ## Install the complete uv workspace
	$(UV) sync --all-packages

lint: ## Run Ruff
	$(UV) run ruff check .

format: ## Apply safe Ruff formatting fixes
	$(UV) run ruff check . --fix

typecheck: ## Run strict mypy over all packages
	$(UV) run mypy packages

imports: ## Enforce package dependency boundaries
	$(UV) run lint-imports

test: ## Run the full software and eval suite
	$(PYTEST) -q

unit: ## Run unit tests
	$(PYTEST) -q tests/unit

policy: ## Run policy invariants
	$(PYTEST) -q tests/policy

integration: ## Run replay/fake-backend integration tests
	$(PYTEST) -q tests/integration

lab-tests: ## Run the isolated local-lab end-to-end tests
	$(PYTEST) -q tests/e2e_lab

eval: ## Run the offline agent scorecard
	$(UV) run python evals/scorecard.py

check: sync lint typecheck imports test eval ## Run every release gate

coverage: ## Run tests with branch coverage
	$(PYTEST) --cov=packages --cov-report=term-missing --cov-report=html

lab: ## Run the deterministic vulnerable lab
	$(UV) run huntress lab serve --host $(LAB_HOST) --port $(LAB_PORT)

smoke: ## Run a fresh CLI end-to-end lab smoke test
	LAB_PORT="$(SMOKE_PORT)" ./scripts/lab-smoke.sh

clean: ## Remove local caches (never removes .huntress data)
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
