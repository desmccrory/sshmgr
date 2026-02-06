.PHONY: help install install-dev test test-integ test-all test-cov lint format typecheck check clean docker-up docker-down docker-build docker-prod prod-up prod-down prod-logs prod-status backup-now backup-list backup-export backup-restore monitoring-up monitoring-down monitoring-logs

# Default target
help:
	@echo "sshmgr - SSH Certificate Management System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  install-dev    Install package in development mode with all dependencies"
	@echo "  install        Install package in production mode"
	@echo "  test           Run unit tests only"
	@echo "  test-integ     Run integration tests only"
	@echo "  test-all       Run all tests (unit + integration)"
	@echo "  test-cov       Run all tests with coverage report"
	@echo "  lint           Run linter (ruff)"
	@echo "  format         Format code (ruff)"
	@echo "  typecheck      Run type checker (mypy)"
	@echo "  check          Run all checks (lint, typecheck, test)"
	@echo "  clean          Remove build artifacts and cache"
	@echo ""
	@echo "Infrastructure (Development):"
	@echo "  docker-up      Start PostgreSQL and Keycloak containers"
	@echo "  docker-down    Stop and remove containers"
	@echo "  docker-logs    Show container logs"
	@echo ""
	@echo "Infrastructure (Production - simple):"
	@echo "  docker-build   Build the sshmgr Docker image"
	@echo "  docker-prod    Start all services in production mode (no TLS)"
	@echo "  docker-prod-down  Stop production services"
	@echo ""
	@echo "Infrastructure (Production - with Traefik/TLS):"
	@echo "  prod-up        Start production stack with Traefik and Let's Encrypt"
	@echo "  prod-down      Stop production stack"
	@echo "  prod-logs      Show production logs"
	@echo "  prod-status    Show status of production services"
	@echo ""
	@echo "Backup & Restore:"
	@echo "  backup-now     Create immediate database backup"
	@echo "  backup-list    List all available backups"
	@echo "  backup-export  Export latest backup to ./backups/"
	@echo "  backup-restore Restore from backup (BACKUP_FILE=path)"
	@echo ""
	@echo "Monitoring (Prometheus + Grafana + AlertManager):"
	@echo "  monitoring-up  Start production with monitoring stack"
	@echo "  monitoring-down Stop monitoring services"
	@echo "  monitoring-logs View monitoring service logs"
	@echo ""
	@echo "Database:"
	@echo "  db-migrate     Run pending database migrations"
	@echo "  db-revision    Create a new migration"
	@echo "  db-downgrade   Rollback one migration"
	@echo ""
	@echo "Utilities:"
	@echo "  generate-key   Generate a new master encryption key"
	@echo "  run-api        Run the API server (development)"

# Installation
install:
	pip install .

install-dev:
	pip install -e ".[dev]"

# Python/venv setup
VENV := .venv
PYTHON := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest
ALEMBIC := $(VENV)/bin/alembic

# Testing
test:
	PYTHONPATH=src $(PYTEST) tests/unit -v

test-integ:
	PYTHONPATH=src $(PYTEST) tests/integration -v

test-all:
	PYTHONPATH=src $(PYTEST) tests -v

test-cov:
	PYTHONPATH=src $(PYTEST) tests --cov=sshmgr --cov-report=term-missing --cov-report=html

# Code quality
lint:
	ruff check src tests

format:
	ruff format src tests
	ruff check --fix src tests

typecheck:
	mypy src

# All checks
check: lint typecheck test

# Clean up
clean:
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Docker infrastructure
docker-up:
	docker-compose up -d
	@echo ""
	@echo "Services starting..."
	@echo "  PostgreSQL: localhost:5432"
	@echo "  Keycloak:   http://localhost:8080 (admin/admin)"
	@echo ""
	@echo "Wait for services to be ready, then run: make keycloak-setup"

docker-down:
	docker-compose down -v

docker-logs:
	docker-compose logs -f

# Production Docker commands
docker-build:
	docker build -t sshmgr:latest .

docker-prod:
	@if [ -z "$$SSHMGR_MASTER_KEY" ] && [ ! -f .env ]; then \
		echo "Error: SSHMGR_MASTER_KEY not set. Create .env file or set environment variable."; \
		echo "Generate a key with: make generate-key"; \
		exit 1; \
	fi
	docker-compose --profile production up -d

docker-prod-down:
	docker-compose --profile production down

docker-prod-logs:
	docker-compose --profile production logs -f

# Keycloak setup (run after docker-up)
keycloak-setup:
	@echo "Setting up Keycloak realm and clients..."
	$(PYTHON) scripts/keycloak_setup.py --create-test-user

keycloak-setup-prod:
	@echo "Setting up Keycloak for production..."
	$(PYTHON) scripts/keycloak_setup.py --no-wait --output-env .env

# Utilities
generate-key:
	@$(PYTHON) -c "from cryptography.fernet import Fernet; print('SSHMGR_MASTER_KEY=' + Fernet.generate_key().decode())"

run-api:
	PYTHONPATH=src $(VENV)/bin/uvicorn sshmgr.api.main:app --reload --host 0.0.0.0 --port 8000

# Database migrations
db-migrate:
	PYTHONPATH=src $(ALEMBIC) upgrade head

db-revision:
	@read -p "Migration message: " msg; PYTHONPATH=src $(ALEMBIC) revision --autogenerate -m "$$msg"

db-downgrade:
	PYTHONPATH=src $(ALEMBIC) downgrade -1

# =============================================================================
# Production with Traefik and TLS (docker-compose.prod.yml)
# =============================================================================
PROD_COMPOSE := docker compose -f docker-compose.prod.yml

prod-up:
	@if [ ! -f .env ]; then \
		echo "Error: .env file not found."; \
		echo "Copy .env.example to .env and configure required values:"; \
		echo "  cp .env.example .env"; \
		echo ""; \
		echo "Required variables:"; \
		echo "  - DOMAIN (your domain, e.g., sshmgr.example.com)"; \
		echo "  - ACME_EMAIL (email for Let's Encrypt)"; \
		echo "  - SSHMGR_MASTER_KEY (generate with: make generate-key)"; \
		echo "  - POSTGRES_PASSWORD"; \
		echo "  - KEYCLOAK_ADMIN_PASSWORD"; \
		exit 1; \
	fi
	@echo "Building sshmgr image..."
	$(PROD_COMPOSE) build
	@echo ""
	@echo "Starting production stack with Traefik..."
	$(PROD_COMPOSE) up -d
	@echo ""
	@echo "Production stack starting. Services will be available at:"
	@echo "  API:      https://api.$${DOMAIN}"
	@echo "  Keycloak: https://auth.$${DOMAIN}"
	@echo ""
	@echo "Check status with: make prod-status"
	@echo "View logs with:    make prod-logs"

prod-down:
	$(PROD_COMPOSE) down

prod-logs:
	$(PROD_COMPOSE) logs -f

prod-status:
	@echo "=== Container Status ==="
	$(PROD_COMPOSE) ps
	@echo ""
	@echo "=== Health Checks ==="
	@docker inspect sshmgr-api --format='API: {{.State.Health.Status}}' 2>/dev/null || echo "API: not running"
	@docker inspect sshmgr-keycloak --format='Keycloak: {{.State.Health.Status}}' 2>/dev/null || echo "Keycloak: not running"
	@docker inspect sshmgr-postgres --format='PostgreSQL: {{.State.Health.Status}}' 2>/dev/null || echo "PostgreSQL: not running"

prod-restart:
	$(PROD_COMPOSE) restart

prod-shell:
	$(PROD_COMPOSE) exec api /bin/bash

# =============================================================================
# Backup and Restore
# =============================================================================

backup-now:
	@echo "Creating immediate database backup..."
	$(PROD_COMPOSE) exec -T postgres-backup sh -c 'pg_dump | gzip > /backups/sshmgr_manual_$$(date +%Y%m%d_%H%M%S).sql.gz'
	@echo "Backup completed. Use 'make backup-list' to see all backups."

backup-list:
	@echo "=== Available Backups ==="
	@docker run --rm -v sshmgr_postgres_backups:/backups alpine ls -lah /backups/ 2>/dev/null || echo "No backups found or volume doesn't exist"

backup-export:
	@echo "Exporting latest backup to ./backups/..."
	@mkdir -p ./backups
	@docker run --rm -v sshmgr_postgres_backups:/backups -v $$(pwd)/backups:/export alpine sh -c 'cp $$(ls -t /backups/sshmgr_*.sql.gz 2>/dev/null | head -1) /export/ 2>/dev/null' && echo "Backup exported to ./backups/" || echo "No backups found to export"

backup-restore:
	@if [ -z "$(BACKUP_FILE)" ]; then \
		echo "Usage: make backup-restore BACKUP_FILE=./backups/sshmgr_YYYYMMDD_HHMMSS.sql.gz"; \
		echo ""; \
		echo "Available backups in volume:"; \
		docker run --rm -v sshmgr_postgres_backups:/backups alpine ls -la /backups/ 2>/dev/null || echo "  (none)"; \
		echo ""; \
		echo "Local backups in ./backups/:"; \
		ls -la ./backups/*.sql.gz 2>/dev/null || echo "  (none)"; \
		exit 1; \
	fi
	@echo "WARNING: This will overwrite the current database!"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "Restoring from $(BACKUP_FILE)..."
	@gunzip -c $(BACKUP_FILE) | docker exec -i sshmgr-postgres psql -U $${POSTGRES_USER:-sshmgr} -d $${POSTGRES_DB:-sshmgr}
	@echo "Restore completed."

# =============================================================================
# Monitoring (Prometheus + Grafana + AlertManager)
# =============================================================================

monitoring-up:
	@if [ ! -f .env ]; then \
		echo "Error: .env file not found. Run 'cp .env.example .env' first."; \
		exit 1; \
	fi
	@if [ -z "$${GRAFANA_ADMIN_PASSWORD}" ] && ! grep -q "^GRAFANA_ADMIN_PASSWORD=." .env 2>/dev/null; then \
		echo "Error: GRAFANA_ADMIN_PASSWORD is required for monitoring."; \
		echo "Add it to your .env file."; \
		exit 1; \
	fi
	@echo "Building sshmgr image..."
	$(PROD_COMPOSE) --profile monitoring build
	@echo ""
	@echo "Starting production stack with monitoring..."
	$(PROD_COMPOSE) --profile monitoring up -d
	@echo ""
	@echo "Production stack with monitoring starting. Services available at:"
	@echo "  API:          https://api.$${DOMAIN}"
	@echo "  Keycloak:     https://auth.$${DOMAIN}"
	@echo "  Grafana:      https://grafana.$${DOMAIN}"
	@echo "  Prometheus:   https://prometheus.$${DOMAIN}"
	@echo "  AlertManager: https://alertmanager.$${DOMAIN}"
	@echo ""
	@echo "Default Grafana login: admin / (GRAFANA_ADMIN_PASSWORD from .env)"

monitoring-down:
	$(PROD_COMPOSE) --profile monitoring down

monitoring-logs:
	$(PROD_COMPOSE) --profile monitoring logs -f prometheus alertmanager grafana
