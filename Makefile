.PHONY: help install install-dev test test-integ test-all test-cov lint format typecheck check clean docker-up docker-down docker-build docker-prod

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
	@echo "Infrastructure (Production):"
	@echo "  docker-build   Build the sshmgr Docker image"
	@echo "  docker-prod    Start all services in production mode"
	@echo "  docker-prod-down  Stop production services"
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
	python scripts/keycloak_setup.py --create-test-user

keycloak-setup-prod:
	@echo "Setting up Keycloak for production..."
	python scripts/keycloak_setup.py --no-wait --output-env .env

# Utilities
generate-key:
	@python -c "from cryptography.fernet import Fernet; print('SSHMGR_MASTER_KEY=' + Fernet.generate_key().decode())"

run-api:
	uvicorn sshmgr.api.main:app --reload --host 0.0.0.0 --port 8000

# Database migrations
db-migrate:
	alembic upgrade head

db-revision:
	@read -p "Migration message: " msg; alembic revision --autogenerate -m "$$msg"

db-downgrade:
	alembic downgrade -1
