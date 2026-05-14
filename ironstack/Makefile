# IronStack Makefile
# =====================================
# Type 'make help' to see all available commands

# Default shell
SHELL := /bin/bash

# Project variables
PROJECT_NAME := ironstack
PYTHON := python3
PIP := pip3
PACKAGE := ironstack

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Default target
.DEFAULT_GOAL := help

# =====================================
# Help
# =====================================
help: ## Show this help message
	@echo ""
	@echo -e "${BLUE}IronStack - Security Swiss Army Knife${NC}"
	@echo ""
	@echo -e "${GREEN}Usage:${NC}"
	@echo "  make [target]"
	@echo ""
	@echo -e "${GREEN}Available targets:${NC}"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "  ${YELLOW}%-20s${NC} %s\n", $$1, $$2}'

# =====================================
# Installation
# =====================================
install: ## Install core package in development mode
	@echo -e "${BLUE}Installing IronStack...${NC}"
	$(PIP) install -e .

install-full: ## Install package with all optional dependencies
	@echo -e "${BLUE}Installing IronStack with all dependencies...${NC}"
	$(PIP) install -e ".[full]"

install-dev: ## Install package with development dependencies
	@echo -e "${BLUE}Installing IronStack with dev dependencies...${NC}"
	$(PIP) install -e ".[dev]"
	$(PIP) install -r requirements-dev.txt

install-defense: ## Install defense layer dependencies only
	@echo -e "${BLUE}Installing IronStack defense layer...${NC}"
	$(PIP) install -e ".[defense]"

install-attack: ## Install attack layer dependencies only
	@echo -e "${BLUE}Installing IronStack attack layer...${NC}"
	$(PIP) install -e ".[attack]"

uninstall: ## Uninstall IronStack
	@echo -e "${RED}Uninstalling IronStack...${NC}"
	$(PIP) uninstall -y $(PROJECT_NAME)

# =====================================
# Virtual Environment
# =====================================
venv: ## Create virtual environment
	@echo -e "${BLUE}Creating virtual environment...${NC}"
	$(PYTHON) -m venv venv
	@echo -e "${GREEN}Virtual environment created at ./venv${NC}"
	@echo -e "${YELLOW}Activate with: source venv/bin/activate${NC}"

venv-activate: ## Show activate command
	@echo -e "${YELLOW}Run: source venv/bin/activate${NC}"

# =====================================
# Development
# =====================================
dev-setup: venv install-dev ## Full development setup
	@echo -e "${GREEN}Development environment ready!${NC}"
	@echo -e "${YELLOW}Activate venv: source venv/bin/activate${NC}"

pre-commit-install: ## Install pre-commit hooks
	@echo -e "${BLUE}Installing pre-commit hooks...${NC}"
	pre-commit install
	pre-commit install --hook-type commit-msg

pre-commit-run: ## Run pre-commit on all files
	@echo -e "${BLUE}Running pre-commit hooks...${NC}"
	pre-commit run --all-files

# =====================================
# Code Quality
# =====================================
format: ## Format code with black and isort
	@echo -e "${BLUE}Formatting code...${NC}"
	black $(PACKAGE)/ tests/
	isort $(PACKAGE)/ tests/

lint: ## Run all linters
	@echo -e "${BLUE}Running linters...${NC}"
	flake8 $(PACKAGE)/ tests/
	pylint $(PACKAGE)/ || true

type-check: ## Run type checker
	@echo -e "${BLUE}Running type checker...${NC}"
	mypy $(PACKAGE)/

quality: format lint type-check ## Run all code quality checks

# =====================================
# Security
# =====================================
security-check: ## Run security checks
	@echo -e "${BLUE}Running security checks...${NC}"
	bandit -r $(PACKAGE)/
	safety check

# =====================================
# Testing
# =====================================
test: ## Run all tests
	@echo -e "${BLUE}Running all tests...${NC}"
	pytest tests/

test-verbose: ## Run tests with verbose output
	@echo -e "${BLUE}Running tests (verbose)...${NC}"
	pytest tests/ -v

test-cov: ## Run tests with coverage report
	@echo -e "${BLUE}Running tests with coverage...${NC}"
	pytest tests/ --cov=$(PACKAGE) --cov-report=html --cov-report=term
	@echo -e "${GREEN}Coverage report: htmlcov/index.html${NC}"

test-cov-xml: ## Run tests with XML coverage (for CI)
	@echo -e "${BLUE}Running tests with XML coverage...${NC}"
	pytest tests/ --cov=$(PACKAGE) --cov-report=xml

test-unit: ## Run unit tests only
	@echo -e "${BLUE}Running unit tests...${NC}"
	pytest tests/ -m "not integration and not slow"

test-integration: ## Run integration tests only
	@echo -e "${BLUE}Running integration tests...${NC}"
	pytest tests/ -m integration

test-slow: ## Run slow tests only
	@echo -e "${BLUE}Running slow tests...${NC}"
	pytest tests/ -m slow

test-watch: ## Run tests on file change
	@echo -e "${BLUE}Watching for file changes...${NC}"
	ptw tests/ $(PACKAGE)/

benchmark: ## Run benchmarks
	@echo -e "${BLUE}Running benchmarks...${NC}"
	pytest tests/ --benchmark-only

# =====================================
# Documentation
# =====================================
docs: ## Build documentation
	@echo -e "${BLUE}Building documentation...${NC}"
	cd docs && $(MAKE) html
	@echo -e "${GREEN}Documentation built: docs/_build/html/index.html${NC}"

docs-serve: ## Serve documentation locally
	@echo -e "${BLUE}Serving documentation...${NC}"
	$(PYTHON) -m http.server 8000 --directory docs/_build/html/

docs-clean: ## Clean documentation build
	@echo -e "${BLUE}Cleaning documentation...${NC}"
	cd docs && $(MAKE) clean

# =====================================
# Build & Package
# =====================================
build: clean-build ## Build package
	@echo -e "${BLUE}Building package...${NC}"
	$(PYTHON) -m build

build-check: build ## Check built package
	@echo -e "${BLUE}Checking package...${NC}"
	twine check dist/*

publish-test: build-check ## Publish to Test PyPI
	@echo -e "${BLUE}Publishing to Test PyPI...${NC}"
	twine upload --repository testpypi dist/*

publish: build-check ## Publish to PyPI
	@echo -e "${RED}Publishing to PyPI...${NC}"
	@echo -e "${YELLOW}Are you sure? [y/N]${NC}"
	@read -r response && if [ "$$response" = "y" ]; then \
		twine upload dist/*; \
	else \
		echo "Canceled."; \
	fi

# =====================================
# Cleaning
# =====================================
clean: clean-build clean-pyc clean-test clean-venv ## Clean everything
	@echo -e "${GREEN}Cleaned!${NC}"

clean-build: ## Clean build artifacts
	@echo -e "${BLUE}Cleaning build artifacts...${NC}"
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf $(PACKAGE)/*.egg-info
	rm -rf .eggs/

clean-pyc: ## Clean Python bytecode
	@echo -e "${BLUE}Cleaning Python bytecode...${NC}"
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	find . -type f -name '*~' -delete
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.mypy_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.ruff_cache' -exec rm -rf {} + 2>/dev/null || true

clean-test: ## Clean test artifacts
	@echo -e "${BLUE}Cleaning test artifacts...${NC}"
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf coverage.xml
	rm -rf .tox/

clean-venv: ## Remove virtual environment
	@echo -e "${RED}Removing virtual environment...${NC}"
	rm -rf venv/

# =====================================
# Environment Information
# =====================================
info: ## Show environment information
	@echo -e "${BLUE}IronStack Environment Info${NC}"
	@echo -e "${YELLOW}===========================${NC}"
	@echo -e "Python: $$($(PYTHON) --version)"
	@echo -e "Pip: $$($(PIP) --version)"
	@echo -e "Package: $(PROJECT_NAME)"
	@echo -e "Version: $$($(PYTHON) -c 'import $(PACKAGE); print($(PACKAGE).__version__)')"

check: ## Check if all requirements are installed
	@echo -e "${BLUE}Checking dependencies...${NC}"
	$(PYTHON) -c "import $(PACKAGE)" 2>/dev/null && \
		echo -e "${GREEN}✓ $(PACKAGE) is installed${NC}" || \
		echo -e "${RED}✗ $(PACKAGE) is not installed${NC}"

# =====================================
# Git Helpers
# =====================================
git-status: ## Show git status
	git status

git-log: ## Show git log
	git log --oneline --graph --decorate -20

git-commits: ## Show recent commits
	git log --pretty=format:"%h - %an, %ar : %s" -10

# =====================================
# Docker (Optional)
# =====================================
docker-build: ## Build Docker image
	@echo -e "${BLUE}Building Docker image...${NC}"
	docker build -t $(PROJECT_NAME) .

docker-run: ## Run Docker container
	@echo -e "${BLUE}Running Docker container...${NC}"
	docker run -it $(PROJECT_NAME)

docker-clean: ## Clean Docker artifacts
	@echo -e "${BLUE}Cleaning Docker artifacts...${NC}"
	docker rmi $(PROJECT_NAME) 2>/dev/null || true

# =====================================
# Release
# =====================================
release-patch: ## Bump patch version
	@echo -e "${BLUE}Bumping patch version...${NC}"
	bumpversion patch
	git push --tags

release-minor: ## Bump minor version
	@echo -e "${BLUE}Bumping minor version...${NC}"
	bumpversion minor
	git push --tags

release-major: ## Bump major version
	@echo -e "${RED}Bumping major version...${NC}"
	bumpversion major
	git push --tags

# =====================================
# Aliases
# =====================================
fmt: format ## Alias for format
t: test ## Alias for test
tc: test-cov ## Alias for test-cov
q: quality ## Alias for quality
b: build ## Alias for build
c: clean ## Alias for clean

# =====================================
# Phony targets
# =====================================
.PHONY: help install install-full install-dev install-defense install-attack uninstall
.PHONY: venv venv-activate dev-setup pre-commit-install pre-commit-run
.PHONY: format lint type-check quality security-check
.PHONY: test test-verbose test-cov test-cov-xml test-unit test-integration test-slow test-watch benchmark
.PHONY: docs docs-serve docs-clean
.PHONY: build build-check publish-test publish
.PHONY: clean clean-build clean-pyc clean-test clean-venv
.PHONY: info check
.PHONY: git-status git-log git-commits
.PHONY: docker-build docker-run docker-clean
.PHONY: release-patch release-minor release-major
.PHONY: fmt t tc q b c
