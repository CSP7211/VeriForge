.PHONY: help install install-dev test lint format security clean build docs

PYTHON := python3

help:
	@echo "VeriForge — Hardened Formal Verification Platform"
	@echo ""
	@echo "Available targets:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install with development dependencies"
	@echo "  test         Run the test suite"
	@echo "  test-cov     Run tests with coverage"
	@echo "  lint         Run all linters (black, mypy, bandit)"
	@echo "  format       Auto-format code with black"
	@echo "  format-check Check code formatting"
	@echo "  security     Run security scanners (bandit)"
	@echo "  clean        Remove build artifacts"
	@echo "  build        Build distribution packages"
	@echo "  docs         Show documentation links"

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest tests/ -v

test-cov:
	$(PYTHON) -m pytest tests/ --cov=veriforge --cov-report=term-missing --cov-report=xml

lint: format-check security
	$(PYTHON) -m mypy veriforge/

format:
	$(PYTHON) -m black veriforge/ tests/ examples/

format-check:
	$(PYTHON) -m black --check veriforge/ tests/ examples/

security:
	$(PYTHON) -m bandit -r veriforge/ -f json -o bandit-report.json || true
	$(PYTHON) -m bandit -r veriforge/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .coverage coverage.xml bandit-report.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

build: clean
	$(PYTHON) -m build

docs:
	@echo "Documentation:"
	@echo "  docs/ARCHITECTURE.md  — Security architecture"
	@echo "  docs/API.md           — API reference"
	@echo "  docs/DEPLOYMENT.md    — Docker/K8s deployment"
