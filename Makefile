.PHONY: install test lint clean build docs

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --tb=short --cov=veriforge_sdk --cov-report=term-missing --cov-report=html

lint:
	black veriforge_sdk/ tests/ examples/
	mypy veriforge_sdk/

lint-check:
	black --check veriforge_sdk/ tests/ examples/
	mypy veriforge_sdk/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache htmlcov/

build: clean
	python -m build

docs:
	@echo "See README.md for full documentation"

all: lint test
