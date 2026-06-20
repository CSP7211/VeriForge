.PHONY: install test test-cov lint format security clean docs build publish

install:
	pip install -e ".[dev]"

test:
	pytest vericlaw/tests/ -v

test-cov:
	pytest vericlaw/tests/ --cov=vericlaw --cov-report=term-missing --cov-report=html

lint:
	ruff check vericlaw/
	mypy vericlaw/

format:
	black vericlaw/
	ruff check --fix vericlaw/

security:
	bandit -r vericlaw/
	python -m vericlaw.scan --target vericlaw/ --format json

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

publish: build
	python -m twine upload dist/*

docs:
	mkdocs serve
