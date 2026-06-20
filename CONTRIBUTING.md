# Contributing to VeriClaw

Thank you for your interest in contributing to VeriClaw! This document provides guidelines for contributing.

## Development Setup

```bash
git clone https://github.com/veriforge/vericlaw.git
cd vericlaw
pip install -e ".[dev]"
```

## Code Style

- **Black**: `black vericlaw/`
- **Ruff**: `ruff check vericlaw/`
- **MyPy**: `mypy vericlaw/`
- **Bandit**: `bandit -r vericlaw/`

## Running Tests

```bash
pytest vericlaw/tests/ -v
pytest vericlaw/tests/ --cov=vericlaw --cov-report=term-missing
```

## Adding a New Mutation Strategy

1. Add the strategy method to `vericlaw/mutator.py`
2. Register it in the strategies list
3. Add tests in `vericlaw/tests/test_core.py`
4. Update documentation

## Adding a New Payload Type

1. Add payload variants to `vericlaw/payloads.py`
2. Add context detection logic
3. Add tests in `vericlaw/tests/test_security.py`

## Pull Request Checklist

- [ ] Tests pass (`pytest -v`)
- [ ] Code formatted (`black`)
- [ ] Linting passes (`ruff` + `mypy`)
- [ ] Security scan passes (`bandit`)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
