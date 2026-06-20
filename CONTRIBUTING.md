# Contributing to VeriForge

Thank you for your interest in contributing to VeriForge! This document provides guidelines for contributing to the project.

## Code of Conduct

All contributors are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in the [issue tracker](https://github.com/veriforge/veriforge/issues)
2. If not, open a new issue using the bug report template
3. Include:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, VeriForge version)

### Requesting Features

1. Check if the feature has already been requested
2. Open a new issue using the feature request template
3. Describe the feature and its use case

### Pull Requests

1. Fork the repository
2. Create a new branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes
4. Ensure all tests pass:
   ```bash
   pytest tests/ -v
   ```
5. Ensure code quality:
   ```bash
   black veriforge/ tests/
   mypy veriforge/
   bandit -r veriforge/
   ```
6. Commit using [conventional commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat: add new verification mode"
   git commit -m "fix: handle edge case in path sanitization"
   git commit -m "docs: update API reference"
   ```
7. Push and open a pull request

## Development Setup

```bash
# Clone the repository
git clone https://github.com/veriforge/veriforge.git
cd veriforge

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=veriforge --cov-report=term-missing
```

## Security Considerations

When contributing, please ensure:

- **No `eval()` or `exec()`** — All analysis must use static AST methods
- **Input validation** — All external inputs must be validated and sanitized
- **HMAC signatures** — Any new data flows must include HMAC signing
- **No hard-coded secrets** — Use `SecureConfig` for all configuration
- **Type hints** — All functions must have complete type annotations
- **Tests** — All security features must have corresponding tests

## Code Style

- Follow PEP 8
- Use `black` for formatting (line length: 100)
- Use `mypy` for type checking with `disallow_untyped_defs = true`
- Use `slots=True` for dataclasses where possible
- Use `frozen=True` for immutable data structures

## Testing

- All new features must include tests
- All security fixes must include regression tests
- Tests go in `tests/test_hardened.py` or new `test_*.py` files
- Aim for 100% coverage of security-critical code paths

## Documentation

- Update `docs/API.md` for any public API changes
- Update `docs/ARCHITECTURE.md` for structural changes
- Update `CHANGELOG.md` for all user-visible changes

## License

By contributing to VeriForge, you agree that your contributions will be licensed under the MIT License.
