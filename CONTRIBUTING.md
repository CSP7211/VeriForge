# Contributing to VeriForge Red

## Setup
```bash
git clone https://github.com/veriforge/veriforge-red.git
cd veriforge-red
pip install -e ".[dev]"
```

## Testing
```bash
pytest veriforge_red/tests/ -v
```

## Code Style
```bash
black veriforge_red/
bandit -r veriforge_red/
```

## Pull Request Checklist
- [ ] Tests pass
- [ ] Code formatted with black
- [ ] Security scan passes (bandit)
- [ ] Documentation updated
