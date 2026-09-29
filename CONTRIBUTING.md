# Contributing to qscout

Thank you for contributing to qscout.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Code standards

- Python 3.11+ with type hints
- `ruff` for linting
- `mypy` and `pyright` for static analysis
- Tests must pass with `PQC_INVENTORY_NO_NETWORK=1`

## Running tests

```bash
PQC_INVENTORY_NO_NETWORK=1 pytest --cov=qscout --cov-fail-under=90
```

## Pull requests

1. Add tests for new checks or collectors
2. Keep coverage at 90% or above
3. Document CLI changes in README and CHANGELOG
4. Do not include secrets or real credentials in fixtures

## Check catalogue changes

New checks require:

- Entry in `src/qscout/checks/rules.py`
- Evaluation logic in `src/qscout/checks/engine.py`
- Tests covering pass and fail cases
- Standards mapping with "informed by" phrasing unless exact

## Security

Report security issues privately to the maintainers. Do not open public issues
for undisclosed vulnerabilities.
