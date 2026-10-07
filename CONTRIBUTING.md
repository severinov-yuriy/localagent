# Contributing

## Development setup

Use a supported Python interpreter and install the project with the development extras:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Required checks

Before opening a change, run:

```bash
pytest -q
ruff check src tests
mypy src
python -m build
```

The CI workflow runs the same checks on the supported Python versions. Security-sensitive changes should include a focused regression test plus an end-to-end test where the behavior crosses the agent/tool boundary.

## Security rules

Do not broaden capabilities to make a failing test pass. In particular, do not add generic subprocess/shell/Python execution, external filesystem roots, disabled DLP, or ACL bypasses. Centralize new filesystem authorization and secret handling in the existing policy/security components.

Avoid committing generated artifacts such as `.pytest_cache/`, `__pycache__/`, `.pyc`, coverage files, build directories, or local credentials.
