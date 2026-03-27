# Contributing to Argus

Thank you for your interest in contributing to Argus! This guide will help you get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/cortexc0de/argus-lite.git
cd argus-lite

# Create virtual environment
python3.10 -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Verify tests pass
pytest tests/ -q
```

## Architecture

Argus follows a layered architecture:

```
CLI (cli.py) → Core (orchestrator/agent/skills) → Modules (recon/analysis) → Tools (external binaries)
```

Key principles:
- **TDD** — write tests first, then implementation
- **SDD** — models define the data contract before code
- **ADD** — architecture decisions documented before implementation

## Code Style

- Python 3.10+ type hints on all public functions
- Pydantic v2 for all data models
- `async/await` for I/O-bound operations
- No `shell=True` in subprocess calls (security requirement)
- `Field(default_factory=list)` for mutable defaults in Pydantic models

## Testing

We use pytest with a TDD workflow:

```bash
# Run all tests
pytest tests/ -q

# Run specific module
pytest tests/test_skills.py -v

# Run with coverage
pytest tests/ --cov=argus_lite --cov-report=term-missing

# Coverage must stay above 70%
pytest tests/ --cov=argus_lite --cov-fail-under=70
```

### Writing Tests

1. Create test file in `tests/` matching `test_<module>.py`
2. Write failing tests first (RED)
3. Implement the minimum code to pass (GREEN)
4. Refactor while keeping tests green (REFACTOR)

```python
class TestMyFeature:
    def test_basic_case(self):
        result = my_function("input")
        assert result.success

    def test_edge_case(self):
        result = my_function("")
        assert not result.success
```

## Creating Custom Skills

You can extend Argus with custom skills defined as markdown files. See [docs/skills/custom-skills.md](docs/skills/custom-skills.md) for the full guide.

Quick example — create `~/.argus-lite/skills/check_wp.md`:

```markdown
---
name: check_wordpress
description: WordPress-specific security checks
tools: [nuclei, httpx]
---

1. Probe /wp-admin and /wp-login.php
2. Run nuclei with wordpress tags
3. Check xmlrpc.php exposure
```

## Pull Request Process

1. **Fork** the repository and create a feature branch from `master`
2. **Write tests** for your changes
3. **Implement** the feature/fix
4. **Run the full test suite** — all tests must pass
5. **Commit** with a descriptive message following conventional commits:
   - `feat: add new skill for X`
   - `fix: correct severity mapping in nuclei`
   - `docs: update installation guide`
   - `test: add tests for bulk scanner edge cases`
6. **Open a PR** against `master` with:
   - Clear description of what and why
   - Link to related issue (if any)
   - Test plan

## Reporting Issues

- Use [GitHub Issues](https://github.com/cortexc0de/argus-lite/issues)
- Include: Argus version, Python version, OS, full error output
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
