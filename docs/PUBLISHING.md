# Publishing to PyPI Guide

This guide walks you through publishing `mcp-wireshark` to PyPI so users can install it via `pip install mcp-wireshark`.

## Prerequisites

1. **PyPI Account**: Create accounts on:
   - [PyPI](https://pypi.org/account/register/) (production)
   - [TestPyPI](https://test.pypi.org/account/register/) (testing)

2. **API Tokens**: Generate API tokens for both:
   - PyPI: Account Settings → API tokens → "Add API token"
   - TestPyPI: Same process on test.pypi.org

3. **Install Tools**:
```bash
pip install build twine
```

## Step 1: Prepare Your Package

### Update Version
Edit `pyproject.toml` and update the version:
```toml
[project]
version = "0.1.0"  # Change this for each release
```

### Run Quality Checks
```bash
# Format code
black src tests

# Lint
ruff check src tests

# Type check
mypy src

# Run tests
pytest
```

## Step 2: Build the Package

```bash
# Clean old builds
rm -rf dist/ build/ *.egg-info

# Build
python -m build
```

This creates:
- `dist/mcp_wireshark-0.1.0.tar.gz` (source distribution)
- `dist/mcp_wireshark-0.1.0-py3-none-any.whl` (wheel)

## Step 3: Test on TestPyPI

```bash
# Upload to TestPyPI
twine upload --repository testpypi dist/*
# Enter your TestPyPI credentials when prompted
```

### Test Installation from TestPyPI
```bash
# Create a new virtual environment
python -m venv test-env
source test-env/bin/activate  # Windows: test-env\Scripts\activate

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ mcp-wireshark

# Test it works
mcp-wireshark --help
```

## Step 4: Publish to PyPI

Once you've verified it works on TestPyPI:

```bash
# Upload to PyPI
twine upload dist/*
# Enter your PyPI credentials when prompted
```

## Step 5: Verify Installation

```bash
# In a fresh virtual environment
pip install mcp-wireshark

# Test
mcp-wireshark
```

## Automated Publishing with GitHub Actions

### Setup GitHub Secrets

1. Go to your GitHub repository
2. Settings → Secrets and variables → Actions
3. Add secrets:
   - `PYPI_API_TOKEN`: Your PyPI API token
   - `TEST_PYPI_API_TOKEN`: Your TestPyPI API token

### Create a Release

The `.github/workflows/publish.yml` workflow automatically publishes when you create a GitHub release:

1. Go to your repository → Releases → "Draft a new release"
2. Create a new tag (e.g., `v0.1.0`)
3. Title: `v0.1.0` or `Release 0.1.0`
4. Description: Copy from `CHANGELOG.md`
5. Click "Publish release"

The GitHub Action will automatically:
- Build the package
- Run tests
- Publish to PyPI

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH`
- `0.1.0` → `0.1.1` (bug fixes)
- `0.1.0` → `0.2.0` (new features)
- `0.9.0` → `1.0.0` (stable release)

## Checklist Before Publishing

- [ ] All tests pass (`pytest`)
- [ ] Code is formatted (`black src tests`)
- [ ] No lint errors (`ruff check src tests`)
- [ ] Type checking passes (`mypy src`)
- [ ] Documentation is updated
- [ ] `CHANGELOG.md` is updated
- [ ] Version number is bumped in `pyproject.toml`
- [ ] `README.md` is accurate
- [ ] Examples work
- [ ] Tested on TestPyPI

## Troubleshooting

### "File already exists" Error
You can't upload the same version twice. Increment the version number in `pyproject.toml`.

### Import Errors After Install
Ensure your package structure is correct:
```
src/
  mcp_wireshark/
    __init__.py
    server.py
    ...
```

### Missing Dependencies
Users must install Wireshark/tshark separately. This is documented in the README.

## Post-Publication

After publishing:
1. Tag the release in git: `git tag v0.1.0 && git push --tags`
2. Update `CHANGELOG.md` with the next version
3. Announce on social media, GitHub Discussions, etc.

## Resources

- [PyPI Help](https://pypi.org/help/)
- [Python Packaging Guide](https://packaging.python.org/)
- [Twine Documentation](https://twine.readthedocs.io/)
