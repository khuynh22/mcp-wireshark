# Development Setup Guide

Complete guide for contributors to set up their development environment.

## Prerequisites

- **Python 3.10+**: Download from [python.org](https://www.python.org/downloads/)
- **Git**: Download from [git-scm.com](https://git-scm.com/)
- **Wireshark/tshark**: See installation instructions below

### Installing Wireshark/tshark

**macOS** (using Homebrew):
```bash
brew install wireshark
```

**Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install tshark
sudo usermod -aG wireshark $USER
sudo chmod +x /usr/bin/dumpcap
# Log out and back in for group changes to take effect
```

**Windows**:
1. Download from [Wireshark Downloads](https://www.wireshark.org/download.html)
2. Run installer
3. Add to PATH: `C:\Program Files\Wireshark`

## Fork and Clone

1. **Fork** the repository on GitHub
2. **Clone** your fork:
```bash
git clone https://github.com/YOUR_USERNAME/mcp-wireshark.git
cd mcp-wireshark
```

3. **Add upstream** remote:
```bash
git remote add upstream https://github.com/khuynh22/mcp-wireshark.git
```

## Virtual Environment Setup

### Windows (PowerShell)
```powershell
# Create virtual environment
python -m venv venv

# Activate
.\venv\Scripts\Activate.ps1

# If you get execution policy error:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### macOS/Linux
```bash
# Create virtual environment
python3 -m venv venv

# Activate
source venv/bin/activate
```

## Install Development Dependencies

```bash
# Install package in editable mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (recommended)
pip install pre-commit
pre-commit install
```

## Verify Installation

```bash
# Run tests
pytest

# Check code style
black --check src tests
ruff check src tests

# Type checking
mypy src

# Try the CLI
mcp-wireshark
```

## Development Workflow

### 1. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

Edit code in `src/mcp_wireshark/`

### 3. Run Quality Checks

```bash
# Auto-format code
black src tests

# Fix linting issues
ruff check --fix src tests

# Type checking
mypy src

# Run tests
pytest

# Run all checks with coverage
pytest --cov=mcp_wireshark --cov-report=html
# Open htmlcov/index.html to view coverage
```

### 4. Test Manually

```bash
# Run the server
mcp-wireshark

# Or test specific examples
python examples/basic_usage.py
python examples/live_capture_demo.py
```

### 5. Commit Changes

```bash
git add .
git commit -m "feat: add your feature description"
```

Follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `refactor:` Code refactoring
- `style:` Code style changes
- `chore:` Build/tooling

### 6. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## IDE Setup

### VS Code (Recommended)

1. **Install Extensions**:
   - Python
   - Pylance
   - Ruff
   - Black Formatter
   - MCP Inspector

2. **Settings** (`.vscode/settings.json`):
```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/venv/bin/python",
  "python.testing.pytestEnabled": true,
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  },
  "[python]": {
    "editor.defaultFormatter": "ms-python.black-formatter"
  }
}
```

### PyCharm

1. **Set Interpreter**: File → Settings → Project → Python Interpreter → Add → Existing environment → Select `venv/bin/python`
2. **Enable Tools**: Settings → Tools → Black, Mypy, Pytest
3. **Run Configurations**: Create pytest run configuration

## Running Tests

### Run All Tests
```bash
pytest
```

### Run Specific Test
```bash
pytest tests/test_server.py::test_list_interfaces
```

### Run with Coverage
```bash
pytest --cov=mcp_wireshark --cov-report=html
```

### Run in Watch Mode
```bash
pip install pytest-watch
ptw
```

## Debugging

### VS Code Debugging

Create `.vscode/launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: Current File",
      "type": "python",
      "request": "launch",
      "program": "${file}",
      "console": "integratedTerminal"
    },
    {
      "name": "Pytest: Current File",
      "type": "python",
      "request": "launch",
      "module": "pytest",
      "args": ["${file}", "-v"],
      "console": "integratedTerminal"
    },
    {
      "name": "MCP Server",
      "type": "python",
      "request": "launch",
      "module": "mcp_wireshark.cli",
      "console": "integratedTerminal"
    }
  ]
}
```

### Command Line Debugging

```bash
# Use pdb
python -m pdb examples/basic_usage.py

# Or add breakpoint in code
import pdb; pdb.set_trace()
```

## Common Tasks

### Update Dependencies
```bash
pip install --upgrade -e ".[dev]"
```

### Clean Build Artifacts
```bash
rm -rf build/ dist/ *.egg-info __pycache__ .pytest_cache .mypy_cache .ruff_cache
```

### Sync with Upstream
```bash
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

## Getting Help

- **GitHub Discussions**: Ask questions
- **GitHub Issues**: Report bugs, request features
- **Discord/Slack**: Join community channels (if available)

## Resources

- [MCP Documentation](https://modelcontextprotocol.io/)
- [Wireshark Docs](https://www.wireshark.org/docs/)
- [Python Packaging](https://packaging.python.org/)
- [Pytest Docs](https://docs.pytest.org/)
