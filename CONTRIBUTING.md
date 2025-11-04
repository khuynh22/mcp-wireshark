# Contributing to MCP Wireshark

Thank you for your interest in contributing to mcp-wireshark! This document provides guidelines for contributing to the project.

## Development Setup

1. Fork and clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/mcp-wireshark.git
cd mcp-wireshark
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

4. Install Wireshark/tshark for testing:
   - macOS: `brew install wireshark`
   - Ubuntu: `sudo apt-get install tshark`
   - Windows: Download from wireshark.org

## Code Style

This project follows strict code quality standards:

- **Black** for code formatting (line length: 100)
- **Ruff** for linting
- **Mypy** for type checking
- **Pytest** for testing

Run quality checks before submitting:

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

## Testing

Write tests for new features and bug fixes. Tests should:

- Be placed in the `tests/` directory
- Use pytest fixtures where appropriate
- Achieve good code coverage
- Test both success and error cases

Run tests with coverage:

```bash
pytest --cov=mcp_wireshark --cov-report=html
```

## Pull Request Process

1. Create a new branch for your feature/fix:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes and commit with clear messages:
```bash
git commit -m "Add feature: description"
```

3. Push to your fork:
```bash
git push origin feature/your-feature-name
```

4. Open a Pull Request with:
   - Clear description of changes
   - Reference to related issues
   - Test coverage for new code

## Adding New Tools

To add a new MCP tool:

1. Add the tool definition to `list_tools()` in `server.py`
2. Implement the handler function (e.g., `handle_your_tool()`)
3. Add the handler to `call_tool()`
4. Write tests in `tests/test_server.py`
5. Update documentation in `README.md` and `docs/API.md`

## Documentation

Update documentation for:

- New features or tools
- API changes
- Configuration options
- Examples

Documentation files to update:
- `README.md` - User-facing documentation
- `docs/API.md` - API reference
- `examples/` - Usage examples

## Commit Messages

Follow conventional commit format:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `style:` Code style changes
- `chore:` Build/tooling changes

Example:
```
feat: add support for PCAPNG format
fix: handle empty pcap files gracefully
docs: update installation instructions
```

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Maintain professional communication

## Questions?

Feel free to open an issue for:
- Bug reports
- Feature requests
- Questions about contributing
- General discussions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
