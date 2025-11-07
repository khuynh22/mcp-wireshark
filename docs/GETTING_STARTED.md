# Getting Started with MCP Wireshark

## 🎯 **What You Need to Know**

This guide will help you:
1. ✅ **Test locally** - Make sure everything works on your machine
2. 🚀 **Publish to PyPI** - Let others install via `pip install mcp-wireshark`
3. 🌐 **Host remotely** - Make it accessible from other machines
4. 🤝 **Enable contributions** - Make it easy for others to contribute

---

## 📝 **STEP 1: Local Testing (Start Here!)**

### Test the Package Locally

```powershell
# Navigate to your project
cd c:\src\mcp-wireshark

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Try the CLI
mcp-wireshark
```

### Test with Claude Desktop

1. **Find your Claude config file**: `%APPDATA%\Claude\claude_desktop_config.json`

2. **Add this configuration**:
```json
{
  "mcpServers": {
    "wireshark": {
      "command": "C:\\src\\mcp-wireshark\\venv\\Scripts\\mcp-wireshark.exe",
      "args": [],
      "env": {}
    }
  }
}
```

3. **Restart Claude Desktop** and test with:
   - "List network interfaces"
   - "Read a pcap file from [path]"

---

## 📦 **STEP 2: Publish to PyPI**

### One-Time Setup

1. **Create PyPI accounts**:
   - Production: https://pypi.org/account/register/
   - Testing: https://test.pypi.org/account/register/

2. **Generate API tokens**:
   - PyPI → Account Settings → API tokens → "Add API token"
   - Save the token securely!

3. **Install build tools**:
```powershell
pip install build twine
```

### Publishing Process

See **[docs/PUBLISHING.md](PUBLISHING.md)** for the complete guide. Quick version:

```powershell
# 1. Update version in pyproject.toml
# [project]
# version = "0.1.0"  # Change this!

# 2. Build the package
python -m build

# 3. Test on TestPyPI first
twine upload --repository testpypi dist/*

# 4. If it works, publish to real PyPI
twine upload dist/*
```

### Automated Publishing

The project includes GitHub Actions that auto-publish when you create a release:

1. Go to GitHub → Releases → "Draft a new release"
2. Create tag: `v0.1.0`
3. Click "Publish release"
4. GitHub Actions automatically publishes to PyPI!

**Setup required**: Add `PYPI_API_TOKEN` to GitHub Secrets (Settings → Secrets and variables → Actions)

---

## 🌐 **STEP 3: Host Remotely**

### Option A: Run as a Service (Windows)

Create a Windows service using NSSM or Task Scheduler:

```powershell
# Using Task Scheduler
# 1. Open Task Scheduler
# 2. Create Basic Task
# 3. Trigger: At startup
# 4. Action: Start program
# 5. Program: C:\src\mcp-wireshark\venv\Scripts\python.exe
# 6. Arguments: -m mcp_wireshark.cli
```

### Option B: Docker Container

Create `Dockerfile`:
```dockerfile
FROM python:3.11-slim

# Install tshark
RUN apt-get update && \
    apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

# Copy project
WORKDIR /app
COPY . .

# Install package
RUN pip install .

# Run server
CMD ["mcp-wireshark"]
```

Build and run:
```bash
docker build -t mcp-wireshark .
docker run -it mcp-wireshark
```

### Option C: Cloud Deployment

**AWS EC2 / Azure VM / Google Compute Engine:**

1. Create a VM (Ubuntu recommended)
2. Install dependencies:
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip tshark
pip install mcp-wireshark
```

3. Run as systemd service:
```bash
sudo nano /etc/systemd/system/mcp-wireshark.service
```

```ini
[Unit]
Description=MCP Wireshark Server
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/home/your-user
ExecStart=/usr/local/bin/mcp-wireshark
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable mcp-wireshark
sudo systemctl start mcp-wireshark
```

### Remote Access Configuration

**For remote clients to connect**, you'll need to modify the server to support TCP/HTTP instead of stdio. This requires:

1. Update `server.py` to use TCP server
2. Add authentication/security
3. See MCP documentation: https://modelcontextprotocol.io/

**Note**: The current implementation uses stdio (standard input/output), designed for local use. For true remote hosting, you'll need to implement HTTP/SSE transport.

---

## 🤝 **STEP 4: Enable Contributions**

### What's Already Done ✅

Your project already has:
- ✅ `CONTRIBUTING.md` - Contribution guidelines
- ✅ `LICENSE` - MIT License
- ✅ `pyproject.toml` - Package configuration
- ✅ GitHub Issue templates (bug reports, feature requests)
- ✅ GitHub PR template
- ✅ CI/CD workflows
- ✅ Pre-commit hooks
- ✅ Code quality tools (Black, Ruff, Mypy)
- ✅ Comprehensive documentation

### Make Your First Release

1. **Push to GitHub** (if not already):
```powershell
git add .
git commit -m "docs: add publishing and development guides"
git push origin main
```

2. **Create a Release**:
   - Go to GitHub → Releases → "Draft a new release"
   - Tag: `v0.1.0`
   - Title: `v0.1.0 - Initial Release`
   - Description: Copy from `CHANGELOG.md`
   - Check "This is a pre-release" if not stable
   - Click "Publish release"

3. **Add Topics to Repository**:
   - Go to GitHub → About → Settings ⚙️
   - Add topics: `mcp`, `wireshark`, `network-analysis`, `packet-capture`, `python`, `ai-tools`

4. **Create a Good README** ✅ (Already done!)

5. **Enable GitHub Discussions**:
   - Settings → Features → Discussions → Enable

6. **Add a Code of Conduct**:
```powershell
# GitHub provides templates
# Settings → Community Standards → Add Code of Conduct
```

### Promote Your Project

After publishing:
- Post on Reddit: r/Python, r/networking, r/sysadmin
- Tweet about it with hashtags: #Python #Wireshark #MCP
- Share on Hacker News
- Write a blog post
- Create a demo video
- Add to awesome-mcp lists

---

## 🎓 **Quick Reference**

### Daily Development Workflow

```powershell
# Start developing
git checkout -b feature/my-feature
# Make changes...
black src tests              # Format
ruff check --fix src tests   # Lint
mypy src                     # Type check
pytest                       # Test
git commit -m "feat: my feature"
git push origin feature/my-feature
# Create PR on GitHub
```

### Before Publishing New Version

```powershell
# Run all checks
pytest --cov=mcp_wireshark
black src tests
ruff check src tests
mypy src

# Update version in pyproject.toml
# Update CHANGELOG.md

# Build and publish
python -m build
twine upload dist/*
```

### Testing Installation

```powershell
# Create fresh environment
python -m venv test-env
.\test-env\Scripts\Activate.ps1
pip install mcp-wireshark
mcp-wireshark
```

---

## 📚 **Complete Documentation**

- **[README.md](../README.md)** - Project overview and usage
- **[QUICKSTART.md](QUICKSTART.md)** - Quick start guide
- **[API.md](API.md)** - API reference
- **[DEVELOPMENT.md](DEVELOPMENT.md)** - Developer setup guide
- **[PUBLISHING.md](PUBLISHING.md)** - PyPI publishing guide
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - How to contribute
- **[CHANGELOG.md](../CHANGELOG.md)** - Version history

---

## ❓ **FAQ**

### Q: Can people install it now?
**A:** Not yet! You need to publish to PyPI first (see Step 2).

### Q: How do I update after publishing?
**A:** Increment version in `pyproject.toml`, rebuild with `python -m build`, and re-upload with `twine upload dist/*`.

### Q: Do users need Wireshark installed?
**A:** Yes, they need to install Wireshark/tshark separately. It's documented in the README.

### Q: How do I test changes before publishing?
**A:** Use `pip install -e .` for editable install, or publish to TestPyPI first.

### Q: Can this run on a server?
**A:** The current version uses stdio (local only). For remote access, you'd need to implement HTTP/SSE transport as per MCP spec.

---

## 🆘 **Need Help?**

- **GitHub Issues**: Report bugs or request features
- **GitHub Discussions**: Ask questions
- **Email**: [Your email if you want]

---

## ✅ **Checklist**

Before going public:
- [ ] All tests pass locally
- [ ] Documentation is complete and accurate
- [ ] Examples work
- [ ] Code is formatted and linted
- [ ] Version number is set
- [ ] CHANGELOG is updated
- [ ] PyPI account created
- [ ] API token generated
- [ ] Published to TestPyPI successfully
- [ ] Published to PyPI successfully
- [ ] GitHub release created
- [ ] README badges updated
- [ ] Project promoted

**You're ready to launch! 🚀**
