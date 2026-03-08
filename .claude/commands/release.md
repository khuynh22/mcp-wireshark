Cut a new release for mcp-wireshark. Follow these steps exactly.

## Step 1 — Determine bump type

Ask the user: "patch, minor, or major?"

- **patch** (0.1.x): bug fixes, security fixes, no new tools, no API changes
- **minor** (0.x.0): new tools, new optional parameters, new features — backwards compatible
- **major** (x.0.0): removed tools, changed required params, breaking output format changes

## Step 2 — Confirm what's changed

Run:
```bash
git log --oneline $(git describe --tags --abbrev=0)..HEAD
```

Show the commits to the user and ask them to confirm the bump type makes sense.

## Step 3 — Bump version

Update the version string in **both** files:
- `pyproject.toml` → `version = "X.Y.Z"`
- `src/mcp_wireshark/__init__.py` → `__version__ = "X.Y.Z"`
- `mcp.json` → `"version": "X.Y.Z"`

## Step 4 — Run full validation

Run `/validate` (all four checks must pass). Do not proceed if any check fails.

## Step 5 — Commit and tag

```bash
git add pyproject.toml src/mcp_wireshark/__init__.py mcp.json
git commit -m "chore: bump version to X.Y.Z"
git tag vX.Y.Z
git push && git push --tags
```

## Step 6 — Remind about PyPI

Tell the user:
```
Version X.Y.Z is tagged and pushed. The auto-release CI will run.
To publish to PyPI manually:
  python -m build
  twine upload dist/*
```

Do not push to PyPI automatically. That is a manual step the user controls.
