Trigger a release for mcp-wireshark.

The CI handles everything automatically — no manual version bumping needed.

## How it works

1. The PR must have exactly one of these labels before merging:
   - `release:patch` → 0.1.x (bug fixes, security fixes, no new tools)
   - `release:minor` → 0.x.0 (new tools, new optional params, backwards-compatible)
   - `release:major` → x.0.0 (removed tools, changed required params, breaking changes)

2. When the PR is merged to `main`, `auto-release.yml` automatically:
   - Bumps the version in `pyproject.toml`, `src/mcp_wireshark/__init__.py`, and `mcp.json`
   - Commits the bump as `chore: bump version to X.Y.Z`
   - Creates and pushes a `vX.Y.Z` git tag
   - Builds and publishes to PyPI
   - Creates a GitHub Release with auto-generated release notes
   - Sends an email notification

## What to tell the user

Ask: "Does the current PR need a release? If so, which type: patch, minor, or major?"

Then tell them:
- Add the appropriate `release:patch / release:minor / release:major` label to the PR on GitHub before merging
- After merging, the CI takes 2–3 minutes and handles everything
- They can watch progress at: https://github.com/khuynh22/mcp-wireshark/actions

## If no label is added

The PR merges cleanly with no version bump. The change ships in the next release whenever they add a label to a future PR.

## Manual fallback

If auto-release failed, use the "Manual Release" workflow on GitHub Actions — it takes a version string and publishes that exact tag to PyPI.
