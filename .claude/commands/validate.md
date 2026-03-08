Run the full quality check suite for this project and report results.

Use the Python from miniconda (`C:/Users/khang/miniconda3/python.exe`) since the venv Python is broken.

Run these four checks **sequentially** (each must pass before the next):

```bash
C:/Users/khang/miniconda3/python.exe -m black src tests
C:/Users/khang/miniconda3/python.exe -m black --check src tests
C:/Users/khang/miniconda3/python.exe -m ruff check src tests
C:/Users/khang/miniconda3/python.exe -m mypy src
C:/Users/khang/miniconda3/python.exe -m pytest
```

For each step:
- If it **passes**: report "✓ black / ruff / mypy / pytest" and continue
- If it **fails**: show the error output, fix the issue, then re-run that step before moving on

After all checks pass, print a summary:
```
All checks passed:
  ✓ black   — formatting ok
  ✓ ruff    — no lint errors
  ✓ mypy    — no type errors
  ✓ pytest  — N tests passed
```

If any check cannot be fixed automatically (e.g. a logic bug in a test), explain what the user needs to do manually and stop.

Do not commit. Only validate.
