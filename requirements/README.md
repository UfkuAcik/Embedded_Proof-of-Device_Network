# Python CI dependency lock

`ci.lock` contains the complete Python CI dependency graph with exact versions
and distribution hashes. CI installs it with `--require-hashes`, then installs
the three local packages with dependency resolution disabled.

Regenerate deliberately with Python 3.11 and pip-tools 7.6.0:

```bash
python -m pip install "pip-tools==7.6.0"
python -m piptools compile \
  --allow-unsafe \
  --generate-hashes \
  --resolver=backtracking \
  --strip-extras \
  --output-file requirements/ci.lock \
  requirements/ci.in
```

Review the entire diff and rerun the Python tests plus `pip-audit` before
accepting an update.
