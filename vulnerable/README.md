# Vulnerable baseline (do not deploy)

The pre-remediation infrastructure, kept so the before/after can be reproduced:

```sh
python3 scan.py vulnerable/   # flags F-01 … F-07, F-09, F-11, F-12 and F-13, exits 1
python3 scan.py .             # hardened root, exits 0
```

These files are a test fixture for `scan.py`. They are intentionally insecure and are
excluded from Checkov in CI.
