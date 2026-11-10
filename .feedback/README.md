# Feedback task starting environment

Upstream: https://github.com/paramiko/paramiko
Upstream commit: `0e9ccb91e0f9a68f2587233d523ad7fe46e730fe`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_message.py tests/test_hostkeys.py tests/test_kex.py tests/test_config.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-10): `146 passed, 7 skipped, 1 warning, 13 subtests passed in 0.58s`
Whole-command wall time: 2.710 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
