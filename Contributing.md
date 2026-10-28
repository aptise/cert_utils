Contributing
============

Code Requirements - General
* typing and mypy is required
* Run `python -m black src tests` after every Python edit, before verification.
  pre-commit also runs Black using the project configuration.
* Keep text literals readable: use one literal for short text and complete URLs.
  Wrap long prose only at natural phrase boundaries, never into word-sized
  fragments or arbitrary character slices. Preserve intentional regex structure
  and line-oriented messages when they improve readability.

Code Requirements - Style
* for fallback oprations, parse required args before invoking `check_openssl()`


Code of Conduct
---------------

Adherence to standard codes of conduct is expected and required.

Please see the current policy outlined in: CODE_OF_CONDUCT.md



Running tests and reports
-------------------------

Install the test dependencies with `python -m pip install -e '.[testing]'`.
Run `python -m pytest` for the default suite, or
`CERT_UTILS_EXTENDED_TESTS=1 python -m pytest` to include the existing extended
backend tests (also enabled by tox). Pytest generates terminal coverage with
missing lines, `htmlcov/index.html`, and `coverage.xml`, including branch coverage.
Coverage is informational: there is no minimum coverage requirement.
Use `python -m pytest --no-cov` when coverage is not needed.

Mypy, pytest, coverage, and tox configuration live in `pyproject.toml`.
Run `tox -c pyproject.toml -e mypy` for typing or `tox -c pyproject.toml -e lint` for style checks. Packaging metadata
and dependencies live in `setup.cfg`. Builds use the setuptools backend declared in `pyproject.toml`.

Use `tox -c pyproject.toml -e py` to run the test environment. The explicit
configuration path works around a tox 4.30.3 discovery bug in the Python 3.9
CI job: that is the newest tox available for Python 3.9, and it can select the
packaging-only setup.cfg and fail with `section tox:tox not found`.
When Python 3.9 support is removed, remove the `-c pyproject.toml` workaround
from the CI and contributor commands (after checking the remaining tox versions).
Keep the configuration in pyproject.toml; do not add a placeholder tox section
to setup.cfg, which would select an incomplete configuration.
