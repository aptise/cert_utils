Contributing
============

Code Requirements - General
* typing and mypy is required
* pre-commit is used to integrate black formatting

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
configuration path works around tox 4.30.x configuration discovery, which can
select the packaging-only setup.cfg and fail with `section tox:tox not found`.
Keep the configuration in pyproject.toml; do not add a placeholder tox section
to setup.cfg, which would select an incomplete configuration.
