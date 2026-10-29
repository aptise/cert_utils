# Typing and call signature audit

Initial audit: 2026-10-27. The findings and baseline below describe the original
state. See the 2026-10-28 resolution notes at the end for implemented fixes.

## Findings, in priority order

1. **Incorrect verification return contract.** `core.account_key__verify` declares
   `bytes`; the Cryptography `verify()` calls return `None` on success and raise
   on invalid signatures. Its docstring instead promises `bool`. The fallback
   raises `ValueError("not supported yet")`. Annotate the implemented success
   result as `None`, document the exception contract/backend requirement, and
   test success and invalid signatures explicitly. The existing signing test
   assigns the verification result without asserting its value.

2. **CLI ignores its explicit argument.** `scripts.cert_info.main(argv)` checks
   the supplied list length but reads the target from `sys.argv[1]`. Calls from
   another program can select the wrong target or raise `IndexError`. Use the
   supplied arguments consistently; consider `Optional[List[str]] = None` to
   resolve the process arguments at call time. Add tests with process arguments
   different from the explicit argument list.

3. **Public-key types admit private keys.** `parse_key__spki_sha256(publickey=...)`
   and `_cryptography__public_key_spki_sha256` allow RSA/EC private-key instances
   through `_TYPES_CRYPTOGRAPHY_KEYS`, but the helper directly calls
   `public_bytes()`. Private keys do not provide that method. Restrict the hint
   to public keys, or explicitly normalize private keys with `.public_key()`.
   The extended public-key union also lags current Cryptography's certificate
   and CSR public-key return types: mypy reports mismatches at the two callers.
   Prefer a narrowly scoped structural protocol for SPKI serialization if
   compatibility across Cryptography versions is required; do not add runtime
   Cryptography imports just to resolve annotations.

4. **Legacy integer constants disagree with key-generation annotations.**
   `new_account_key` and `new_private_key` accept `KeyTechnology.RSA/EC` integers
   at runtime, but annotate only `KeyTechnologyEnum.RSA/EC`. Their docstrings
   advertise integers. Decide whether both are public supported inputs, then
   share that type with `NewKeyArgs`. Preserve existing positional parameter
   order. `KeyTechnology.to_new_args(id_)` also lacks an input annotation.
   `new_private_key` documents defaults that disagree with its signature
   (`rsa_bits=2048`, `ec_curve="P-384"`).

5. **Untyped boundaries conceal errors.** `account_key__sign(data)` and
   `account_key__verify(signature, data)` accept strings or bytes in their
   implementations; annotate those inputs as `Union[str, bytes]`.
   `_check_fallback` lacks a return annotation and mixes integer/string/None
   results. `AccountKeyData.__init__` lacks `-> None`. The CLI has untyped hook
   variadics, `_print`, and `usage` arguments; `usage` should return `NoReturn`
   and `main` should return `None`. AST review found nine function definitions
   with at least one missing argument or return annotation.

6. **Structured results erase useful types.** `parse_cert`, `parse_csr`, and
   `parse_key` expose bare `Dict` return types. `account_key__parse` exposes a
   bare JWK `Dict`; the model's JWK field does too. Define distinct `TypedDict`
   results after checking both backend paths and nullable fields. Avoid
   tightening `parse_key` beyond its documented installation-dependent output.
   Bare `Tuple`, `List`, and `Callable` annotations elsewhere also introduce Any.

7. **Python 3.7 CLI import compatibility.** `scripts.cert_info` imports
   `TypedDict` from `typing`, which only provides it starting in Python 3.8.
   The package advertises Python 3.7; use the existing `typing_extensions`
   dependency here. Validate the entry point on the supported version matrix.

8. **Backend contracts need explicit parity tests.** `validate_csr` documents
   raising for invalid input but its Cryptography path returns the
   `is_signature_valid` boolean (which can be `False`). `ensure_chain` uses
   `build_client_verifier()` with Cryptography and `openssl verify -purpose
   sslserver` in the subprocess path. These select different certificate
   purposes despite sharing a signature. Define the intended validation
   contract before changing either path; test invalid signatures and
   client/server extended-key-usage cases on both backends.

## Typing baseline and scope

The migrated mypy settings preserve `check_untyped_defs` and existing missing
import overrides. They do not enable strict checking. Optional dependencies
are deliberately loaded through module-valued conditional imports; this leaves
many calls dynamically typed, so a passing mypy run alone would not establish
correct backend contracts. Review existing `type: ignore` comments with focused
backend tests before removing them.

On Python 3.14 with mypy 2.4.0, Cryptography 50.0.1, pyOpenSSL 26.4.0, and the testing dependencies,
`python -m mypy src tests` reports **23 errors in two files**: two SPKI argument
mismatches in `core.py`, and 21 errors in the historical fixture-generation
script `tests/test_data/unit_tests/cert_001/test.py`. Keep these visible for now;
consider a separate documented checking scope for fixture-generation scripts.
The initial run without dependencies also reported missing stubs/imports;
those environment errors are not counted as source defects.

## Configuration changes

- Metadata, dependencies, package discovery, typed marker, and console script
  moved into `setup.cfg`; `setup.py` now only invokes setuptools.
- Mypy and tox moved into `pyproject.toml`. Tox uses its embedded INI format to
  remain usable with older tox releases on Python 3.7. Corrected `py13` to
  `py313` and supplied dedicated commands for the listed lint/mypy environments.
- Pytest now records package line and branch coverage, generating terminal,
  HTML and XML reports. No coverage threshold is enforced. Reports are ignored
  by Git and uploaded by CI even when a test fails.
- The existing Python support declaration, runtime dependencies, optional
  Cryptography behavior, version, and script name are preserved. Removed the
  obsolete setuptools `tests_require`/`test_suite` interface; use `[testing]`
  and pytest instead. Corrected the package summary spelling.

Validation builds both an sdist and wheel; the wheel includes `py.typed` and
`cert_info`. The supported Python/OpenSSL matrix still requires CI; local runs
use Python 3.14 and OpenSSL 3.6.4 only. Newly wired lint reports 12 existing
style/unused-global findings; runtime source was not reformatted for this audit.

## Test and coverage baseline

Command: `CERT_UTILS_EXTENDED_TESTS=1 python -m pytest -q` in a temporary test
virtual environment. Result: **129 passed, 12 failed**, 141 collected, about six
minutes. Reports were generated despite failures.

| Measurement | Result |
| --- | ---: |
| Covered executable lines | 1,562 / 2,243 (69.64%) |
| Covered branches | 402 / 772 (52.07%) |
| Combined terminal coverage | 65% |

The 12 failures consist of four chain-validation cases, six fallback key
parse/generation cases, and two fallback CSR-generation cases. The native
chain failures report certificates invalid at the current validation time;
the fallback chain failures report OpenSSL verification errors. Fallback key
handling rejects the current OpenSSL success message `EC Key valid.\n` because
it expects `read EC key\nEC Key valid.\n`. CSR errors discard stderr, preventing
a precise diagnosis from the traceback alone. Commands interpolate file paths
without quoting; paths containing spaces, as in this checkout, need a focused
regression test. These are runtime follow-ups; coverage collection does not
suppress or fix them.

Prioritize these coverage gaps:

| Area | Line coverage | Branch coverage | Follow-up |
| --- | ---: | ---: | --- |
| CLI (`scripts/cert_info.py`) | 0% | 0% | Explicit argv, file/URL dispatch, mocked HTTP/socket handling |
| Let’s Encrypt information helpers | 0% | 0% | Mock downloads and error responses |
| Model | 54.69% | 0% | Key mappings, reverse lookups, invalid IDs, account data |
| Core | 78.24% | 58.22% | Chain ordering, invalid inputs, settings, subprocess errors |
| OpenSSL adapter | 83.33% | 63.24% | Output/version differences and failure handling |

Deprecated adapters also have 0% coverage and remain in the denominator to make
the baseline transparent. Some uncovered paths follow early failures, so this
is a baseline for this environment rather than a complete backend/version
assessment. The suite simulates optional dependencies being unavailable; it
does not replace fresh-process tests without those dependencies installed.

Local report: `htmlcov/index.html`; machine-readable report: `coverage.xml`.
No new tests or runtime changes were introduced to inflate this baseline.


## Resolution — 2026-10-28

- Removed setup.py; the setuptools PEP 517 backend builds from setup.cfg.
- Corrected verification return/input types, CLI argv handling and Python 3.7
  TypedDict imports. Public-key serialization uses a structural protocol.
- Annotated remaining function boundaries, accepted legacy integer technology
  constants, corrected key defaults in docstrings, and introduced typed
  certificate, CSR and diagnostic key result mappings plus string-valued JWKs.
- Modernized the historical RSA fixture inspection script rather than excluding
  its type errors. Flake8 now checks src/tests without the removed setup.py.
- CSR creation uses subprocess argument lists in both OpenSSL modes; success
  checks use return codes and failures retain diagnostic output. EC checks
  accept modern and legacy success messages.
- Chain validation defaults to server purpose consistently. Client purpose and
  a specific server hostname can be selected explicitly. Historical validation
  accepts an explicit validation_time; ordinary calls retain current-time
  expiry checks. Fixture tests use 2024-01-01, within their validity windows.
- Chain ordering compares issuer/subject adjacency on both backends; it does
  not establish trust or check expiry. Use ensure_chain for trust validation.
- Invalid CSR signatures raise consistently. Verification and CLI regression
  tests, expiry checks and hostname rejection tests cover the changed contracts.

Coverage gaps listed above remain test-development opportunities; no coverage
threshold has been introduced. Optional-library-free fresh-process testing and
older Python/OpenSSL versions still require the CI/environment matrix.

Final local validation: 148 tests passed in the extended suite. Seven contract
regression tests also passed against the finished source, including two new
client-purpose cases (150 distinct tests across the runs). Mypy passes all 23
source/test files and flake8 passes src/tests. Both wheel and sdist build without
setup.py; the wheel retains py.typed and cert_info. pyOpenSSL is now explicitly
included in the testing extra for checks of the optional legacy adapter.

Combined coverage after appending the final contract tests: 1,674 / 2,267 lines
(73.84%), 444 / 782 branches (56.78%), 69% combined terminal coverage. HTML and
XML reports have been regenerated. These remain reports with no minimum gate.
