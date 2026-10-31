# cert_info Python 3.7 test compatibility

Scope: fix test_cli_cache_precedence's mock argument inspection.
Branch: fix-py37-discovery-test. No commits.

Changed: tests/test_discovery.py uses call_args[0] instead of the .args
property added in Python 3.8. CHANGES.txt records the compatibility fix.
The user's discovery-module relocation is preserved.

Validation: focused test passed on the existing Python 3.14 environment
(1 passed); git diff --check passed. Log: /tmp/cert-utils-py37-test-fix.log.
Python 3.7 is unavailable locally, so no Python 3.7 execution is claimed.

Next action: user review and Python 3.7 CI verification. No blockers to review.
