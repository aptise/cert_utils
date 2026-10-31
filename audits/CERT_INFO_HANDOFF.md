# Actions and modulus deprecation handoff

Scope: approved action upgrades, public modulus API deprecation, and SPKI TODOs.
Branch: feature-actions-modulus-deprecation. No commits.

Changed: core-tests.yml pins checkout v7.0.1, setup-python v7.1.0 and
upload-artifact v7.0.2 (verified upstream release pages). Migration notes checked:
Node 24 requires runner >=2.327.1; existing GitHub-hosted Ubuntu jobs and workflow
inputs/triggers need no changes. Hosted execution remains for CI.

core.py: modulus_md5_key/csr/cert emit caller-directed DeprecationWarning and
document existing parse_key/csr/cert__spki_sha256 replacements. Results and
signatures preserved. Internal modulus cleanup is retained without warnings.
TODO.txt: appended relationship regression and legacy modulus-field migration
follow-ups; no missing standalone SPKI hash API was found. CHANGES.txt updated.

Completed: workflow YAML/reference validation, diff checks, formatting,
and typing of core.py/new test passed (/tmp/cert-utils-modulus-typing.log).
Selected native/OpenSSL modulus and parsing regression tests completed:
28 passed, 20 skipped, 99 deselected, 60 expected deprecation warnings in
337.68 seconds (/tmp/cert-utils-modulus-tests.log).

Next: user review and GitHub-hosted CI verification. No implementation blockers.
No installs, full-suite run, or general documentation audit performed.
