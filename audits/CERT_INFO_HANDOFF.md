# Validation and SPKI follow-ups

Branch: feature-validation-spki-followups. Scope: two active TODO sections and
untracking local audit notes. No commits.

Changes: new tests/test_validation_spki.py covers malformed/wrong-object PEM,
altered CSR signatures, cross-object RSA/EC SPKI identity, unrelated keys,
native/OpenSSL parity, and retained parse_key modulus fields. Existing keys
are reused; local short-lived certificates are generated without network.
core.py/model.py document modulus_md5 field deprecation and SPKI migration;
obsolete EC modulus TODO replaced. Completed TODO sections removed; deferred
notes untouched. CHANGES.txt updated.

Audits: all three formerly tracked files removed from Git's index, retained
on disk. /audits/ added to .gitignore. This handoff stays local.

Checks: 30 tests passed (/tmp/cert-utils-validation-spki.log); after adding
legacy-field assertions, affected 4 tests passed (/tmp/cert-utils-spki-field.log).
Typing passed for all 3 changed source/test files
(/tmp/cert-utils-followups-typing.log). Diff check passed.
Next: user review. No full-suite run or installs.
