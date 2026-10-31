# cert_info v1.3 implementation

Scope: approved CLI operations, Certbot renewal discovery and private per-root
metadata caching. Branch: feature-cert-info-discovery. No commits.

Changed areas: scripts/cert_info.py, new scripts/discovery.py, CLI/discovery tests,
and CHANGES.txt. New source and test files are staged as required by workspace
instructions; existing files remain unstaged.

Decisions: 300-second TTL; ~/.cert_utils cache; raw byte identity;
--no-cache overrides refresh; all adds path/public-key correlation.
Certbot renewal/ and alternate renewals/ directories are supported.

Completed checks: 64 focused tests passed (/tmp/cert-utils-focused.log);
changed-source typing passed (/tmp/cert-utils-typing.log); syntax and diff checks.
Combined regression completed: 293 passed, 54 skipped in 700.73 seconds
(/tmp/cert-utils-regression.log), including broader modes and CLI precedence.

Next action: user code review. No remaining implementation blockers. No documentation audit, installs, or commits authorized.
