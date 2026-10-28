# Follow-up audit — 2026-10-28

Scope: review of the CLI, backend boundaries, conditional dependencies,
subprocess invocations, packaging and the earlier audit resolutions. This is a
source review and local validation, not a full security assessment or evidence
of compatibility with every supported Python/OpenSSL release.

## Original findings (see maintainer clarification and resolution below)

1. **Profile context clarified; general-X509 contract question.**
   `core.ensure_chain` selects the first name from
   `_cryptography__cert_or_req__all_names` when no explicit server hostname is
   supplied. That helper puts the common name before SAN entries. A certificate
   with a common name absent from its SANs can therefore fail the Python
   verifier even though its SAN identity is valid; the OpenSSL path performs
   no hostname check by default. IP-only certificates also require deliberate
   handling rather than always constructing a DNSName. Define whether this API
   validates a particular peer identity or just the chain; add SAN/CN mismatch
   and IP SAN parity cases before changing that contract. Supplying an explicit
   DNS server_hostname avoids the implicit selection issue for DNS callers.
   Evidence: src/cert_utils/core.py, lines 2416–2422;
   src/cert_utils/compat/cryptography.py, lines 107–131.

2. **Resolved: missing timeouts and owned-session cleanup.**
   The CLI's ARI and URL requests and the certificate-download helper omit
   timeouts. A stalled endpoint can hang the command indefinitely. ari_query
   and process_url create sessions without closing them on success or failure.
   Add a documented timeout and use context managers for sessions owned by
   these functions; retain caller ownership in process_ari_url. Tests should
   cover timeout propagation and cleanup after errors.
   Evidence: src/cert_utils/scripts/cert_info.py, functions process_ari_url,
   ari_query and process_url; src/cert_utils/letsencrypt_info.py, line 768.

3. **Intentional compatibility design: historical socket-layout probes.**
   Five layouts are now tested, along with HTTP sockets, missing sockets and
   cached results. Those tests establish current behavior but cannot guarantee
   future requests/urllib3 compatibility. Missing peer information now returns
   gracefully instead of crashing the CLI. Consider an explicit diagnostic
   when extraction fails, and compatibility tests against supported requests
   and urllib3 releases.
   Evidence: src/cert_utils/scripts/cert_info.py, get_response_data.

## Changes completed in this pass

- Added 40 offline CLI tests covering command/module dispatch, usage errors,
  all five socket layouts, cached/missing peer data, HTTP/TLS sockets, response
  hooks, headers, issuer discovery, ARI directory/response/error handling, and
  file/URL processing. All network operations are mocked.
- Removed issuer position assumptions, handled missing peer information,
  corrected the module entry point, and handled an empty explicit argv list.
- ARI responses now check HTTP status, and renewal URLs avoid doubled slashes.
- Moved the unused compat/deprecated.py helper verbatim (apart from its import
  path) into docs/openssl-reference.md as a fenced Python example. No runtime
  callers were found. Documentation is linked from README and included in the
  source distribution.

## Validation

40 CLI tests pass. The CLI module has 100% executable-line and branch coverage
in the focused report. Mypy passes all 22 source/test files after removal of the
reference module; flake8 passes src/tests. The coverage report from this run is
CLI-focused, not a new package-wide baseline; its low package total includes
unexercised modules and should not be compared to the earlier full-suite total.

No source outside the CLI was changed in this pass. Full backend/version-matrix
validation remains a CI task. The prior full-suite results remain recorded in
AUDIT.md rather than being presented as a fresh complete-suite run.

## Maintainer clarification and resolution

The hostname finding above needs profile context: valid Let's Encrypt classic
CNs are also SANs, while tlsserver/shortlived certificates omit CNs. The existing
helper already falls back to SANs when CN is absent. No hostname policy or CSR
CN behavior was changed in response to the audit. Generic X509/IP identity
semantics remain a separate design topic, not a reason to enforce classic
issuance policy on all certificates. See docs/compatibility.md and its primary
source link for profile details.

The peer hook/probes are intentional and retained. Requests' public response
hook provides the timing required for metadata extraction; historical storage
probes bridge the missing upstream socket API. Reclassified as a documented
compatibility constraint, not a requested redesign.

The timeout/session finding is addressed: default connect/read timeouts are
5/30 seconds, overridden by CERT_UTILS_TIMEOUT=CONNECT,READ or --timeout
CONNECT,READ. Explicit arguments take precedence, including across ARI lookup
requests. Positive finite values are required. Sessions created by CLI helpers
close on success and exception; supplied sessions remain caller-owned.


Timeout validation: 58 focused tests pass, including configuration precedence,
invalid/zero/negative/nonfinite timeouts, per-request positional/keyword
compatibility, ARI propagation, download requests, and session cleanup on
success and timeout exceptions. Both scripts/cert_info.py and network.py have
100% line and branch coverage in this focused run. Mypy passes 23 files and
flake8 passes src/tests. The full backend suite was not rerun for these HTTP
configuration changes.
