# Bundled Let's Encrypt certificate archive

Import certificate metadata explicitly:

```python
from cert_utils.letsencrypt_info import certificates
from cert_utils.letsencrypt_info.types import CERT_CA_PAYLOAD

roots = certificates.DEFAULT_CA_PREFERENCES
```

The namespace itself no longer eagerly exports/loads certificate data.
Certificate PEM files remain in `cert_utils/letsencrypt-certs`; only the Python
module moved. Rate policy is separate in `cert_utils.letsencrypt_info.rate_limits`,
and both modules share definitions from `cert_utils.letsencrypt_info.types`.

Snapshot: 2026-10-28; `CERT_CAS_VERSION = 5`.

Sources:
- https://letsencrypt.org/certificates/
- Local letsencrypt-website checkout bb7e7238 (2026-10-26),
  content/en/certificates.md (page lastmod 2026-07-08), static/certs/.

All 51 bundled PEM certificates were compared by DER SHA-256 fingerprint
against that official archive. The offline manifest in
`tests/test_data/letsencrypt_bundle_manifest.json` records their upstream `source` paths,
local `bundle_path` paths and fingerprints; the website checkout is not required to run the tests.

## Current set

CERT_CAS_DATA contains 15 certificates: 13 production certificates plus the
existing two staging roots. Production includes X1 and X2; the renewed X2
cross-sign; YE and YR self-signed and cross-signed certificates; YE1/YE2 and
YR1/YR2 (active); and YE3/YR3 (backups). Backup intermediates have
`is_active=False`, `is_backup=True` and remain in CERT_CAS_DATA and
CA_LE_INTERMEDIATES so consumers can prepare for rotation.

YE and YR are issuer roots, but are not yet included in major root stores.
Their self-signed certificates have `is_trusted_root=False` and
`is_untrusted_root=True`; no platform compatibility claims are invented.
DEFAULT_CA_PREFERENCES retains X2, X1 first and appends YE, YR. This list
expresses available preference choices, not operating-system trust-store
installation or an assertion that every listed root is already trusted.

The renewed X2 cross-sign is `isrg_root_x2_cross_2025` and uses
`root-x2-by-x1.pem`. The old certificate retains `isrg_root_x2_cross` and its
original filename under deprecated/. Both refer to isrg_root_x2 via alternate_of;
its alternates list includes the new certificate first and historical one last.

## Historical set and metadata

CERT_CAS_DEPRECATED contains 36 certificates. E5–E9 and R10–R14 are retired,
even where their notAfter dates are still in the future. Expired and retired
certificates remain available for historical tests. The expired staging X2
cross-sign also moves to deprecated/. Existing identifiers, including the
historical staging cross-sign identifier, are preserved.

SHA-1/SHA-256 fingerprints, key technology, self-signing, signer relationships
and UTC `.enddate` tuples were extracted from the actual certificates.
`.enddate` describes X509 notAfter, not a trust program's sunset date. Existing
platform compatibility information is preserved, not newly verified.

PEM bytes for moved certificates are unchanged. New PEMs are copied from the
official archive. No certificates are silently replaced under historical keys.
The tests verify issuer signatures, alternate public-key identity, metadata,
file inventories, ordering and pending-root flags. DST Root CA X3's historical
SHA-1 self-signature is verified with the lower-level RSA API because newer
Cryptography rejects it through the high-level certificate verifier.

Downstream code opening package files directly must follow the deprecated/
relocations. Code selecting historical metadata must now look in
CERT_CAS_DEPRECATED for the moved entries. The two explicit order lists are
complete and deterministic; existing deprecated order is retained.
