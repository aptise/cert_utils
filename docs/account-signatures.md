# Account signature backend parity

Both account_key__sign and account_key__verify support RSA PKCS#1 v1.5 and
ECDSA with SHA-256 through Cryptography/josepy or OpenSSL subprocesses. Supported
EC curves for the fallback are P-256, P-384 and P-521. This preserves the
existing SHA-256 choice; it does not automatically select a JOSE algorithm
from the curve (for example, P-384 does not switch this API to ES384).

The public interface still accepts a private PEM key, with an optional file
path used by the subprocess backend. If both are supplied, callers must ensure
that their contents match. Encrypted keys/passphrase prompting and public-key
inputs are not added by this change.

For EC, standardize_signature=True means fixed-width unsigned r||s (32, 48 or
66 bytes per component); False/None means ASN.1 DER. RSA is unaffected.
OpenSSL signing previously ignored True and returned DER; callers depending
on that historical output must now explicitly request False. Formats are never
auto-detected. Binary signatures are not Base64-decoded by this API.

Verification returns None on success. The Python backend retains
cryptography.exceptions.InvalidSignature; the OpenSSL verification command's
nonzero exit raises OpenSslError_InvalidSignature, a subclass of OpenSslError,
with diagnostics. Key-loading failures raise OpenSslError_InvalidKey in the
fallback; malformed standardized signatures and unsupported key types/curves
raise ValueError. Process startup failures propagate as OS errors. A nonzero
verification command can also indicate provider/operational failure, so callers
should retain its diagnostics rather than interpret every failure as forgery.

The fallback uses psutil.Popen throughout. It obtains public DER SPKI metadata
with openssl pkey -pubout to determine the algorithm and curve without parsing
private-key text. ECDSA conversions use a small DER codec independent of
Cryptography/josepy. It rejects negative/non-minimal integers, malformed lengths,
extra components, oversized values and trailing data. OpenSSL performs the
actual mathematical verification with dgst -sha256 -prverify. Arguments are
passed as lists; messages use binary stdin. Private temporary keys use mode
0600 inside a private temporary directory. Key and signature files are removed
on successful and failed verification. Caller-supplied files are not removed.

Tests cover cross-backend signing and verification, missing josepy and missing
both optional packages, altered messages, wrong keys, both EC encodings,
leading-zero/sign-bit handling, P-521 long DER lengths, malformed DER and
verification temporary-file cleanup. Historical OpenSSL versions still require
the supported-version CI matrix; local validation uses the installed OpenSSL.
