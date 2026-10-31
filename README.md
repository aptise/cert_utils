![Python package](https://github.com/jvanasco/cert_utils/workflows/Python%20package/badge.svg)

cert_utils
==========

**cert_utils** offers support for common operations when dealing with SSL
Certificates, specifically within the LetsEncrypt ecosystem.

This library was originally developed as a toolkit for bugfixing and
troubleshooting large ACME installations.

**cert_utils** will attempt to process operations with Python via the modern
[Cryptography](https://cryptography.io/en/latest/) package when possible.
If the required Python libraries are not installed, it will fallback to using
OpenSSL commandline via subprocesses.  **cert_utils** does a bit of work to
standardize certificate operations across versions of Python and OpenSSL that
do not share the same inputs, outputs or invocations.

**cert_utils** was formerly part of the
**[peter_sslers](https://github.com/aptise/peter_sslers)** ACME Client and
Certificate Management System, and has been separated into its own library.

This library *does not* process Certificates and Certificate Data itself.
Instead, it offers a simplified API to invoke other libraries and extract data
from Certificates.  It was designed for developers and system administrators to
more easily use the various libraries to accomplish specific tasks on the
commandline or as part of other projects.

## Certificate inspection with `cert_info`

Run `cert_info --version` to print the library version, Python version, and
invoked binary path to stderr. No certificate argument is required.

Inspect a local PEM certificate or the certificate served by an HTTPS URL:

```sh
cert_info /path/to/cert.pem
cert_info https://example.com
```

Local inspection performs no network requests by default. HTTPS inspection
fetches the URL using Requests and prints the peer certificate as PEM to stdout.
ARI checks are optional for either input and require `--check-ari`:

```sh
cert_info /path/to/cert.pem --check-ari
cert_info https://example.com --check-ari
```

Version 1.4 renames the discovery/context flags to Certbot terminology; the
previous `--discover-letsencrypt`, `--letsencrypt-directory`, and
`--letsencrypt-managed` spellings are no longer accepted. Certbot manages the
filesystem layout; Let's Encrypt is the certificate authority.

### Search a local Certbot installation

Add `--discover-certbot` to compare the inspected certificate with Certbot
renewal configurations and associated ACME accounts. This works for a local PEM
or a live HTTPS certificate, so you can check whether a server is still serving
an older certificate after renewal or a missed restart:

```sh
cert_info https://example.com --discover-certbot
cert_info https://example.com --discover-certbot=all --certbot-config-directory /srv/letsencrypt
cert_info /path/to/cert.pem --discover-certbot=overlap
```

- `exact` (the default when the flag has no value): identical DNS name sets;
  inspect matching lineage archives for byte-identical certificate copies.
- `overlap`: include lineages sharing at least one DNS name.
- `all`: also correlate managed paths and public keys. A shared key does not
  mean two certificates are identical.

Byte-identical copies at other paths trigger an alert. Account associations are
potential historical issuance relationships, not proof of current issuance or
revocation authority. An older archive match can help explain a stale server;
check the reported paths against the current deployed certificate.

The Certbot configuration directory defaults to `/etc/letsencrypt`. Override it with
`--certbot-config-directory PATH`. For a local certificate under `live/` or
`archive/`, `--certbot-managed` derives the root. Both context options may
be used together only if their roots agree. Managed-path inference does not
apply to HTTPS URLs. Context options enable neither discovery nor ARI.

Discovery caches parsed renewal domains and account IDs privately under
`~/.cert_utils`, with a separate versioned cache per installation root.
`--cache-ttl SECONDS` defaults to 300; after that interval, renewal-file and
certificate timestamps/sizes are revalidated. Use `--refresh-cache` to rebuild
or `--no-cache` to bypass persistent reads and writes (`--no-cache` takes
precedence). Environment defaults are `CERT_INFO_CACHE_TTL`,
`CERT_INFO_REFRESH_CACHE`, and `CERT_INFO_NO_CACHE`; explicit CLI options win.

ARI and discovery are independent and can be combined. Discovery reads the
local installation and makes no additional outbound requests. HTTPS peer
extraction depends on Requests exposing its connection socket; if unavailable,
requested discovery fails explicitly. The printed PEM is part of diagnostic
output, not a standalone PEM-only stream.

Examples API:
-------------

For example, `cert_utils.parse_cert` returns a Python dict of key fields in a
certificate.  This can make writing a script to analyze large directories of
certificates fairly simple. Successful parsing always supplies string `issuer`,
`subject`, and `fingerprint_sha1` values and datetime `startdate` and `enddate`
values. Other metadata can be `None`, including key technology and SPKI for
unsupported key algorithms. Parsing failures raise an exception.


### Parse a Leaf/End-Entity

Example Script:

```!python
import cert_utils
import pprint

cert_path = "./tests/test_data/unit_tests/cert_001/cert.pem"
cert_pem = open(cert_path, 'r').read()
data = cert_utils.parse_cert(cert_pem)
pprint.pprint(data)
```

Result:

    {'SubjectAlternativeName': ['a.example.com',
                                'b.example.com',
                                'c.example.com',
                                'd.example.com'],
     'authority_key_identifier': 'D159010094B0A62ADBABE54B2321CA1B6EBA93E7',
     'enddate': datetime.datetime(2025, 6, 16, 20, 19, 30),
     'fingerprint_sha1': 'F63C5C66B52551EEDADF7CE44301D646680B8F5D',
     'issuer': 'CN=Pebble Intermediate CA 601ea1',
     'issuer_uri': None,
     'key_technology': 'RSA',
     'spki_sha256': '34E67CC615761CBADAF430B2E02E0EC39C99EEFC73CCE469B18AE54A37EF6942',
     'startdate': datetime.datetime(2020, 6, 16, 20, 19, 30),
     'subject': 'CN=a.example.com'}

The payload contains `SubjectAlternativeName` listing all the domains, along
with `enddate` and `startdate` in Python datetime objects for easy comparison.

### Parse a Trusted Root

Example Script:

```!python
import cert_utils
import pprint

cert_path = "./src/cert_utils/letsencrypt-certs/isrgrootx1.pem"
cert_pem = open(cert_path, 'r').read()
data = cert_utils.parse_cert(cert_pem)
pprint.pprint(data)
```

Result:

    {'SubjectAlternativeName': None,
     'authority_key_identifier': None,
     'enddate': datetime.datetime(2035, 6, 4, 11, 4, 38),
     'fingerprint_sha1': 'CABD2A79A1076A31F21D253635CB039D4329A5E8',
     'issuer': 'C=US\nO=Internet Security Research Group\nCN=ISRG Root X1',
     'issuer_uri': None,
     'key_technology': 'RSA',
     'spki_sha256': '0B9FA5A59EED715C26C1020C711B4F6EC42D58B0015E14337A39DAD301C5AFC3',
     'startdate': datetime.datetime(2015, 6, 4, 11, 4, 38),
     'subject': 'C=US\nO=Internet Security Research Group\nCN=ISRG Root X1'}

The payload on Trusted Roots is identical.


Why does this exist?
--------------------

The [peter_sslers](https://github.com/aptise/peter_sslers) project was designed
to deploy on a wide variety of production servers that did not share common
Python and OpenSSL installations.  Earlier versions of the library
(within peter_sslers) supported both Python2.7 and Python3, as it was common to
encounter a machine that did not have Python3 installed.  Although it is still
common to find these machines, Python2.7 was dropped to take advantage of
typing.  Depending on the version of OpenSSL installed on a system,
**cert_utils** will invoke the binary or regex the output to bridge support
through a unified interface.

Historical implementation notes: [OpenSSL reference](docs/openssl-reference.md).

HTTP timeouts
-------------

`cert_info` uses a Requests `(connect, read)` timeout of `(5, 30)` seconds.
The read timeout limits inactivity between reads; it is not a total command
execution deadline. Override both values with positive, finite seconds:

```sh
CERT_UTILS_TIMEOUT=3,20 cert_info https://example.com
cert_info --timeout 2,10 https://example.com
cert_info --timeout 2,10 /path/to/cert.pem
```

Precedence is explicit CLI/Python argument, then `CERT_UTILS_TIMEOUT`, then the
default. The CLI override also applies to directory and subsequent ARI requests.
Python callers can pass `timeout=(connect, read)` to `new_session`, `ari_query`,
`process_url`, `process_filepath`, `process_ari_url`, and
`download_letsencrypt_certificates`. Sessions from `new_session` retain Requests'
per-request timeout override support. CLI-owned sessions are closed on success
and failure; callers retain ownership of sessions passed to `process_ari_url`.

Compatibility design notes: [certificate profiles and peer hooks](docs/compatibility.md).

Bundled CA snapshot and migration notes: [Let's Encrypt certificate archive](docs/letsencrypt-bundle.md).

Machine-readable production rate policy: [schema 2 and migration guide](docs/rate-limits.md).
Import `cert_utils.letsencrypt_info.rate_limits.RATE_LIMITS` without loading the CA archive.

Account-signature formats and backend behavior: [signing and verification](docs/account-signatures.md).
