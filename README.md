![Python package](https://github.com/jvanasco/cert_utils/workflows/Python%20package/badge.svg)

cert_utils
==========

**cert_utils** offers support for common operations when dealing with SSL
Certificates within the LetsEncrypt ecosystem.

This library was originally developed as a toolkit for bugfixing and
troubleshooting large ACME installations.

**cert_utils** will attempt to process operations with Python when possible.
If the required Python libraries are not installed, it will fallback to using
OpenSSL commandline via subprocesses.  **cert_utils** does a bit of work to
standardize certificate operations across versions of Python and OpenSSL that
do not share the same inputs, outputs or invocations.

**cert_utils** was formerly part of the
**[peter_sslers](https://github.com/aptise/peter_sslers)** ACME Client and
Certificate Management System, and has been descoped into it's own library.

This library *does not* process Certificates and Certificate Data itself.
Instead, it offers a simplified API to invoke other libraries and extract data
from Certificates.  It was designed for developers and system administrators to
more easily use the various libraries to accomplish specific tasks on the
commandline or as part of other projects.

Examples:
---------

For example, `cert_utils.parse_cert` returns a Python dict of key fields in a
certificate.  This can make writing a script to analyze large directories of
certificates fairly simple.


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
