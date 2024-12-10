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

This library now includes a utility, `cert_info`:

Examples CLI:
-------------

The CLI tool `cert_info` can parse a cert and pull the active ARI info.

The tool accepts a filepath to a local file OR a https URL to be inspected live:

> cert_info https://letsencrypt.org

This will gnerate the output:

    ********************************************************************************
    ********************************************************************************
    Process URL:
    url:  https://letsencrypt.org
    =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    Connection Data:
    {'cert_dict': {'OCSP': ('http://e6.o.lencr.org',),
                   'caIssuers': ('http://e6.i.lencr.org/',),
                   'issuer': ((('countryName', 'US'),),
                              (('organizationName', "Let's Encrypt"),),
                              (('commonName', 'E6'),)),
                   'notAfter': 'Mar  7 14:44:04 2025 GMT',
                   'notBefore': 'Dec  7 14:44:05 2024 GMT',
                   'serialNumber': '04C7A73A361AC02B67BDBD6AF210285B1CC7',
                   'subject': ((('commonName', 'letsencrypt.org'),),),
                   'subjectAltName': (('DNS', 'lencr.org'),
                                      ('DNS', 'letsencrypt.com'),
                                      ('DNS', 'letsencrypt.org'),
                                      ('DNS', 'www.lencr.org'),
                                      ('DNS', 'www.letsencrypt.com'),
                                      ('DNS', 'www.letsencrypt.org')),
                   'version': 3},
     'cert_pem': '-----BEGIN CERTIFICATE-----\n'
                 'MIID1DCCA1qgAwIBAgISBMenOjYawCtnvb1q8hAoWxzHMAoGCCqGSM49BAMDMDIx\n'
                 'CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF\n'
                 'NjAeFw0yNDEyMDcxNDQ0MDVaFw0yNTAzMDcxNDQ0MDRaMBoxGDAWBgNVBAMTD2xl\n'
                 'dHNlbmNyeXB0Lm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDgHHaIeMwYz\n'
                 'APO9ZgfeGansUeFRN0sW4K23nrVppRXfjHvN+83vtH170hshCrIAZRJCL+CPcA2N\n'
                 'UqmLiSdM/M+jggJmMIICYjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYB\n'
                 'BQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFD2MLtcnwBWM\n'
                 'FukcX4wMfYCQUCMAMB8GA1UdIwQYMBaAFJMnRpgDqVFojpjWxEJI2yO/WJTSMFUG\n'
                 'CCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL2U2Lm8ubGVuY3Iub3Jn\n'
                 'MCIGCCsGAQUFBzAChhZodHRwOi8vZTYuaS5sZW5jci5vcmcvMG8GA1UdEQRoMGaC\n'
                 'CWxlbmNyLm9yZ4IPbGV0c2VuY3J5cHQuY29tgg9sZXRzZW5jcnlwdC5vcmeCDXd3\n'
                 'dy5sZW5jci5vcmeCE3d3dy5sZXRzZW5jcnlwdC5jb22CE3d3dy5sZXRzZW5jcnlw\n'
                 'dC5vcmcwEwYDVR0gBAwwCjAIBgZngQwBAgEwggEEBgorBgEEAdZ5AgQCBIH1BIHy\n'
                 'APAAdgB9WR4S4XgqexxhZ3xe/fjQh1wUoE6VnrkDL9kOjC55uAAAAZOhyXh9AAAE\n'
                 'AwBHMEUCIAXoVc0BRK6ELL0Q1lHv+QbrobnBiPthcr2E7g0IulkHAiEAlVkiVkF9\n'
                 '7KeR/At3XdJNRYbJda0iKaKtqKy0KH7igZgAdgATSt8atZhCCXgMb+9MepGkFrcj\n'
                 'Sc5YV2rfrtqnwqvgIgAAAZOhyXk0AAAEAwBHMEUCIQD+yhm/6lwMMWyxBaB15Mkh\n'
                 'g3tsQCtr0DOD4uvAzc63FAIgHgjXduGCbB/3VTtRCGWfmkWSS9z+CjfO1O6hkzGW\n'
                 'XBowCgYIKoZIzj0EAwMDaAAwZQIxAKVLzxW03Kk8qJMBtWQCw5dgSHNWOGG9Oq03\n'
                 'XOGr8092sx9Ezz3XsXWeq8JvokFjhAIwCZOX/UjxdHfgV/O6gkiNARQ1FokDyfS0\n'
                 'ClynPk9psMTPVl5QWgYJzjVrJagAjtJm\n'
                 '-----END CERTIFICATE-----\n',
     'peername': ('100.28.201.155', 443)}
    =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    Cert Data:
    ARI ID: kydGmAOpUWiOmNbEQkjbI79YlNI.BMenOjYawCtnvb1q8hAoWxzH
    =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    Requesting ARI
    ari_url: https://acme-v02.api.letsencrypt.org/draft-ietf-acme-ari-03/renewalInfo/kydGmAOpUWiOmNbEQkjbI79YlNI.BMenOjYawCtnvb1q8hAoWxzH
    {'Server': 'nginx', 'Date': 'Tue, 10 Dec 2024 18:29:04 GMT', 'Content-Type': 'application/json', 'Content-Length': '101', 'Connection': 'keep-alive', 'Cache-Control': 'public, max-age=0, no-cache', 'Link': '<https://acme-v02.api.letsencrypt.org/directory>;rel="index"', 'Retry-After': '21600', 'X-Frame-Options': 'DENY', 'Strict-Transport-Security': 'max-age=604800'}
    - - - - - - - - - - 
    {'suggestedWindow': {'end': '2025-02-06T15:03:34Z',
                         'start': '2025-02-04T15:03:34Z'}}


Examples API:
-------------

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
