# stdlib
import json
import logging
import os
import test
import test.test_httplib
import unittest

# pypi
from acme import crypto_util as acme_crypto_util
from certbot import crypto_util as certbot_crypto_util
import cryptography
from cryptography.hazmat.primitives import serialization as crypto_serialization
import josepy
from OpenSSL import crypto as openssl_crypto

# local
import cert_utils
from cert_utils import core
from cert_utils import model
from cert_utils import utils
from cert_utils.errors import OpenSslError
from ._utils import _Mixin_filedata
from ._utils import CERT_CA_SETS
from ._utils import CSR_SETS
from ._utils import KEY_SETS
from ._utils import TEST_FILES

# ==============================================================================

EXTENDED_TESTS = bool(int(os.getenv("CERT_UTILS_EXTENDED_TESTS", "0")))

# ------------------------------------------------------------------------------

# these mixins are used to simulate behavior as if we are missing libraries


class _Mixin_fallback_possible(object):
    _fallback = False
    _fallback_global = False


class _MixinNoCrypto(_Mixin_fallback_possible):
    _fallback = True
    _fallback_global = True

    def setUp(self):
        # print("_MixinNoCrypto.setUp")
        global cert_utils
        cert_utils.core.acme_crypto_util = None
        cert_utils.core.certbot_crypto_util = None
        cert_utils.core.cryptography = None
        cert_utils.core.crypto_serialization = None
        cert_utils.core.josepy = None
        cert_utils.core.openssl_crypto = None

    def tearDown(self):
        # print("_MixinNoCrypto.tearDown")
        global cert_utils
        cert_utils.core.acme_crypto_util = acme_crypto_util
        cert_utils.core.certbot_crypto_util = certbot_crypto_util
        cert_utils.core.cryptography = cryptography
        cert_utils.core.crypto_serialization = crypto_serialization
        cert_utils.core.josepy = josepy
        cert_utils.core.openssl_crypto = openssl_crypto


class _Mixin_Missing_acme(_Mixin_fallback_possible):
    _fallback = True

    def setUp(self):
        global cert_utils
        cert_utils.core.acme_crypto_util = None

    def tearDown(self):
        global cert_utils
        cert_utils.core.acme_crypto_util = acme_crypto_util


class _Mixin_Missing_certbot(_Mixin_fallback_possible):
    _fallback = True

    def setUp(self):
        global cert_utils
        cert_utils.core.certbot_crypto_util = None

    def tearDown(self):
        global cert_utils
        cert_utils.core.certbot_crypto_util = certbot_crypto_util


class _Mixin_Missing_cryptography(_Mixin_fallback_possible):
    _fallback = True

    def setUp(self):
        global cert_utils
        cert_utils.core.cryptography = None

    def tearDown(self):
        global cert_utils
        cert_utils.core.cryptography = cryptography


class _Mixin_Missing_josepy(_Mixin_fallback_possible):
    _fallback = True

    def setUp(self):
        global cert_utils
        cert_utils.core.josepy = None

    def tearDown(self):
        global cert_utils
        cert_utils.core.josepy = josepy


class _Mixin_Missing_openssl_crypto(_Mixin_fallback_possible):
    _fallback = True

    def setUp(self):
        global cert_utils
        cert_utils.core.openssl_crypto = None

    def tearDown(self):
        global cert_utils
        cert_utils.core.openssl_crypto = openssl_crypto


# ------------------------------------------------------------------------------


class UnitTest_CertUtils(unittest.TestCase, _Mixin_fallback_possible, _Mixin_filedata):
    """python -m unittest tests.test_unit.UnitTest_CertUtils"""

    _account_sets = {
        "001": {
            "letsencrypt": True,
            "pem": True,
            "signature.input": "example.sample",
            "signature.output": "hN3bre1YpxSGbvKmx8zK9_o0yaxtDblDfS3Q3CsjAas9wUVIHk7NqxXH0HeEeZG_7T0AHH6HTfxMbucXK_dLog_g9AxQYFsRBc8587C8Z5rWF2YDCoo0W7JB7VOoLEHGfe7JRXeqgA9QSnci0wMFlKXC_6MbKxql8QtswOdvtFM85qcJsMCOSu2Xf6HLIAYFhdBJH-DvQGzE4ctOKAYCmDyXs42DBUU4CU0cNXj8TsN0cFRXvInvSqDsiPNSjyV32WC4clPHX69KEbs5Wr0WV2diHR-Q6w0QUljWZEDpcl8mb86LZwBqoUTHX2xstQI77sLcg7YhDfaIPrCjYJcNZw",
        },
    }
    _cert_sets = {
        "001": {
            "csr": True,
            "csr.subject": "",
            "csr.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "csr.domains.subject": None,
            "csr.domains.san": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert": True,
            "cert.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert.domains.subject": "a.example.com",
            "cert.domains.san": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert.notAfter": "2025-06-16 20:19:30",  # "Jun 16 20:19:30 2025 GMT",
            "cert.notBefore": "2020-06-16 20:19:30",
            "cert.fingerprints": {
                "sha1": "F63C5C66B52551EEDADF7CE44301D646680B8F5D",
                "sha256": "027E69B35F0D8F2D2A3D06D47208F0C4FD31B69A429DFC36BE8DD0D5B73D8DC4",
                "md5": "21C60FE639DF16CA5BF15D8207F07A42",
            },
            "cert.authority_key_identifier": "D159010094B0A62ADBABE54B2321CA1B6EBA93E7",
            "cert.issuer_uri": None,
            "key_technology": "RSA",
            "pubkey_modulus_md5": "052dec9ebfb5036c7aa6dd61888765b6",
            "spki_sha256": "34E67CC615761CBADAF430B2E02E0EC39C99EEFC73CCE469B18AE54A37EF6942",
            "spki_sha256.b64": "NOZ8xhV2HLra9DCy4C4Ow5yZ7vxzzORpsYrlSjfvaUI=",
        },
        "002": {
            "csr": True,
            "csr.subject": "CN=example.com",
            "csr.domains.all": [
                "example.com",
            ],
            "csr.domains.subject": "example.com",
            "csr.domains.san": [],
            "cert": False,
            "key_technology": "RSA",
            "pubkey_modulus_md5": "c25a298dc7de8f855453a6ed8be8bb5f",
            "spki_sha256": "C1FF7146EE861479AE997617CB994424905F9441C6D9E669A9A6CC520445C663",
            "spki_sha256.b64": "wf9xRu6GFHmumXYXy5lEJJBflEHG2eZpqabMUgRFxmM=",
        },
        "003": {
            "csr": True,
            "csr.subject": "",
            "csr.domains.all": [
                "example.com",
            ],
            "csr.domains.subject": None,
            "csr.domains.san": ["example.com"],
            "cert": True,
            "cert.domains.all": [
                "example.com",
            ],
            "cert.domains.subject": "example.com",
            "cert.domains.san": [
                "example.com",
            ],
            "cert.notAfter": "2025-06-16 22:06:46",  # "Jun 16 22:06:46 2025 GMT",
            "cert.notBefore": "2020-06-16 22:06:46",
            "cert.fingerprints": {
                "sha1": "E8503EAC0F4F9685841F961AD966774D66521C5E",
                "sha256": "CC8D066A7C59D67A4DAEE02AC67BAAC5DA0296303758CC824AF6243D5A8C78F6",
                "md5": "455A11B05729B3BDE11A86D5A94C40D7",
            },
            "cert.authority_key_identifier": "D159010094B0A62ADBABE54B2321CA1B6EBA93E7",
            "cert.issuer_uri": None,
            "key_technology": "RSA",
            "pubkey_modulus_md5": "f625ac6f399f90867cbf6a4e5dd8fc9e",
            "spki_sha256": "043AF1B9CC1AF925C132E19574FB7B251F727D55E185D9882B7A72F11F82AD97",
            "spki_sha256.b64": "BDrxucwa+SXBMuGVdPt7JR9yfVXhhdmIK3py8R+CrZc=",
        },
        "004": {
            "csr": True,
            "csr.subject": "",
            "csr.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "csr.domains.subject": "",
            "csr.domains.san": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert": True,
            "cert.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert.domains.subject": "a.example.com",
            "cert.domains.san": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert.notAfter": "2025-06-16 22:07:02",  # "Jun 16 22:07:02 2025 GMT",
            "cert.notBefore": "2020-06-16 22:07:02",
            "cert.fingerprints": {
                "sha1": "A8880200452452ADF192847CDEC1330617204D14",
                "sha256": "3906F17472B9E180C6526135B0BBF4CA2C6187D2DC9067809FC023B5EA276257",
                "md5": "36D3A42948CF7C78D50660C9F46618B3",
            },
            "cert.authority_key_identifier": "D159010094B0A62ADBABE54B2321CA1B6EBA93E7",
            "cert.issuer_uri": None,
            "pubkey_modulus_md5": "797ba616e62dedcb014a7a37bcde3fdf",
            "key_technology": "RSA",
            "spki_sha256": "04825ACA7FDE791C3FFDAC73B8F52575EA598753D0F9E995187E856E34633922",
            "spki_sha256.b64": "BIJayn/eeRw//axzuPUldepZh1PQ+emVGH6FbjRjOSI=",
        },
        "005": {
            "csr": True,
            "csr.subject": "CN=a.example.com",
            "csr.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "csr.domains.subject": "a.example.com",
            "csr.domains.san": [
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert": False,
            "key_technology": "RSA",
            "pubkey_modulus_md5": "f4614ec52f34066ce074798cdc494d74",
            "spki_sha256": "BED992DAD570A4984EA47BE1C92F091839888BC3482D9206F891C4A8239AD2AB",
            "spki_sha256.b64": "vtmS2tVwpJhOpHvhyS8JGDmIi8NILZIG+JHEqCOa0qs=",
        },
    }
    _csr_sets_alt = {
        "001": {
            "directory": "key_technology-ec",
            "file.key": "ec384-1-key.pem",
            "file.csr": "ec384-1.csr",
            "csr": True,
            "csr.subject": "CN=ec384-1.example.com",
            "csr.domains.all": [
                "ec384-1.example.com",
            ],
            "csr.domains.subject": "ec384-1.example.com",
            "csr.domains.san": [],
            "cert": False,
            "pubkey_modulus_md5": "None",
            "key_technology": "EC",
            "spki_sha256": "E739FB0081868C97B8AC0D3773680974E9FCECBFA1FC8B80AFDDBE42F30D1D9D",
            "spki_sha256.b64": "5zn7AIGGjJe4rA03c2gJdOn87L+h/IuAr92+QvMNHZ0=",
        }
    }

    def test__parse_cert__domains(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_cert__domains
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                cert_domains = cert_utils.parse_cert__domains(
                    cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
                )
                self.assertEqual(
                    cert_domains, self._cert_sets[cert_set]["cert.domains.all"]
                )
                if self._fallback_global or (not cert_utils.core.certbot_crypto_util):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_cert__domains > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_cert__domains > openssl fallback",
                        logged.output,
                    )

    def test__fingerprint_cert(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__fingerprint_cert
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)

            # defaults to sha1
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                _fingerprint = cert_utils.fingerprint_cert(
                    cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
                )
                self.assertEqual(
                    _fingerprint, self._cert_sets[cert_set]["cert.fingerprints"]["sha1"]
                )
                if self._fallback_global or (not cert_utils.core.openssl_crypto):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.fingerprint_cert > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.fingerprint_cert > openssl fallback",
                        logged.output,
                    )

            # test the supported
            for _alg in ("sha1", "sha256", "md5"):
                _fingerprint = cert_utils.fingerprint_cert(
                    cert_pem=cert_pem,
                    cert_pem_filepath=cert_pem_filepath,
                    algorithm=_alg,
                )
                self.assertEqual(
                    _fingerprint, self._cert_sets[cert_set]["cert.fingerprints"][_alg]
                )
                # no need to test the fallback behavior again

            # test unsupported
            with self.assertRaises(ValueError) as cm:
                _fingerprint = cert_utils.fingerprint_cert(
                    cert_pem=cert_pem,
                    cert_pem_filepath=cert_pem_filepath,
                    algorithm="fake",
                )
            self.assertTrue(
                cm.exception.args[0].startswith("algorithm `fake` not in `('")
            )

    def test__parse_csr_domains(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_csr_domains
        """

        for cert_set in sorted(self._cert_sets.keys()):
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                csr_domains = cert_utils.parse_csr_domains(
                    csr_pem=csr_pem,
                    csr_pem_filepath=csr_pem_filepath,
                    submitted_domain_names=self._cert_sets[cert_set]["csr.domains.all"],
                )
                self.assertEqual(
                    csr_domains, self._cert_sets[cert_set]["csr.domains.all"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.certbot_crypto_util)
                    or (not cert_utils.core.openssl_crypto)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_csr_domains > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_csr_domains > openssl fallback",
                        logged.output,
                    )

    def test__validate_csr(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__validate_csr
        """
        for cert_set in sorted(self._cert_sets.keys()):
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                cert_utils.validate_csr(
                    csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
                )
                if self._fallback_global or (not cert_utils.core.certbot_crypto_util):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.validate_csr > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.validate_csr > openssl fallback",
                        logged.output,
                    )

    def test__validate_key(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__validate_key
        """

        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                key_technology = cert_utils.validate_key(
                    key_pem=key_pem, key_pem_filepath=key_pem_filepath
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.crypto_serialization)
                    or (not cert_utils.core.crypto_rsa)
                    or (not cert_utils.core.crypto_ec)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.validate_key > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.validate_key > openssl fallback",
                        logged.output,
                    )

        for key_filename in sorted(KEY_SETS.keys()):
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                key_technology = cert_utils.validate_key(
                    key_pem=key_pem, key_pem_filepath=key_pem_filepath
                )
                self.assertEqual(
                    key_technology, KEY_SETS[key_filename]["key_technology"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.crypto_serialization)
                    or (not cert_utils.core.crypto_rsa)
                    or (not cert_utils.core.crypto_ec)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.validate_key > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.validate_key > openssl fallback",
                        logged.output,
                    )

    def test__validate_cert(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__validate_cert
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                cert_utils.validate_cert(
                    cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
                )
                if self._fallback_global or (not cert_utils.core.openssl_crypto):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.validate_cert > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.validate_cert > openssl fallback",
                        logged.output,
                    )

    def test__make_csr(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__make_csr
        """

        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                csr_pem = cert_utils.make_csr(
                    domain_names=self._cert_sets[cert_set]["csr.domains.all"],
                    key_pem=key_pem,
                    key_pem_filepath=key_pem_filepath,
                )
                if self._fallback_global or (not cert_utils.core.acme_crypto_util):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.make_csr > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.make_csr > openssl fallback",
                        logged.output,
                    )

    def test__modulus_md5_key(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__modulus_md5_key
        """
        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                modulus_md5 = cert_utils.modulus_md5_key(
                    key_pem=key_pem, key_pem_filepath=key_pem_filepath
                )
                self.assertEqual(
                    modulus_md5, self._cert_sets[cert_set]["pubkey_modulus_md5"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.modulus_md5_key > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.modulus_md5_key > openssl fallback",
                        logged.output,
                    )

        for key_filename in sorted(KEY_SETS.keys()):
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            modulus_md5 = cert_utils.modulus_md5_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(modulus_md5, KEY_SETS[key_filename]["modulus_md5"])
            # no need to test for fallback behavior again

    def test__modulus_md5_csr(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__modulus_md5_csr
        """
        for cert_set in sorted(self._cert_sets.keys()):
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                modulus_md5 = cert_utils.modulus_md5_csr(
                    csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
                )
                self.assertEqual(
                    modulus_md5, self._cert_sets[cert_set]["pubkey_modulus_md5"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.modulus_md5_csr > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.modulus_md5_csr > openssl fallback",
                        logged.output,
                    )

        # csr sets
        for csr_filename in sorted(CSR_SETS.keys()):
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            modulus_md5 = cert_utils.modulus_md5_csr(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            if modulus_md5 is None:
                # TODO: no way of testing this in Pure-python right now
                if self.__class__ == UnitTest_CertUtils:
                    continue
                elif cert_utils.core.openssl_crypto:
                    continue
            self.assertEqual(modulus_md5, CSR_SETS[csr_filename]["modulus_md5"])
            # no need to test for fallback behavior again

    def test__modulus_md5_cert(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__modulus_md5_cert
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                modulus_md5 = cert_utils.modulus_md5_cert(
                    cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
                )
                self.assertEqual(
                    modulus_md5, self._cert_sets[cert_set]["pubkey_modulus_md5"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.modulus_md5_cert > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.modulus_md5_cert > openssl fallback",
                        logged.output,
                    )

        # ca certs
        for cert_filename in sorted(CERT_CA_SETS.keys()):
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            modulus_md5 = cert_utils.modulus_md5_cert(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(modulus_md5, CERT_CA_SETS[cert_filename]["modulus_md5"])
            # no need to test for fallback behavior again

    def test__parse_cert__enddate(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_cert__enddate
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                cert_enddate = cert_utils.parse_cert__enddate(
                    cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
                )
                self.assertEqual(
                    str(cert_enddate), self._cert_sets[cert_set]["cert.notAfter"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_cert__enddate > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_cert__enddate > openssl fallback",
                        logged.output,
                    )

    def test__parse_cert__startdate(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_cert__startdate
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                cert_startdate = cert_utils.parse_cert__startdate(
                    cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
                )
                self.assertEqual(
                    str(cert_startdate), self._cert_sets[cert_set]["cert.notBefore"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_cert__startdate > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_cert__startdate > openssl fallback",
                        logged.output,
                    )

    def test__parse_cert(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_cert
        python -m unittest tests.test_unit.UnitTest_CertUtils_fallback.test__parse_cert

        This UnitTest tests the following functions:

            * cert_utils.parse_cert
            * cert_utils.parse_cert__spki_sha256
            * cert_utils.parse_cert__key_technology

        These are run on Signed and CA Certificates
            self._cert_sets
            CERT_CA_SETS
        """

        # normal certs
        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)

            # `cert_utils.parse_cert`
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                rval = cert_utils.parse_cert(
                    cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_cert > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_cert > openssl fallback",
                        logged.output,
                    )
            self.assertEqual(
                rval["fingerprint_sha1"],
                self._cert_sets[cert_set]["cert.fingerprints"]["sha1"],
            )
            self.assertEqual(
                rval["spki_sha256"], self._cert_sets[cert_set]["spki_sha256"]
            )
            self.assertEqual(
                rval["issuer_uri"], self._cert_sets[cert_set]["cert.issuer_uri"]
            )
            self.assertEqual(
                rval["authority_key_identifier"],
                self._cert_sets[cert_set]["cert.authority_key_identifier"],
            )

            # `cert_utils.parse_cert__spki_sha256`
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                spki_sha256 = cert_utils.parse_cert__spki_sha256(
                    cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_cert__spki_sha256 > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_cert__spki_sha256 > openssl fallback",
                        logged.output,
                    )

            self.assertEqual(spki_sha256, self._cert_sets[cert_set]["spki_sha256"])
            spki_sha256_b64 = cert_utils.parse_cert__spki_sha256(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath, as_b64=True
            )
            self.assertEqual(
                spki_sha256_b64, self._cert_sets[cert_set]["spki_sha256.b64"]
            )

            # `cert_utils.parse_cert__key_technology`
            key_technology = cert_utils.parse_cert__key_technology(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                key_technology, self._cert_sets[cert_set]["key_technology"]
            )

        # ca certs
        for cert_filename in sorted(CERT_CA_SETS.keys()):
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)

            # `cert_utils.parse_cert`
            rval = cert_utils.parse_cert(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            for field in (
                "key_technology",
                "issuer",
                "subject",
                "issuer_uri",
                "authority_key_identifier",
            ):
                self.assertEqual(rval[field], CERT_CA_SETS[cert_filename][field])
            self.assertEqual(
                rval["fingerprint_sha1"],
                CERT_CA_SETS[cert_filename]["cert.fingerprints"]["sha1"],
            )

            # `cert_utils.parse_cert__spki_sha256`
            spki_sha256 = cert_utils.parse_cert__spki_sha256(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(spki_sha256, CERT_CA_SETS[cert_filename]["spki_sha256"])
            spki_sha256_b64 = cert_utils.parse_cert__spki_sha256(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath, as_b64=True
            )
            self.assertEqual(
                spki_sha256_b64, CERT_CA_SETS[cert_filename]["spki_sha256.b64"]
            )

            # `cert_utils.parse_cert__key_technology`
            key_technology = cert_utils.parse_cert__key_technology(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                key_technology, CERT_CA_SETS[cert_filename]["key_technology"]
            )

    def test__parse_csr(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_csr
        python -m unittest tests.test_unit.UnitTest_CertUtils_fallback.test__parse_csr

        This UnitTest tests the following functions:

            * cert_utils.parse_csr
            * cert_utils.parse_csr__spki_sha256
            * cert_utils.parse_csr__key_technology

        These are run on Signed and CA Certificates
            self._cert_sets
            CERT_CA_SETS
        """

        # normal certs
        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["csr"]:
                raise ValueError("missing csr!")
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)

            # `cert_utils.parse_csr`
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                rval = cert_utils.parse_csr(
                    csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
                )
                self.assertEqual(
                    rval["key_technology"],
                    self._cert_sets[cert_set]["key_technology"],
                )
                self.assertEqual(
                    rval["spki_sha256"], self._cert_sets[cert_set]["spki_sha256"]
                )
                self.assertEqual(
                    rval["subject"],
                    self._cert_sets[cert_set]["csr.subject"],
                )
                self.assertEqual(
                    rval["SubjectAlternativeName"],
                    self._cert_sets[cert_set]["csr.domains.san"],
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_csr > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_csr > openssl fallback",
                        logged.output,
                    )

            # `cert_utils.parse_csr__spki_sha256`
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                spki_sha256 = cert_utils.parse_csr__spki_sha256(
                    csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
                )
                self.assertEqual(spki_sha256, self._cert_sets[cert_set]["spki_sha256"])
                spki_sha256_b64 = cert_utils.parse_csr__spki_sha256(
                    csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath, as_b64=True
                )
                self.assertEqual(
                    spki_sha256_b64, self._cert_sets[cert_set]["spki_sha256.b64"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_csr__spki_sha256 > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_csr__spki_sha256 > openssl fallback",
                        logged.output,
                    )

            # `cert_utils.parse_csr__key_technology
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                key_technology = cert_utils.parse_csr__key_technology(
                    csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
                )
                self.assertEqual(
                    key_technology, self._cert_sets[cert_set]["key_technology"]
                )
                if self._fallback_global or (not cert_utils.core.openssl_crypto):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_csr__key_technology > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_csr__key_technology > openssl fallback",
                        logged.output,
                    )

        # extended csr
        for csr_set in sorted(self._csr_sets_alt.keys()):
            if not self._csr_sets_alt[csr_set]["csr"]:
                raise ValueError("missing csr!")
            csr_filename = "%s/%s" % (
                self._csr_sets_alt[csr_set]["directory"],
                self._csr_sets_alt[csr_set]["file.csr"],
            )
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)

            # `cert_utils.parse_csr`
            rval = cert_utils.parse_csr(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(
                rval["key_technology"],
                self._csr_sets_alt[csr_set]["key_technology"],
            )
            self.assertEqual(
                rval["spki_sha256"], self._csr_sets_alt[csr_set]["spki_sha256"]
            )
            self.assertEqual(
                rval["subject"],
                self._csr_sets_alt[csr_set]["csr.subject"],
            )
            self.assertEqual(
                rval["SubjectAlternativeName"],
                self._csr_sets_alt[csr_set]["csr.domains.san"],
            )

            # `cert_utils.parse_csr__spki_sha256`
            spki_sha256 = cert_utils.parse_csr__spki_sha256(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(spki_sha256, self._csr_sets_alt[csr_set]["spki_sha256"])
            spki_sha256_b64 = cert_utils.parse_csr__spki_sha256(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath, as_b64=True
            )
            self.assertEqual(
                spki_sha256_b64, self._csr_sets_alt[csr_set]["spki_sha256.b64"]
            )

            # `cert_utils.parse_csr__key_technology`
            key_technology = cert_utils.parse_csr__key_technology(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(
                key_technology, self._csr_sets_alt[csr_set]["key_technology"]
            )

    def test__parse_key(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_key
        python -m unittest tests.test_unit.UnitTest_CertUtils_fallback.test__parse_key

        This is a debugging display function. The output is not guaranteed across installations.

        This UnitTest tests the following functions:

            * cert_utils.parse_key
            * cert_utils.parse_key__spki_sha256
            * cert_utils.parse_key__technology
        """

        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)

            # `cert_utils.parse_key`
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                rval = cert_utils.parse_key(
                    key_pem=key_pem, key_pem_filepath=key_pem_filepath
                )
                self.assertEqual(
                    rval["key_technology"], self._cert_sets[cert_set]["key_technology"]
                )
                self.assertEqual(
                    rval["modulus_md5"], self._cert_sets[cert_set]["pubkey_modulus_md5"]
                )
                self.assertEqual(
                    rval["spki_sha256"], self._cert_sets[cert_set]["spki_sha256"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_key > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_key > openssl fallback",
                        logged.output,
                    )

            # `cert_utils.parse_key__spki_sha256`
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                spki_sha256 = cert_utils.parse_key__spki_sha256(
                    key_pem=key_pem, key_pem_filepath=key_pem_filepath
                )
                self.assertEqual(spki_sha256, self._cert_sets[cert_set]["spki_sha256"])
                spki_sha256_b64 = cert_utils.parse_key__spki_sha256(
                    key_pem=key_pem, key_pem_filepath=key_pem_filepath, as_b64=True
                )
                self.assertEqual(
                    spki_sha256_b64, self._cert_sets[cert_set]["spki_sha256.b64"]
                )
                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_key__spki_sha256 > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_key__spki_sha256 > openssl fallback",
                        logged.output,
                    )

            # `cert_utils.parse_key__technology`
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                key_technology = cert_utils.parse_key__technology(
                    key_pem=key_pem, key_pem_filepath=key_pem_filepath
                )
                self.assertEqual(
                    key_technology, self._cert_sets[cert_set]["key_technology"]
                )
                if self._fallback_global or (not cert_utils.core.openssl_crypto):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.parse_key__technology > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.parse_key__technology > openssl fallback",
                        logged.output,
                    )

        # this will test against EC+RSA
        for key_filename in sorted(KEY_SETS.keys()):
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)

            # `cert_utils.parse_key`
            rval = cert_utils.parse_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(
                rval["key_technology"], KEY_SETS[key_filename]["key_technology"]
            )
            self.assertEqual(rval["modulus_md5"], KEY_SETS[key_filename]["modulus_md5"])
            self.assertEqual(rval["spki_sha256"], KEY_SETS[key_filename]["spki_sha256"])

            # `cert_utils.parse_key__spki_sha256`
            spki_sha256 = cert_utils.parse_key__spki_sha256(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(spki_sha256, KEY_SETS[key_filename]["spki_sha256"])
            spki_sha256_b64 = cert_utils.parse_key__spki_sha256(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath, as_b64=True
            )
            self.assertEqual(spki_sha256_b64, KEY_SETS[key_filename]["spki_sha256.b64"])

            # `cert_utils.parse_key__technology`
            key_technology = cert_utils.parse_key__technology(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(key_technology, KEY_SETS[key_filename]["key_technology"])

    def test__cert_and_chain_from_fullchain(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__cert_and_chain_from_fullchain
        """
        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            fullchain_filename = "unit_tests/cert_%s/fullchain.pem" % cert_set
            fullchain_pem_filepath = self._filepath_testfile(fullchain_filename)
            fullchain_pem = self._filedata_testfile(fullchain_filename)

            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)

            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                (_cert, _chain) = cert_utils.cert_and_chain_from_fullchain(
                    fullchain_pem
                )
                self.assertEqual(_cert, cert_pem)
                if self._fallback_global or (not cert_utils.core.certbot_crypto_util):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.cert_and_chain_from_fullchain > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.cert_and_chain_from_fullchain > openssl fallback",
                        logged.output,
                    )

    def test__analyze_chains(self):
        """
        This tests:
        * cert_utils.cert_and_chain_from_fullchain
        * cert_utils.decompose_chain
        * cert_utils.ensure_chain
        * cert_utils.ensure_chain_order
        """
        # test long chains
        long_chain_tests = [
            "TestA",
        ]
        for _test_id in long_chain_tests:
            _test_dir = "long_chains/%s" % _test_id
            _test_data_filename = "%s/_data.json" % _test_dir
            _test_data_filepath = self._filepath_testfile(_test_data_filename)
            _test_data = self._filedata_testfile(_test_data_filepath)
            _test_data = json.loads(_test_data)
            count_roots = _test_data["roots"]
            count_intermediates = _test_data["intermediates"]

            cert_filename = "%s/cert.pem" % _test_dir
            cert_pem = self._filedata_testfile(cert_filename)

            test_pems = {}
            for i in range(0, count_roots):
                root_filename = "%s/root_%s.pem" % (_test_dir, i)
                root_pem_filepath = self._filepath_testfile(root_filename)
                root_pem = self._filedata_testfile(root_pem_filepath)

                chain_filename = "%s/chain_%s.pem" % (_test_dir, i)
                chain_pem_filepath = self._filepath_testfile(chain_filename)
                chain_pem = self._filedata_testfile(chain_pem_filepath)

                test_pems[i] = {"root": root_pem, "chain": chain_pem}

            for idx in test_pems:
                # create a fullchain
                # cert_pem ends in a "\n"
                fullchain_pem = cert_pem + test_pems[idx]["chain"]

                # decompose a fullchain
                (_cert, _chain) = cert_utils.cert_and_chain_from_fullchain(
                    fullchain_pem
                )
                self.assertEqual(_cert, cert_pem)
                self.assertEqual(_chain, test_pems[idx]["chain"])

                with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                    _upstream_certs = cert_utils.decompose_chain(_chain)
                    self.assertEqual(len(_upstream_certs), count_intermediates)

                    _all_certs = cert_utils.decompose_chain(fullchain_pem)
                    self.assertEqual(len(_all_certs), count_intermediates + 1)
                    if self._fallback_global or (not cert_utils.core.openssl_crypto):
                        self.assertIn(
                            "DEBUG:cert_utils.core:.decompose_chain > openssl fallback",
                            logged.output,
                        )
                    else:
                        self.assertNotIn(
                            "DEBUG:cert_utils.core:.decompose_chain > openssl fallback",
                            logged.output,
                        )

                # `ensure_chain` can accept two types of data
                root_pem = test_pems[idx]["root"]
                with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                    self.assertTrue(
                        cert_utils.ensure_chain(
                            root_pem=root_pem, chain_pem=_chain, cert_pem=cert_pem
                        )
                    )
                    self.assertTrue(
                        cert_utils.ensure_chain(
                            root_pem=root_pem, fullchain_pem=fullchain_pem
                        )
                    )
                    if self._fallback_global or (not cert_utils.core.openssl_crypto):
                        self.assertIn(
                            "DEBUG:cert_utils.core:.ensure_chain > openssl fallback",
                            logged.output,
                        )
                    else:
                        self.assertNotIn(
                            "DEBUG:cert_utils.core:.ensure_chain > openssl fallback",
                            logged.output,
                        )

                # `ensure_chain` will not accept user error
                # fullchain error
                _error_expected = "If `ensure_chain` is invoked with `fullchain_pem`, do not pass in `chain_pem` or `cert_pem`."
                # invoking `fullchain_pem` with: `chain_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem, fullchain_pem=fullchain_pem, chain_pem=_chain
                    )
                self.assertEqual(cm.exception.args[0], _error_expected)
                # invoking `fullchain_pem` with: `cert_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem,
                        fullchain_pem=fullchain_pem,
                        cert_pem=cert_pem,
                    )
                self.assertEqual(cm.exception.args[0], _error_expected)
                # invoking `fullchain_pem` with: `cert_pem` and `chain_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem,
                        fullchain_pem=fullchain_pem,
                        chain_pem=_chain,
                        cert_pem=cert_pem,
                    )
                self.assertEqual(cm.exception.args[0], _error_expected)
                # NO fullchain error
                _error_expected = "If `ensure_chain` is not invoked with `fullchain_pem`, you must pass in `chain_pem` and `cert_pem`."
                # invoking NO `fullchain_pem` with: `chain_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem, chain_pem=_chain
                    )
                self.assertEqual(cm.exception.args[0], _error_expected)
                # invoking NO `fullchain_pem` with: `cert_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem, cert_pem=cert_pem
                    )

                # ENSURE THE CHAIN ORDER
                # forward: YAY!
                _all_certs = cert_utils.decompose_chain(fullchain_pem)
                with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                    cert_utils.ensure_chain_order(_all_certs)
                    if self._fallback_global or (not cert_utils.core.openssl_crypto):
                        self.assertIn(
                            "DEBUG:cert_utils.core:.ensure_chain_order > openssl fallback",
                            logged.output,
                        )
                    else:
                        self.assertNotIn(
                            "DEBUG:cert_utils.core:.ensure_chain_order > openssl fallback",
                            logged.output,
                        )
                # reverse: nay :(
                _all_certs_reversed = _all_certs[::-1]
                with self.assertRaises(OpenSslError) as cm:
                    cert_utils.ensure_chain_order(_all_certs_reversed)
                self.assertTrue(cm.exception.args[0].startswith("could not verify:"))

    def test__convert_lejson_to_pem(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__convert_lejson_to_pem
        """
        for account_set in sorted(self._account_sets.keys()):
            if not self._account_sets[account_set]["letsencrypt"]:
                continue
            if not self._account_sets[account_set]["pem"]:
                raise ValueError("need pem")

            # load the json
            key_jsons_filename = "unit_tests/account_%s/private_key.json" % account_set
            key_jsons_filepath = self._filepath_testfile(key_jsons_filename)
            key_jsons = self._filedata_testfile(key_jsons_filepath)

            # load the pem
            key_pem_filename = "unit_tests/account_%s/private_key.pem" % account_set
            key_pem_filepath = self._filepath_testfile(key_pem_filename)
            key_pem = self._filedata_testfile(key_pem_filepath)

            # convert
            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                rval = cert_utils.convert_lejson_to_pem(key_jsons)
            if (
                self._fallback_global
                or (not cert_utils.core.crypto_serialization)
                or (not cert_utils.core.josepy)
            ):
                self.assertIn(
                    "DEBUG:cert_utils.core:.convert_lejson_to_pem > openssl fallback",
                    logged.output,
                )
            else:
                self.assertNotIn(
                    "DEBUG:cert_utils.core:.convert_lejson_to_pem > openssl fallback",
                    logged.output,
                )

            # compare
            self.assertEqual(rval, key_pem)

    def test__account_key__parse(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__account_key__parse
        """
        for account_set in sorted(self._account_sets.keys()):
            if not self._account_sets[account_set]["pem"]:
                raise ValueError("need pem")

            # load the pem
            key_pem_filename = "unit_tests/account_%s/private_key.pem" % account_set
            key_pem_filepath = self._filepath_testfile(key_pem_filename)
            key_pem = self._filedata_testfile(key_pem_filepath)

            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                rval = cert_utils.account_key__parse(
                    key_pem=key_pem, key_pem_filepath=key_pem_filepath
                )
                if self._fallback_global or (not cert_utils.core.josepy):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.account_key__parse > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.account_key__parse > openssl fallback",
                        logged.output,
                    )

    def test__account_key__sign(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__account_key__sign
        """
        for account_set in sorted(self._account_sets.keys()):
            if not self._account_sets[account_set]["pem"]:
                raise ValueError("need pem")

            # load the pem
            key_pem_filename = "unit_tests/account_%s/private_key.pem" % account_set
            key_pem_filepath = self._filepath_testfile(key_pem_filename)
            key_pem = self._filedata_testfile(key_pem_filepath)

            input = self._account_sets[account_set]["signature.input"]
            expected = self._account_sets[account_set]["signature.output"]

            with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
                signature = cert_utils.account_key__sign(
                    input, key_pem=key_pem, key_pem_filepath=key_pem_filepath
                )
                signature = cert_utils.jose_b64(signature)
                self.assertEqual(signature, expected)

                if (
                    self._fallback_global
                    or (not cert_utils.core.openssl_crypto)
                    or (not cert_utils.core.crypto_rsa)
                    or (not cert_utils.core.cryptography)
                ):
                    self.assertIn(
                        "DEBUG:cert_utils.core:.account_key__sign > openssl fallback",
                        logged.output,
                    )
                else:
                    self.assertNotIn(
                        "DEBUG:cert_utils.core:.account_key__sign > openssl fallback",
                        logged.output,
                    )

    def test__private_key__new(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__private_key__new
        """
        _combinations = (
            (model.KeyTechnology.RSA, 2048, None),
            (model.KeyTechnology.RSA, 3072, None),
            (model.KeyTechnology.RSA, 4096, None),
            (model.KeyTechnology.EC, None, 256),
            (model.KeyTechnology.EC, None, 384),
        )
        for _combo in _combinations:
            key_pem = cert_utils.new_private_key(
                _combo[0], rsa_bits=_combo[1], ec_bits=_combo[2]
            )
            if _combo[0] == model.KeyTechnology.RSA:
                # crypto: -----BEGIN PRIVATE KEY-----
                # openssl fallback: -----BEGIN RSA PRIVATE KEY-----
                self.assertIn(
                    key_pem.split("\n")[0],
                    (
                        "-----BEGIN RSA PRIVATE KEY-----",
                        "-----BEGIN PRIVATE KEY-----",
                    ),
                )
            elif _combo[0] == model.KeyTechnology.RSA:
                self.assertEqual(
                    "-----BEGIN EC PRIVATE KEY-----", key_pem.split("\n")[0]
                )

    def test_new_key_ec(self):
        # test no bits
        with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
            key_pem = cert_utils.new_key_ec()
            self.assertIn("-----BEGIN EC PRIVATE KEY-----", key_pem)
            if (
                self._fallback_global
                or (not cert_utils.core.crypto_ec)
                or (not cert_utils.core.crypto_serialization)
            ):
                self.assertIn(
                    "DEBUG:cert_utils.core:.new_key_ec > openssl fallback",
                    logged.output,
                )
            else:
                self.assertNotIn(
                    "DEBUG:cert_utils.core:.new_key_ec > openssl fallback",
                    logged.output,
                )

        # test valid bits
        key_pem = cert_utils.new_key_ec(bits=256)
        self.assertIn("-----BEGIN EC PRIVATE KEY-----", key_pem)
        key_pem = cert_utils.new_key_ec(bits=384)
        self.assertIn("-----BEGIN EC PRIVATE KEY-----", key_pem)

        # test invalid bits
        with self.assertRaises(ValueError) as cm:
            key_pem = cert_utils.new_key_ec(bits=1)
        self.assertIn(
            "LetsEncrypt only supports ECDSA keys with bits:", cm.exception.args[0]
        )

    def test_new_key_rsa(self):
        # test no bits

        def _key_compliance(key_pem: str):
            # crypto: -----BEGIN PRIVATE KEY-----
            # openssl fallback: -----BEGIN RSA PRIVATE KEY-----
            self.assertIn(
                key_pem.split("\n")[0],
                (
                    "-----BEGIN RSA PRIVATE KEY-----",
                    "-----BEGIN PRIVATE KEY-----",
                ),
            )

        with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
            key_pem = cert_utils.new_key_rsa()
            _key_compliance(key_pem)
            if self._fallback_global or (not cert_utils.core.certbot_crypto_util):
                self.assertIn(
                    "DEBUG:cert_utils.core:.new_key_rsa > openssl fallback",
                    logged.output,
                )
            else:
                self.assertNotIn(
                    "DEBUG:cert_utils.core:.new_key_rsa > openssl fallback",
                    logged.output,
                )

        # test valid bits
        key_pem = cert_utils.new_key_rsa(bits=2048)
        _key_compliance(key_pem)

        key_pem = cert_utils.new_key_rsa(bits=3072)
        _key_compliance(key_pem)

        key_pem = cert_utils.new_key_rsa(bits=4096)
        _key_compliance(key_pem)

        # test invalid bits
        with self.assertRaises(ValueError) as cm:
            key_pem = cert_utils.new_key_rsa(bits=1)
        self.assertIn(
            "LetsEncrypt only supports RSA keys with bits:", cm.exception.args[0]
        )

    def test_convert_pkcs7_to_pems(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test_convert_pkcs7_to_pems
        python -m unittest tests.test_unit.UnitTest_CertUtils_fallback.test_convert_pkcs7_to_pems
        """
        fname_pkcs7 = "letsencrypt-certs/trustid-x3-root.p7c"
        fpath_pkcs7 = self._filepath_testfile(fname_pkcs7)
        fdata_pkcs7 = self._filedata_testfile(fname_pkcs7, is_binary=True)
        with self.assertLogs("cert_utils.core", level="DEBUG") as logged:
            pkcs7_pems = cert_utils.convert_pkcs7_to_pems(fdata_pkcs7)
            if (
                self._fallback_global
                or (not cert_utils.core.crypto_pkcs7)
                or (not cert_utils.core.crypto_serialization)
            ):
                self.assertIn(
                    "DEBUG:cert_utils.core:.convert_pkcs7_to_pems > openssl fallback",
                    logged.output,
                )
            else:
                self.assertNotIn(
                    "DEBUG:cert_utils.core:.convert_pkcs7_to_pems > openssl fallback",
                    logged.output,
                )

        fname_pem = "letsencrypt-certs/trustid-x3-root.pem"
        fpath_pem = self._filedata_testfile(fname_pem)
        fdata_pem = self._filedata_testfile(fname_pem)
        pem_pem = cert_utils.cleanup_pem_text(fdata_pem)
        self.assertEqual(len(pkcs7_pems), 1)
        self.assertEqual(pkcs7_pems[0], pem_pem)

    def test_convert_pkix_to_pem(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test_convert_pkix_to_pem
        python -m unittest tests.test_unit.UnitTest_CertUtils_fallback.test_convert_pkix_to_pem
        """
        fname_pkix = "letsencrypt-certs/isrgrootx1.pkix"
        fpath_pkix = self._filepath_testfile(fname_pkix)
        fdata_pkix = self._filedata_testfile(fname_pkix, is_binary=True)
        pkix_pem = cert_utils.convert_der_to_pem(fdata_pkix)

        fname_pem = "letsencrypt-certs/isrgrootx1.pem"
        fpath_pem = self._filedata_testfile(fname_pem)
        fdata_pem = self._filedata_testfile(fname_pem)
        pem_pem = cert_utils.cleanup_pem_text(fdata_pem)

        self.assertEqual(pkix_pem, pem_pem)


class UnitTest_OpenSSL(unittest.TestCase, _Mixin_fallback_possible, _Mixin_filedata):
    """python -m unittest tests.test_unit.UnitTest_OpenSSL"""

    def test_modulus_PrivateKey(self):
        """
        modulus_md5_key is covered in the CertUtils tests. not sure why we have this
        """
        for pkey_set_id, set_data in sorted(TEST_FILES["PrivateKey"].items()):
            key_pem_filepath = self._filepath_testfile(set_data["file"])
            key_pem = self._filedata_testfile(key_pem_filepath)
            _computed_modulus_md5 = cert_utils.modulus_md5_key(
                key_pem=key_pem,
                key_pem_filepath=key_pem_filepath,
            )
            _expected_modulus_md5 = set_data["key_pem_modulus_md5"]
            assert _computed_modulus_md5 == _expected_modulus_md5
            _computed_md5 = cert_utils.utils.md5_text(
                self._filedata_testfile(key_pem_filepath)
            )
            _expected_md5 = set_data["key_pem_md5"]
            assert _computed_md5 == _expected_md5

        # this will test against EC+RSA
        for key_filename in sorted(KEY_SETS.keys()):
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            _computed_modulus_md5 = cert_utils.modulus_md5_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            _expected_modulus_md5 = KEY_SETS[key_filename]["modulus_md5"]
            assert _computed_modulus_md5 == _expected_modulus_md5


class UnitTest_CertUtils_fallback(_MixinNoCrypto, UnitTest_CertUtils):
    """python -m unittest tests.test_unit.UnitTest_CertUtils_fallback"""

    pass


@unittest.skipUnless(EXTENDED_TESTS, "Extended tests disabled")
class UnitTest_CertUtils_fallback_acme(_Mixin_Missing_acme, UnitTest_CertUtils):
    """python -m unittest tests.test_unit.UnitTest_CertUtils_fallback_acme"""

    pass


@unittest.skipUnless(EXTENDED_TESTS, "Extended tests disabled")
class UnitTest_CertUtils_fallback_missing_acme(_Mixin_Missing_acme, UnitTest_CertUtils):
    """python -m unittest tests.test_unit.UnitTest_CertUtils_fallback_missing_acme"""

    pass


@unittest.skipUnless(EXTENDED_TESTS, "Extended tests disabled")
class UnitTest_CertUtils_fallback_missing_certbot(
    _Mixin_Missing_certbot, UnitTest_CertUtils
):
    """python -m unittest tests.test_unit.UnitTest_CertUtils_fallback_missing_certbot"""

    pass


@unittest.skipUnless(EXTENDED_TESTS, "Extended tests disabled")
class UnitTest_CertUtils_fallback_missing_cryptography(
    _Mixin_Missing_cryptography, UnitTest_CertUtils
):
    """python -m unittest tests.test_unit.UnitTest_CertUtils_fallback_missing_cryptography"""

    pass


@unittest.skipUnless(EXTENDED_TESTS, "Extended tests disabled")
class UnitTest_CertUtils_fallback_missing_josepy(
    _Mixin_Missing_josepy, UnitTest_CertUtils
):
    """python -m unittest tests.test_unit.UnitTest_CertUtils_fallback_missing_josepy"""

    pass


@unittest.skipUnless(EXTENDED_TESTS, "Extended tests disabled")
class UnitTest_CertUtils_fallback_missing_openssl_crypto(
    _Mixin_Missing_openssl_crypto, UnitTest_CertUtils
):
    """python -m unittest tests.test_unit.UnitTest_CertUtils_fallback_missing_openssl_crypto"""

    pass


class UnitTest_OpenSSL_fallback(_MixinNoCrypto, UnitTest_OpenSSL):
    """python -m unittest tests.test_unit.UnitTest_OpenSSL_fallback"""

    pass


class UnitTest_api(unittest.TestCase):
    """python -m unittest tests.test_unit.UnitTest_api"""

    def test_check_openssl_version(self):
        """
        # this is not set until used, but we can't trust the execution order
        import cert_utils
        _original = cert_utils.core.openssl_version
        self.assertIsNone(_original)
        """
        # invoking `check` will return the new version
        active = cert_utils.check_openssl_version()
        # first invocation should set the value
        self.assertEqual(active, cert_utils.core.openssl_version)

        # let's try to replace it
        cert_utils.core.openssl_version = "x"
        self.assertEqual("x", cert_utils.core.openssl_version)
        new = cert_utils.check_openssl_version(replace=True)
        self.assertEqual(active, new)
        self.assertEqual(new, cert_utils.core.openssl_version)


class UnitTest_utils(unittest.TestCase):
    """python -m unittest tests.test_unit.UnitTest_utils"""

    def test_validate_domains__valid(self):
        domains = (
            "EXAMPLE.com",
            "example.com",
            "foo.example.com",
            "test-1.example.com",
        )
        for d in domains:
            # validate domains expects a list
            utils.validate_domains(
                [
                    d,
                ]
            )

    def test_validate_domains__invalid(self):
        domains = (
            "-EXAMPLE.com",
            "example.com-",
            "example.com.",
            ".example.com.",
            "test_1.example.com",
        )
        for d in domains:
            # validate domains expects a list
            with self.assertRaises(ValueError) as cm:
                utils.validate_domains(
                    [
                        d,
                    ]
                )
