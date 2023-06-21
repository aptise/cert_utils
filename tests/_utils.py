# stdlib
import os
from typing import Union

# local
import cert_utils

# ==============================================================================


CERT_CA_SETS = {
    "letsencrypt-certs/trustid-x3-root.pem": {
        "key_technology": "RSA",
        "modulus_md5": "35f72cb35ea691144ffc2798db20ccfd",
        "spki_sha256": "563B3CAF8CFEF34C2335CAF560A7A95906E8488462EB75AC59784830DF9E5B2B",
        "spki_sha256.b64": "Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=",
        "cert.fingerprints": {
            "sha1": "DAC9024F54D8F6DF94935FB1732638CA6AD77C13",
        },
        "subject": "O=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "issuer": "O=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "issuer_uri": None,
        "authority_key_identifier": None,
    },
    "letsencrypt-certs/isrgrootx1.pem": {
        "key_technology": "RSA",
        "modulus_md5": "9454972e3730ac131def33e045ab19df",
        "spki_sha256": "0B9FA5A59EED715C26C1020C711B4F6EC42D58B0015E14337A39DAD301C5AFC3",
        "spki_sha256.b64": "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
        "cert.fingerprints": {
            "sha1": "CABD2A79A1076A31F21D253635CB039D4329A5E8",
        },
        "subject": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "issuer": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "issuer_uri": None,
        "authority_key_identifier": None,
    },
    "letsencrypt-certs/isrg-root-x1-cross-signed.pem": {
        "key_technology": "RSA",
        "modulus_md5": "9454972e3730ac131def33e045ab19df",
        "spki_sha256": "0B9FA5A59EED715C26C1020C711B4F6EC42D58B0015E14337A39DAD301C5AFC3",
        "spki_sha256.b64": "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
        "cert.fingerprints": {
            "sha1": "933C6DDEE95C9C41A40F9F50493D82BE03AD87BF",
        },
        "subject": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "issuer": "O=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "issuer_uri": "http://apps.identrust.com/roots/dstrootcax3.p7c",
        "authority_key_identifier": "C4A7B1A47B2C71FADBE14B9075FFC41560858910",
    },
    "letsencrypt-certs/isrg-root-x2.pem": {
        "key_technology": "EC",
        "modulus_md5": None,
        "spki_sha256": "762195C225586EE6C0237456E2107DC54F1EFC21F61A792EBD515913CCE68332",
        "spki_sha256.b64": "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
        "cert.fingerprints": {
            "sha1": "BDB1B93CD5978D45C6261455F8DB95C75AD153AF",
        },
        "subject": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X2",
        "issuer": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X2",
        "issuer_uri": None,
        "authority_key_identifier": None,
    },
    "letsencrypt-certs/isrg-root-x2-cross-signed.pem": {
        "key_technology": "EC",
        "modulus_md5": None,
        "spki_sha256": "762195C225586EE6C0237456E2107DC54F1EFC21F61A792EBD515913CCE68332",
        "spki_sha256.b64": "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
        "cert.fingerprints": {
            "sha1": "151682F5218C0A511C28F4060A73B9CA78CE9A53",
        },
        "subject": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X2",
        "issuer": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "issuer_uri": "http://x1.i.lencr.org/",
        "authority_key_identifier": "79B459E67BB6E5E40173800888C81A58F6E99B6E",
    },
    "letsencrypt-certs/lets-encrypt-r3-cross-signed.pem": {
        "key_technology": "RSA",
        "spki_sha256": "8D02536C887482BC34FF54E41D2BA659BF85B341A0A20AFADB5813DCFBCF286D",
        "spki_sha256.b64": "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=",
        "modulus_md5": "7d877784604ba0a5e400e5da7ec048e4",
        "cert.fingerprints": {
            "sha1": "48504E974C0DAC5B5CD476C8202274B24C8C7172",
        },
        "subject": "C=US\nO=Let's Encrypt\nCN=R3",
        "issuer": "O=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "issuer_uri": "http://apps.identrust.com/roots/dstrootcax3.p7c",
        "authority_key_identifier": "C4A7B1A47B2C71FADBE14B9075FFC41560858910",
    },
}


CSR_SETS = {
    "key_technology-ec/ec384-1.csr": {
        "key_private": {
            "file": "key_technology-ec/ec384-1-key.pem",
            "key_technology": "EC",
            "modulus_md5": None,
        },
        "modulus_md5": "e69f1df0d5a5c7c63e81a83c4f5411a7",
    },
    "key_technology-rsa/selfsigned_1-server.csr": {
        "key_private": {
            "file": "key_technology-rsa/selfsigned_1-server.csr",
            "key_technology": "RSA",
            "modulus_md5": "e0d99ec6424d5182755315d56398f658",
        },
        "modulus_md5": "e0d99ec6424d5182755315d56398f658",
    },
}

KEY_SETS = {
    "key_technology-rsa/acme_account_1.key": {
        "key_technology": "RSA",
        "modulus_md5": "ceec56ad4caba2cd70ee90c7d80fbb74",
        "spki_sha256": "E70DCB45009DF3F79FC708B46888609E34A3D8D19AEAFA566389718A29140782",
        "spki_sha256.b64": "5w3LRQCd8/efxwi0aIhgnjSj2NGa6vpWY4lxiikUB4I=",
    },
    "key_technology-ec/ec384-1-key.pem": {
        "key_technology": "EC",
        "modulus_md5": None,
        "spki_sha256": "E739FB0081868C97B8AC0D3773680974E9FCECBFA1FC8B80AFDDBE42F30D1D9D",
        "spki_sha256.b64": "5zn7AIGGjJe4rA03c2gJdOn87L+h/IuAr92+QvMNHZ0=",
    },
}


TEST_FILES = {
    "PrivateKey": {
        "1": {
            "file": "key_technology-rsa/private_1.key",
            "key_pem_md5": "462dc10731254d7f5fa7f0e99cbece73",
            "key_pem_modulus_md5": "fc1a6c569cba199eb5341c0c423fb768",
        },
        "2": {
            "file": "key_technology-rsa/private_2.key",
            "key_pem_md5": "cdde9325bdbfe03018e4119549c3a7eb",
            "key_pem_modulus_md5": "397282f3cd67d33b2b018b61fdd3f4aa",
        },
        "3": {
            "file": "key_technology-rsa/private_3.key",
            "key_pem_md5": "399236401eb91c168762da425669ad06",
            "key_pem_modulus_md5": "112d2db5daba540f8ff26fcaaa052707",
        },
        "4": {
            "file": "key_technology-rsa/private_4.key",
            "key_pem_md5": "6867998790e09f18432a702251bb0e11",
            "key_pem_modulus_md5": "687f3a3659cd423c48c50ed78a75eba0",
        },
        "5": {
            "file": "key_technology-rsa/private_5.key",
            "key_pem_md5": "1b13814854d8cee8c64732a2e2f7e73e",
            "key_pem_modulus_md5": "1eee27c04e912ff24614911abd2f0f8b",
        },
    },
}


# ------------------------------------------------------------------------------


class _Mixin_filedata(object):
    _data_root = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data")
    _data_root_letsencrypt = os.path.join(
        os.path.dirname(os.path.realpath(cert_utils.__file__)),
        "letsencrypt-certs",
    )

    def _filepath_testfile(self, filename: str) -> str:
        if filename.startswith("letsencrypt-certs/"):
            filename = filename[18:]
            return os.path.join(self._data_root_letsencrypt, filename)
        return os.path.join(self._data_root, filename)

    def _filedata_testfile(
        self, filename: str, is_binary: bool = False
    ) -> Union[str, bytes]:
        _data_root = self._data_root
        if filename.startswith("letsencrypt-certs/"):
            filename = filename[18:]
            _data_root = self._data_root_letsencrypt
        if is_binary:
            with open(os.path.join(_data_root, filename), "rb") as f:
                data = f.read()
        else:
            with open(os.path.join(_data_root, filename), "rt", encoding="utf-8") as f:
                data = f.read()
        return data
