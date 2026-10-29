"""
This file contains the following:

* Information on the LetsEncrypt Trust Chain
* A routine to load the LetsEncrypt Certificates into Python

Because this loads Certificates into memory for some operations, it should
generally not be imported.
"""

# stdlib
import copy
import os
from typing import Any
from typing import Dict
from typing import Optional

# pypi
import requests

# localapp
from .types import CERT_CA_PAYLOAD
from ..network import get_timeout
from ..network import Timeout
from ..utils import cleanup_pem_text
from ..utils import md5_text

# ==============================================================================


# certificates are published online
# https://letsencrypt.org/certificates/
# last checked: 2026.10.28 (website checkout bb7e7238; certificates page 2026-07-08)

# this info is checked for compliance with
# * tests.test_unit.UnitTest_LetsEncrypt_Data


CERT_CAS_VERSION = 5  # update when the information below changes
"""
format details:

the KEY in the dictionary is a unique string

the payload can have one of these two values, which reference another key:
    "alternates": ["isrg_root_x2_cross"],
    "alternate_of": "isrg_root_x2",

Special Values
    ".enddate": the args to datetime.datetime()

Compatibility Info
    via https://letsencrypt.org/docs/certificate-compatibility/
    Last updated: Jan 21, 2021

["cert.fingerprints"]["sha1"] = `openssl x509 -fingerprint -sha1 -noout -in isrg-root-x2.pem`

"""

CERT_CAS_DEPRECATED: Dict[str, CERT_CA_PAYLOAD] = {
    "trustid_root_x3": {
        "display_name": "DST Root CA X3",
        "url_pem": "https://letsencrypt.org/certs/trustid-x3-root.pem",
        "is_trusted_root": True,
        "is_self_signed": True,
        "signed_by": "trustid_root_x3",
        "is_active": False,
        "key_technology": "RSA",
        "cert.fingerprints": {
            "sha1": "DAC9024F54D8F6DF94935FB1732638CA6AD77C13",
            "sha256": "0687260331A72403D909F105E69BCF0D32E1BD2493FFC6D9206D11BCD6770739",
        },
        ".enddate": (2021, 9, 30, 14, 1, 15),
        "compatibility": {
            "Windows": (">= XP SP3", None, None),
            "macOS": ("(most versions)", None, None),
            "iOS": ("(most versions)", None, None),
            "Android": (">= v2.3.6", None, None),
            "Mozilla Firefox": (">= v2.0", None, None),
            "Ubuntu": (">= precise / 12.04", None, None),
            "Debian": (">= squeee / 6", None, None),
            "Java 8": (">= 8u101", None, None),
            "Java 7": (">= 7u111", None, None),
            "NSS": (">= v3.11.9", None, None),
            "Amazon FireOS (Silk Browser)": ("?", None, None),
            "Cyanogen": ("> v10", None, None),
            "Jolla Sailfish OS": ("> v1.1.2.16", None, None),
            "Kindle": ("> v3.4.1", None, None),
            "Blackberry": (">= 10.3.3", None, None),
            "PS4 game console": ("with firmware >= 5.00", None, None),
        },
        "is_retired": True,
    },
    "isrg_root_x1_cross": {
        "display_name": "ISRG Root X1 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-x1-cross-signed.pem",
        "is_trusted_root": False,
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "isrg_root_x1",
        "cert.fingerprints": {
            "sha1": "933C6DDEE95C9C41A40F9F50493D82BE03AD87BF",
            "sha256": "6D99FB265EB1C5B3744765FCBC648F3CD8E1BFFAFDC4C2F99B9D47CF7FF1C24F",
        },
        ".enddate": (2024, 9, 30, 18, 14, 3),
        "is_self_signed": False,
    },
    "letsencrypt_ocsp_root_x1": {
        "display_name": "Let's Encrypt OSCP Root X1",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-ocsp-x1.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "cert.fingerprints": {
            "sha1": "7D2671CBB2F689F0E88389DE2880FA1BD0857582",
            "sha256": "F21BC92040EC5DBAA820418A24936628FF87C177E1A5D8AB41FA7EE1FF812642",
        },
        ".enddate": (2025, 6, 10, 13, 4, 11),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_x1": {
        "display_name": "Let's Encrypt Authority X1",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx1.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_x1_cross"],
        "letsencrypt_serial": "x1",
        "cert.fingerprints": {
            "sha1": "E045A5A959F42780FA5BD7623512AF276CF42F20",
            "sha256": "BDEE0D7C8F9C278F14EA9B6A4F90ED665A9F56DB0A56B1CDDA6765912F398A5E",
        },
        ".enddate": (2020, 6, 4, 12, 0, 20),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_x1_cross": {
        "display_name": "Let's Encrypt Authority X1 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_x1",
        "letsencrypt_serial": "x1",
        "cert.fingerprints": {
            "sha1": "3EAE91937EC85D74483FF4B77B07B43E2AF36BF4",
            "sha256": "7FDCE3BF4103C2684B3ADBB5792884BD45C75094C217788863950346F79C90A3",
        },
        ".enddate": (2020, 10, 19, 22, 33, 36),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_x2": {
        "display_name": "Let's Encrypt Authority X2",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx2.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_x2_cross"],
        "letsencrypt_serial": "x2",
        "cert.fingerprints": {
            "sha1": "3A7A7D70C08997BC33161744A5B7C24AD8F67B1B",
            "sha256": "E4EB54A7FFA552EF64D8E1AE338B69BE909C29E6AF57170A2F6F44DF225E5A14",
        },
        ".enddate": (2020, 6, 4, 12, 0, 31),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_x2_cross": {
        "display_name": "Let's Encrypt Authority X2 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_x2",
        "letsencrypt_serial": "x2",
        "cert.fingerprints": {
            "sha1": "02007A05CED36899AA8A03A2CF307F1C0449FC31",
            "sha256": "EC0C6CA496A67A13342FEC5221F68D4B3E53B1BC22F6E4BCCC9C68F0415CDEA4",
        },
        ".enddate": (2020, 10, 19, 22, 35, 1),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_x3": {
        "display_name": "Let's Encrypt Authority X3",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx3.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_x3_cross"],
        "letsencrypt_serial": "x3",
        "cert.fingerprints": {
            "sha1": "1B23675354FCAD90119D88075015EA17ADD527D8",
            "sha256": "731D3D9CFAA061487A1D71445A42F67DF0AFCA2A6C2D2F98FF7B3CE112B1F568",
        },
        ".enddate": (2021, 10, 6, 15, 43, 55),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_x3_cross": {
        "display_name": "Let's Encrypt Authority X3 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_x3",
        "letsencrypt_serial": "x3",
        "cert.fingerprints": {
            "sha1": "E6A3B45B062D509B3382282D196EFE97D5956CCB",
            "sha256": "25847D668EB4F04FDD40B12B6B0740C567DA7D024308EB6C2C96FE41D9DE218D",
        },
        ".enddate": (2021, 3, 17, 16, 40, 46),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_x4": {
        "display_name": "Let's Encrypt Authority X4",
        "url_pem": "https://letsencrypt.org/certs/letsencryptauthorityx4.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_x4_cross"],
        "letsencrypt_serial": "x4",
        "cert.fingerprints": {
            "sha1": "77D6B59A84C605DF62B03ECB28DC168C50A93E98",
            "sha256": "5DE9152BED31FA0515DD1FC746133F1327562EF72A84CF2D2403E748A604D0D4",
        },
        ".enddate": (2021, 10, 6, 15, 44, 34),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_x4_cross": {
        "display_name": "Let's Encrypt Authority X4 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_x4",
        "letsencrypt_serial": "x4",
        "cert.fingerprints": {
            "sha1": "C05E2471E589A57053F2747EE06A593C513E23A5",
            "sha256": "A74B0C32B65B95FE2C4F8F098947A68B695033BED0B51DD8B984ECAE89571BB6",
        },
        ".enddate": (2021, 3, 17, 16, 41, 2),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_r3": {
        "display_name": "Let's Encrypt R3",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_r3_cross"],
        "letsencrypt_serial": "r3",
        "cert.fingerprints": {
            "sha1": "A053375BFE84E8B748782C7CEE15827A6AF5A405",
            "sha256": "67ADD1166B020AE61B8F5FC96813C04C2AA589960796865572A3C7E737613DFD",
        },
        ".enddate": (2025, 9, 15, 16, 0, 0),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_r3_cross": {
        "display_name": "Let's Encrypt R3 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_r3",
        "letsencrypt_serial": "r3",
        "cert.fingerprints": {
            "sha1": "48504E974C0DAC5B5CD476C8202274B24C8C7172",
            "sha256": "730C1BDCD85F57CE5DC0BBA733E5F1BA5A925B2A771D640A26F7A454224DAD3B",
        },
        ".enddate": (2021, 9, 29, 19, 21, 40),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_r4": {
        "display_name": "Let's Encrypt R4",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r4.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "alternates": ["letsencrypt_intermediate_r4_cross"],
        "letsencrypt_serial": "r4",
        "cert.fingerprints": {
            "sha1": "4D7F2DE64A8E44394FEC4A7DC8CDC498230DB829",
            "sha256": "1A07529A8B3F01D231DFAD2ABDF71899200BB65CD7E03C59FA82272533355B74",
        },
        ".enddate": (2025, 9, 15, 16, 0, 0),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_r4_cross": {
        "display_name": "Let's Encrypt R4 (IdenTrust cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-r4-cross-signed.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "RSA",
        "signed_by": "trustid_root_x3",
        "alternate_of": "letsencrypt_intermediate_r4",
        "letsencrypt_serial": "r4",
        "cert.fingerprints": {
            "sha1": "F99ABE21CDB1823C54C272E2B4904D263E8A8BFF",
            "sha256": "5A8F16FDA448D783481CCA57A2428D174DAD8C60943CEB28F661AE31FD39A5FA",
        },
        ".enddate": (2021, 9, 29, 19, 21, 45),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_e1": {
        "display_name": "Let's Encrypt E1",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-e1.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "EC",
        "signed_by": "isrg_root_x2",
        "letsencrypt_serial": "e1",
        "cert.fingerprints": {
            "sha1": "091E8EA1B256A312962AF6C140C0FBF079A407B3",
            "sha256": "46494E30379059DF18BE52124305E606FC59070E5B21076CE113954B60517CDA",
        },
        ".enddate": (2025, 9, 15, 16, 0, 0),
        "is_self_signed": False,
    },
    "letsencrypt_intermediate_e2": {
        "display_name": "Let's Encrypt E2",
        "url_pem": "https://letsencrypt.org/certs/lets-encrypt-e2.pem",
        "is_active": False,
        "is_retired": True,
        "key_technology": "EC",
        "signed_by": "isrg_root_x2",
        "letsencrypt_serial": "e2",
        "cert.fingerprints": {
            "sha1": "9A40DBEB347E861D523A707436225E16D5000133",
            "sha256": "BACDE0463053CE1D62F8BE74370BBAE79D4FCAF19FC07643AEF195E6A59BD578",
        },
        ".enddate": (2025, 9, 15, 16, 0, 0),
        "is_self_signed": False,
    },
    "staging_letsencrypt_root_x1": {
        "display_name": "Fake LE Root X1",
        "url_pem": "https://letsencrypt.org/certs/fakelerootx1.pem",
        "is_trusted_root": True,
        "is_untrusted_root": True,
        "is_self_signed": True,
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "staging_letsencrypt_root_x1",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "B3F73C419DAC14711F4B97192BF89C7DEA7A7794",
            "sha256": "219C4FFCFB04F1D3AD6CA79B2B5C6C0F4493177A80FA37CCE7FC9A32DF28323D",
        },
        ".enddate": (2036, 3, 23, 22, 53, 46),
    },
    "staging_letsencrypt_intermediate_x1": {
        "display_name": "Fake LE Intermediate X1",
        "url_pem": "https://letsencrypt.org/certs/fakeleintermediatex1.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "staging_letsencrypt_root_x1",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "4EEE7398C1A3DAF91DA16689DB8243927A271B9A",
            "sha256": "A99C1B71DA32ADD9429714F71E740AFDC543C4F7F012A748D24A789B8BF3D6C7",
        },
        ".enddate": (2036, 5, 23, 22, 7, 59),
        "is_self_signed": False,
    },
    "e5": {
        "display_name": "Let's Encrypt E5",
        "url_pem": "https://letsencrypt.org/certs/2024/e5.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x2",
        "alternates": ["e5_cross"],
        "letsencrypt_serial": "e5",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "9B9C585F17E3EAE626D4583FC40DE7698A3D3B59",
            "sha256": "E788D14B0436B5120BBEE3F15C15BADF08C1407FE72568A4F16F9151C380E1E3",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "e5_cross": {
        "display_name": "Let's Encrypt E5 (X1 cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/2024/e5-cross.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x1",
        "alternate_of": "e5",
        "letsencrypt_serial": "e5",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "5F28D9C589EE4BF31A11B78C72B8D13F079DDC45",
            "sha256": "5DFDB3CF31B26F23D87C09F3A0CEF642F64069A9FB7CFE29270BB5DC0F1E16BB",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "e6": {
        "display_name": "Let's Encrypt E6",
        "url_pem": "https://letsencrypt.org/certs/2024/e6.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x2",
        "alternates": ["e6_cross"],
        "letsencrypt_serial": "e6",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "C7BA5AA7E91080FA95E157476639736852C6BDF6",
            "sha256": "065AB7D2A050F947587121765D8D070C0E1330D5798FAA42C2072749ED293762",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "e6_cross": {
        "display_name": "Let's Encrypt E6 (X1 cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/2024/e6-cross.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x1",
        "alternate_of": "e6",
        "letsencrypt_serial": "e6",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "C94DC4831A901A9FEC0FB49B71BD49B5AAD4FAD0",
            "sha256": "76E9E288AAFC0E37F4390CBF946AAD997D5C1C901B3CE513D3D8FADBABE2AB85",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "r10": {
        "display_name": "Let's Encrypt R10",
        "url_pem": "https://letsencrypt.org/certs/2024/r10.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "letsencrypt_serial": "r10",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "00ABEFD055F9A9C784FFDEABD1DCDD8FED741436",
            "sha256": "9D7C3F1AA6AD2B2EC0D5CF1E246F8D9AE6CBC9FD0755AD37BB974B1F2FB603F3",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "r11": {
        "display_name": "Let's Encrypt R11",
        "url_pem": "https://letsencrypt.org/certs/2024/r11.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "letsencrypt_serial": "r11",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "696DB3AF0DFFC17E65C6A20D925C5A7BD24DEC7E",
            "sha256": "591E9CE6C863D3A079E9FABE1478C7339A26B21269DDE795211361024AE31A44",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "isrg_root_x2_cross": {
        "display_name": "ISRG Root X2 (Cross-signed by ISRG Root X1)",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-x2-cross-signed.pem",
        "is_trusted_root": False,
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x1",
        "alternate_of": "isrg_root_x2",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "151682F5218C0A511C28F4060A73B9CA78CE9A53",
            "sha256": "8B05B68CC659E5ED0FCB38F2C942FBFD200E6F2FF9F85D63C6994EF5E0B02701",
        },
        ".enddate": (2025, 9, 15, 16, 0, 0),
        "is_self_signed": False,
    },
    "letsencrypt_staging_root_x2_signed_by_x2": {
        "display_name": "(STAGING) Bogus Broccoli X2 (X1 cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2-signed-by-x1.pem",
        "is_trusted_root": True,
        "is_untrusted_root": True,
        "is_self_signed": False,
        "signed_by": "letsencrypt_staging_root_x1",
        "alternate_of": "letsencrypt_staging_root_x2",
        "is_active": False,
        "key_technology": "EC",
        "cert.fingerprints": {
            "sha1": "70CB7923F66CB2678B050CEF38D5B4CB28489E88",
            "sha256": "32D21AF6FC87417A55D7E23C6992B8CE0CB9B5FCD85DA30D194156D53758E4C5",
        },
        ".enddate": (2025, 9, 15, 16, 0, 0),
        "compatibility": {"All": ("<0", ">0", "Untrusted Fake Root")},
        "is_retired": True,
    },
    "e7": {
        "display_name": "Let's Encrypt E7",
        "url_pem": "https://letsencrypt.org/certs/2024/e7.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x2",
        "alternates": ["e7_cross"],
        "letsencrypt_serial": "e7",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "D6C9554B96C89F87A9EEAB5C32CC37D3AF965737",
            "sha256": "54715420224C5B65BEED018DC3940D7338C577E322D5488F633D8C6A8FED61B2",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "e7_cross": {
        "display_name": "Let's Encrypt E7 (X1 cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/2024/e7-cross.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x1",
        "alternate_of": "e7",
        "letsencrypt_serial": "e7",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "3B73C17E3DF87CF3AA77F1389219EB5EDD519E7F",
            "sha256": "AEB1FD7410E83BC96F5DA3C6A7C2C1BB836D1FA5CB86E708515890E428A8770B",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "e8": {
        "display_name": "Let's Encrypt E8",
        "url_pem": "https://letsencrypt.org/certs/2024/e8.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x2",
        "alternates": ["e8_cross"],
        "letsencrypt_serial": "e8",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "E1CC565BEECAE8862A7D37BD291BEB214E1B1C88",
            "sha256": "AC1274542267F17B525535B5563BF731FEBB182533B46A82DC869CB64EB528C0",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "e8_cross": {
        "display_name": "Let's Encrypt E8 (X1 cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/2024/e8-cross.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x1",
        "alternate_of": "e8",
        "letsencrypt_serial": "e8",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "54317EB0765F0BC674855184EB8374B4199E4655",
            "sha256": "83624FD338C8D9B023C18A67CB7A9C0519DA43D11775B4C6CBDAD45C3D997C52",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "e9": {
        "display_name": "Let's Encrypt E9",
        "url_pem": "https://letsencrypt.org/certs/2024/e9.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x2",
        "alternates": ["e9_cross"],
        "letsencrypt_serial": "e9",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "C852082BA3D0B89674F8258803FD5A3CF02DEA4D",
            "sha256": "4185DF97806C2BA76F1D79823F112FFA639A49CCDC990908102067AB6412B886",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "e9_cross": {
        "display_name": "Let's Encrypt E9 (X1 cross-signed)",
        "url_pem": "https://letsencrypt.org/certs/2024/e9-cross.pem",
        "is_active": False,
        "key_technology": "EC",
        "signed_by": "isrg_root_x1",
        "alternate_of": "e9",
        "letsencrypt_serial": "e9",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "62E5E611F170792D7D6CDD45A6B8A06783EC31EE",
            "sha256": "FDE88F2D4F8913D3DC1664D5F8DE51E07FE2ABFED93B45ACAD5A29BFEBAA23FB",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "r12": {
        "display_name": "Let's Encrypt R12",
        "url_pem": "https://letsencrypt.org/certs/2024/r12.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "letsencrypt_serial": "r12",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "EE44782835D8FB31394DA5CEB840DC93849BCF5A",
            "sha256": "131FCE7784016899A5A00203A9EFC80F18EBBD75580717EDC1553580930836EC",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "r13": {
        "display_name": "Let's Encrypt R13",
        "url_pem": "https://letsencrypt.org/certs/2024/r13.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "letsencrypt_serial": "r13",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "22FF89586561FC2D52F77491E9F1EFF1B80BE33E",
            "sha256": "D3B128216A843F8EF1321501F5DF52A5DF52939EE2C19297712CD3DE4D419354",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
    "r14": {
        "display_name": "Let's Encrypt R14",
        "url_pem": "https://letsencrypt.org/certs/2024/r14.pem",
        "is_active": False,
        "key_technology": "RSA",
        "signed_by": "isrg_root_x1",
        "letsencrypt_serial": "r14",
        "is_retired": True,
        "cert.fingerprints": {
            "sha1": "47E0467E82B52DDE4CB867CFBEE75201EE04A9D1",
            "sha256": "24D45AA9B8D6053D281F3842C8CC0C6C1AF7CCDFD42DD5C12F6A74FA9323F7A2",
        },
        ".enddate": (2027, 3, 12, 23, 59, 59),
        "is_self_signed": False,
    },
}

CERT_CAS_DATA: Dict[str, CERT_CA_PAYLOAD] = {
    "isrg_root_x1": {
        "display_name": "ISRG Root X1",
        "url_pem": "https://letsencrypt.org/certs/isrgrootx1.pem",
        "is_trusted_root": True,
        "is_self_signed": True,
        "signed_by": "isrg_root_x1",
        "is_active": True,
        "key_technology": "RSA",
        "alternates": ["isrg_root_x1_cross"],
        "cert.fingerprints": {
            "sha1": "CABD2A79A1076A31F21D253635CB039D4329A5E8",
            "sha256": "96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6",
        },
        ".enddate": (2035, 6, 4, 11, 4, 38),
        "compatibility": {
            "Windows": (
                ">= XP SP3",
                None,
                "unless Automatic Root Certificate Updates have been disabled",
            ),
            "Windows Server": (
                ">= 2008",
                None,
                "unless Automatic Root Certificate Updates have been disabled",
            ),
            "macOS": (">= 10.12.1 Sierra", None, None),
            "iOS": (">= 10", None, None),
            "Android": (">= 7.1.1", None, None),
            "Firefox": (">= 50.0", None, None),
            "Ubuntu": (">= 12.04 Precise Pangolin ", None, "with updates applied"),
            "Debian": (">= 8 / Jessie", None, "with updates applied"),
            "RHEL 6": (">= 6.10", None, "with updates applied"),
            "RHEL 7": (">= 7.4", None, "with updates applied"),
            "RHEL 8": (">= 8", None, None),
            "Java 7": (">= 7u151", None, None),
            "Java 8": (">= 8u141", None, None),
            "Java 9": (">= 9", None, None),
            "NSS": (">= 3.26", None, None),
            "Chrome": (
                ">= 105",
                None,
                "earlier versions use the operating system trust store",
            ),
            "PlayStation PS4": (">= PS4 v8.0.0", None, None),
        },
    },
    "isrg_root_x2": {
        "display_name": "ISRG Root X2",
        "url_pem": "https://letsencrypt.org/certs/isrg-root-x2.pem",
        "is_trusted_root": True,
        "is_self_signed": True,
        "signed_by": "isrg_root_x2",
        "is_active": True,
        "key_technology": "EC",
        "alternates": ["isrg_root_x2_cross_2025", "isrg_root_x2_cross"],
        "cert.fingerprints": {
            "sha1": "BDB1B93CD5978D45C6261455F8DB95C75AD153AF",
            "sha256": "69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470",
        },
        ".enddate": (2040, 9, 17, 16, 0, 0),
        "compatibility": {
            "Windows": (
                ">= XP SP3",
                None,
                "unless Automatic Root Certificate Updates have been disabled",
            ),
            "Windows Server": (
                ">= 2008",
                None,
                "unless Automatic Root Certificate Updates have been disabled",
            ),
            "macOS": (">= 13", None, None),
            "iOS": (">= 16", None, None),
            "Android": (">= 14", None, None),
            "Firefox": (">= 97", None, None),
            "Ubuntu": (">= 18.04 Bionic Beaver ", None, None),
            "Debian": (">= 12/ Bookworm", None, None),
            "RHEL 7": (">= 7.9", None, "with updates applied"),
            "RHEL 8": (">= 8.6", None, "with updates applied"),
            "RHEL 9": (">= 9.1", None, "with updates applied"),
            "Java 8": (">= 8u141", None, None),
            "Java 11": (">= 11.0.22", None, None),
            "Java 17": (">= 17.0.10", None, None),
            "Java 21": (">= 21.0.2", None, None),
            "Java 22": (">= 22", None, None),
            "NSS": (">= 3.74", None, None),
            "Chrome": (
                ">= 105",
                None,
                "earlier versions use the operating system trust store",
            ),
        },
    },
    "isrg_root_x2_cross_2025": {
        "display_name": "Let's Encrypt ISRG Root X2 (cross-signed by ISRG Root X1)",
        "url_pem": "https://letsencrypt.org/certs/gen-y/root-x2-by-x1.pem",
        "signed_by": "isrg_root_x1",
        "is_active": True,
        "key_technology": "EC",
        "cert.fingerprints": {
            "sha1": "3C34E356C7FC17F5ACF04824BC587C6C623951A2",
            "sha256": "EE5F7ABD6981BB0255632CD8F49283451B4B18844D12040B44EE00F07B8FE2C6",
        },
        ".enddate": (2032, 9, 2, 23, 59, 59),
        "is_self_signed": False,
        "is_retired": False,
        "is_trusted_root": False,
        "alternate_of": "isrg_root_x2",
    },
    "isrg_root_ye": {
        "display_name": "ISRG Root YE",
        "url_pem": "https://letsencrypt.org/certs/gen-y/root-ye.pem",
        "signed_by": "isrg_root_ye",
        "is_active": True,
        "key_technology": "EC",
        "cert.fingerprints": {
            "sha1": "A9571557A77DB78FFAC2E97B57B898569039C340",
            "sha256": "E14FFCAD5B0025731006CAA43A121A22D8E9700F4FB9CF852F02A708AA5D5666",
        },
        ".enddate": (2045, 9, 2, 23, 59, 59),
        "is_self_signed": True,
        "is_retired": False,
        "is_trusted_root": False,
        "is_untrusted_root": True,
        "alternates": ["isrg_root_ye_cross"],
    },
    "isrg_root_ye_cross": {
        "display_name": "ISRG Root YE (cross-signed by ISRG Root X2)",
        "url_pem": "https://letsencrypt.org/certs/gen-y/root-ye-by-x2.pem",
        "signed_by": "isrg_root_x2",
        "is_active": True,
        "key_technology": "EC",
        "cert.fingerprints": {
            "sha1": "F37620FC4B1CDDD2A3D74B1D5E8DB42E244CA006",
            "sha256": "0FC0901CCA2BAE9E9FDBB02D50D02F1094F7B36672086991B9E897626DC485F0",
        },
        ".enddate": (2032, 9, 2, 23, 59, 59),
        "is_self_signed": False,
        "is_retired": False,
        "is_trusted_root": False,
        "alternate_of": "isrg_root_ye",
    },
    "isrg_root_yr": {
        "display_name": "ISRG Root YR",
        "url_pem": "https://letsencrypt.org/certs/gen-y/root-yr.pem",
        "signed_by": "isrg_root_yr",
        "is_active": True,
        "key_technology": "RSA",
        "cert.fingerprints": {
            "sha1": "C5F111DA84F7DEF8E6F3F99F8F5F36FF85BAB1B1",
            "sha256": "E57B7E6F150C419102E8D5C055729FF967B9D1A829BF00CEC89CA604EBF4A86F",
        },
        ".enddate": (2045, 9, 2, 23, 59, 59),
        "is_self_signed": True,
        "is_retired": False,
        "is_trusted_root": False,
        "is_untrusted_root": True,
        "alternates": ["isrg_root_yr_cross"],
    },
    "isrg_root_yr_cross": {
        "display_name": "ISRG Root YR (cross-signed by ISRG Root X1)",
        "url_pem": "https://letsencrypt.org/certs/gen-y/root-yr-by-x1.pem",
        "signed_by": "isrg_root_x1",
        "is_active": True,
        "key_technology": "RSA",
        "cert.fingerprints": {
            "sha1": "AB9D0263244DD0326EB67015705A667E79CFE998",
            "sha256": "072639D0B140D5BFFAE16AD9C3F6CC6086040621F51EE61A6D46A8915C07CF76",
        },
        ".enddate": (2032, 9, 2, 23, 59, 59),
        "is_self_signed": False,
        "is_retired": False,
        "is_trusted_root": False,
        "alternate_of": "isrg_root_yr",
    },
    "ye1": {
        "display_name": "Let's Encrypt YE1",
        "url_pem": "https://letsencrypt.org/certs/gen-y/int-ye1.pem",
        "signed_by": "isrg_root_ye",
        "is_active": True,
        "key_technology": "EC",
        "cert.fingerprints": {
            "sha1": "D09370A9864982A5047DA46373540256D08A3C81",
            "sha256": "A2372D06431E9716365EEED47EC020351497D182FCC038E457E58168A03CAC07",
        },
        ".enddate": (2028, 9, 2, 23, 59, 59),
        "is_self_signed": False,
        "is_retired": False,
        "is_trusted_root": False,
        "letsencrypt_serial": "ye1",
    },
    "ye2": {
        "display_name": "Let's Encrypt YE2",
        "url_pem": "https://letsencrypt.org/certs/gen-y/int-ye2.pem",
        "signed_by": "isrg_root_ye",
        "is_active": True,
        "key_technology": "EC",
        "cert.fingerprints": {
            "sha1": "F8158CA8A3A7C5DBD7842218F5D949CEC83ACDBA",
            "sha256": "97658DE8C68DFA98ACE1E5028A63D54A1AAE911B3E21471076C6850CD08CBAB4",
        },
        ".enddate": (2028, 9, 2, 23, 59, 59),
        "is_self_signed": False,
        "is_retired": False,
        "is_trusted_root": False,
        "letsencrypt_serial": "ye2",
    },
    "yr1": {
        "display_name": "Let's Encrypt YR1",
        "url_pem": "https://letsencrypt.org/certs/gen-y/int-yr1.pem",
        "signed_by": "isrg_root_yr",
        "is_active": True,
        "key_technology": "RSA",
        "cert.fingerprints": {
            "sha1": "CBCFD09CE3CD22D99D94E58F92E9898FBEE51A5E",
            "sha256": "13949634D99CD6FD6AA80BC034FEFACCEB1969FEEF986586713ECDBB05758D3F",
        },
        ".enddate": (2028, 9, 2, 23, 59, 59),
        "is_self_signed": False,
        "is_retired": False,
        "is_trusted_root": False,
        "letsencrypt_serial": "yr1",
    },
    "yr2": {
        "display_name": "Let's Encrypt YR2",
        "url_pem": "https://letsencrypt.org/certs/gen-y/int-yr2.pem",
        "signed_by": "isrg_root_yr",
        "is_active": True,
        "key_technology": "RSA",
        "cert.fingerprints": {
            "sha1": "2D74D6DFD96EEA55AD7BAAFA0D3C6552B2DADC37",
            "sha256": "238B85A0099C65B970477D5724F1A1D475CE5058CFFE4EFA8733899BDB863C47",
        },
        ".enddate": (2028, 9, 2, 23, 59, 59),
        "is_self_signed": False,
        "is_retired": False,
        "is_trusted_root": False,
        "letsencrypt_serial": "yr2",
    },
    "ye3": {
        "display_name": "Let's Encrypt YE3",
        "url_pem": "https://letsencrypt.org/certs/gen-y/int-ye3.pem",
        "signed_by": "isrg_root_ye",
        "is_active": False,
        "is_backup": True,
        "key_technology": "EC",
        "cert.fingerprints": {
            "sha1": "A23DA087F94A15259F251FDC6620616864BF54EF",
            "sha256": "82BCFC482CC19F71E6F98F4A027616EBDA6D47096D408B336160D1C0EF8B995A",
        },
        ".enddate": (2028, 9, 2, 23, 59, 59),
        "is_self_signed": False,
        "is_retired": False,
        "is_trusted_root": False,
        "letsencrypt_serial": "ye3",
    },
    "yr3": {
        "display_name": "Let's Encrypt YR3",
        "url_pem": "https://letsencrypt.org/certs/gen-y/int-yr3.pem",
        "signed_by": "isrg_root_yr",
        "is_active": False,
        "is_backup": True,
        "key_technology": "RSA",
        "cert.fingerprints": {
            "sha1": "5F89F238597B90392073AC3D36FD9AC4FA911420",
            "sha256": "35500CB63B8D9769528D65D87220F51C069807A595ACBF2FB6ECA38FBE0A4BD2",
        },
        ".enddate": (2028, 9, 2, 23, 59, 59),
        "is_self_signed": False,
        "is_retired": False,
        "is_trusted_root": False,
        "letsencrypt_serial": "yr3",
    },
    "letsencrypt_staging_root_x1": {
        "display_name": "(STAGING) Pretend Pear X1",
        "url_pem": "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem",
        "is_trusted_root": True,
        "is_untrusted_root": True,
        "is_self_signed": True,
        "signed_by": "letsencrypt_staging_root_x1",
        "is_active": True,
        "key_technology": "RSA",
        "cert.fingerprints": {
            "sha1": "66493BA4F36D1731729B1118C7F5E2D540E3F37B",
            "sha256": "E70570A989F8565AABDF7CAE27ABD1621872D6A3F811E3FEF27E3DBA02912198",
        },
        ".enddate": (2035, 6, 4, 11, 4, 38),
        "compatibility": {"All": ("<0", ">0", "Untrusted Fake Root")},
    },
    "letsencrypt_staging_root_x2": {
        "display_name": "(STAGING) Bogus Broccoli X2",
        "url_pem": "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem",
        "is_trusted_root": True,
        "is_untrusted_root": True,
        "is_self_signed": True,
        "signed_by": "letsencrypt_staging_root_x2",
        "is_active": True,
        "key_technology": "EC",
        "cert.fingerprints": {
            "sha1": "A465AF9AF04F1A86A2701B987B3ED3A75D50ECEA",
            "sha256": "9B2A339FE6A3E85585C4CD75536CB8C1CF7CD603B9A64BEC2521858AE48DA85D",
        },
        ".enddate": (2040, 9, 17, 16, 0, 0),
        "compatibility": {"All": ("<0", ">0", "Untrusted Fake Root")},
        "alternates": ["letsencrypt_staging_root_x2_signed_by_x2"],
    },
}

_CERT_CAS_DEPRECATED_ORDER = [
    "trustid_root_x3",
    "isrg_root_x1_cross",
    "letsencrypt_ocsp_root_x1",
    "letsencrypt_intermediate_x1",
    "letsencrypt_intermediate_x1_cross",
    "letsencrypt_intermediate_x2",
    "letsencrypt_intermediate_x2_cross",
    "letsencrypt_intermediate_x3",
    "letsencrypt_intermediate_x3_cross",
    "letsencrypt_intermediate_x4",
    "letsencrypt_intermediate_x4_cross",
    "letsencrypt_intermediate_r3",
    "letsencrypt_intermediate_r3_cross",
    "letsencrypt_intermediate_r4",
    "letsencrypt_intermediate_r4_cross",
    "letsencrypt_intermediate_e1",
    "letsencrypt_intermediate_e2",
    "e5",
    "e5_cross",
    "e6",
    "e6_cross",
    "r10",
    "r11",
    "staging_letsencrypt_root_x1",
    "staging_letsencrypt_intermediate_x1",
    "isrg_root_x2_cross",
    "e7",
    "e7_cross",
    "e8",
    "e8_cross",
    "e9",
    "e9_cross",
    "r12",
    "r13",
    "r14",
    "letsencrypt_staging_root_x2_signed_by_x2",
]
_CERT_CAS_ORDER = [
    "isrg_root_x1",
    "isrg_root_x2",
    "isrg_root_x2_cross_2025",
    "isrg_root_ye",
    "isrg_root_ye_cross",
    "isrg_root_yr",
    "isrg_root_yr_cross",
    "ye1",
    "ye2",
    "yr1",
    "yr2",
    "ye3",
    "yr3",
    "letsencrypt_staging_root_x1",
    "letsencrypt_staging_root_x2",
]

# Prefer established roots; pending roots are available only as explicit options.
DEFAULT_CA_PREFERENCES = [
    "isrg_root_x2",
    "isrg_root_x1",
    "isrg_root_ye",
    "isrg_root_yr",
]


# these should be a listing of serials
# e.g.: ("x1", "x2", "x3", "x4", "r3", "r4", "e1", "e2")
CA_LE_INTERMEDIATES = []
CA_LE_INTERMEDIATES_CROSSED = []
for _cert_id, _payload in CERT_CAS_DATA.items():
    _serial = _payload.get("letsencrypt_serial")
    if not _serial:
        continue
    if not _payload.get("alternate_of"):
        if not _payload.get("is_trusted_root"):
            CA_LE_INTERMEDIATES.append(_serial)
    else:
        CA_LE_INTERMEDIATES_CROSSED.append(_serial)


# LOAD THE CERTS INTO THE SYSTEM
_dir_here = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_dir_certs = os.path.join(_dir_here, "letsencrypt-certs")
for cert_id, cert_data in CERT_CAS_DATA.items():
    _filename = cert_data["url_pem"].split("/")[-1]  # type: ignore[attr-defined]
    _filepath = os.path.join(_dir_certs, _filename)
    with open(_filepath, "r") as _fp:
        cert_pem_text = _fp.read()
        cert_pem_text = cleanup_pem_text(cert_pem_text)
        cert_data["cert_pem"] = cert_pem_text


def download_letsencrypt_certificates(
    *, timeout: Optional[Timeout] = None
) -> Dict[str, Any]:
    """
    DEPRECATED

    nothing calls this. may be useful for testing to ensure the certs have not
    changed on disk, such as the whitespace issue in 2021/02

    download the known LetsEncrypt certificates

    * correct usage of `requests`
    - currently using `.content`, which is raw bytes
    - usually one uses `.text`, which is `.content` that is decoded
    - there was some concern that triggered this utf8 decode at some point...
    """
    # ???: raise Exception if the cert_pem changes?
    certs = copy.deepcopy(CERT_CAS_DATA)
    for c in list(certs.keys()):
        resp = requests.get(certs[c]["url_pem"], timeout=get_timeout(timeout))
        if resp.status_code != 200:
            raise ValueError("Could not load certificate")
        cert_pem_text = resp.text
        cert_pem_text = cleanup_pem_text(cert_pem_text)
        certs[c]["cert_pem"] = cert_pem_text
        certs[c]["cert_pem_md5"] = md5_text(cert_pem_text)
    return certs
