# stdlib
import logging
import os
import sys
from types import ModuleType
from typing import Any
from typing import Callable
from typing import Optional

log = logging.getLogger("cert_utils")

# ------------------------------------------------------------------------------

"""
Conditional Imports

This package contains our conditional imports.

DO NOT IMPORT FROM THIS PACKAGE.
Instead, import this package and access the imports through it.

The unit tests need to unset these packages to `None` to ensure fallback
operations work correctly. If packages are imported from here, they may not
be property unset in the unit_tests.

BAD:
    from .conditionals import cryptography
    cert = cryptography.x509.load_pem_x509_certificate(
        cert_pem.encode()
    )

GOOD:
    from . import conditionals
    cert = conditionals.cryptography.x509.load_pem_x509_certificate(
        cert_pem.encode()
    )


"""
cryptography: Optional[ModuleType]
crypto_x509: Optional[ModuleType]
crypto_hashes: Optional[ModuleType]
crypto_padding: Optional[ModuleType]
crypto_serialization: Optional[ModuleType]
crypto_dsa: Optional[ModuleType]
crypto_ec: Optional[ModuleType]
crypto_ed25519: Optional[ModuleType]
crypto_ed448: Optional[ModuleType]
crypto_rsa: Optional[ModuleType]
crypto_utils: Optional[ModuleType]
EllipticCurvePublicKey: Optional[Any]
RSAPublicKey: Optional[Any]
crypto_pkcs7: Optional[ModuleType]
josepy: Optional[ModuleType]

# first cryptography
try:
    import cryptography
    import cryptography.x509 as crypto_x509
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives import padding as crypto_padding
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import dsa as crypto_dsa
    from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
    from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519
    from cryptography.hazmat.primitives.asymmetric import ed448 as crypto_ed448
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.serialization import pkcs7 as crypto_pkcs7
except ImportError:
    cryptography = None
    crypto_x509 = None
    crypto_hashes = None
    crypto_padding = None
    crypto_serialization = None
    crypto_dsa = None
    crypto_ec = None
    crypto_ed25519 = None
    crypto_ed448 = None
    crypto_rsa = None
    crypto_utils = None
    EllipticCurvePublicKey = None
    RSAPublicKey = None
    crypto_pkcs7 = None


def is_josepy_compatible() -> bool:
    # this code works with josepy 1 & 2
    f_version: Callable
    if sys.version_info < (3, 8):
        # catch 3.7 and below
        import importlib_metadata

        f_version = importlib_metadata.version
    else:
        import importlib
        import importlib.metadata

        f_version = importlib.metadata.version

    _v = f_version("josepy")
    if int(_v.split(".")[0]) not in (1, 2):
        _force = bool(int(os.environ.get("CERT_UTILS_FORCE_JOSEPY", "0")))
        if not _force:
            return False
    return True


# then josepy
try:
    import josepy

    if not is_josepy_compatible():
        log.critical("josepy might not be compatible; disabling")
        log.critical("set env `CERT_UTILS_FORCE_JOSEPY=1` to bypass")
        josepy = None  # noqa: F811
except ImportError as exc:
    log.critical("josepy ImportError %s", exc)
    josepy = None
