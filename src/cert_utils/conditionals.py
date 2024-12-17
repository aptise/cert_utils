# stdlib
from types import ModuleType
from typing import Optional

# ------------------------------------------------------------------------------
# Conditional Imports

cryptography: Optional[ModuleType]
crypto_dsa: Optional[ModuleType]
crypto_ec: Optional[ModuleType]
crypto_ed25519: Optional[ModuleType]
crypto_ed448: Optional[ModuleType]
crypto_hashes: Optional[ModuleType]
crypto_padding: Optional[ModuleType]
crypto_pkcs7: Optional[ModuleType]
crypto_rsa: Optional[ModuleType]
crypto_serialization: Optional[ModuleType]
crypto_x509: Optional[ModuleType]
josepy: Optional[ModuleType]

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
    from cryptography.hazmat.primitives.serialization import pkcs7 as crypto_pkcs7
except ImportError:
    cryptography = None
    crypto_x509 = None
    crypto_dsa = None
    crypto_ec = None
    crypto_ed25519 = None
    crypto_ed448 = None
    crypto_hashes = None
    crypto_padding = None
    crypto_pkcs7 = None
    crypto_rsa = None
    crypto_serialization = None

try:
    import josepy
except ImportError:
    josepy = None
