# stdlib
from enum import Enum
from typing import Dict
from typing import List
from typing import Optional

# locals
from . import core

# ==============================================================================


class AccountKeyData(object):
    """
    An object encapsulating Account Key data
    """

    key_pem: str
    key_pem_filepath: Optional[str]
    jwk: Dict
    thumbprint: str
    alg: str

    def __init__(
        self,
        key_pem: str,
        key_pem_filepath: Optional[str] = None,
    ):
        """
        :param key_pem: (required) A PEM encoded RSA key
        :param key_pem_filepath: (optional) The filepath of a PEM encoded RSA key
        """
        self.key_pem = key_pem
        self.key_pem_filepath = key_pem_filepath

        (_jwk, _thumbprint, _alg) = core.account_key__parse(
            key_pem=key_pem,
            key_pem_filepath=key_pem_filepath,
        )
        self.jwk = _jwk
        self.thumbprint = _thumbprint
        self.alg = _alg


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _mixin_mapping(object):
    """handles a mapping of db codes/constants"""

    _mapping: Dict[int, str]
    _mapping_reverse: Dict[str, int]

    @classmethod
    def as_string(cls, mapping_id: int) -> str:
        if mapping_id in cls._mapping:
            return cls._mapping[mapping_id]
        return "unknown"

    @classmethod
    def from_string(cls, mapping_text: str) -> int:
        if not hasattr(cls, "_mapping_reverse"):
            cls._mapping_reverse = {v: k for k, v in cls._mapping.items()}
        return cls._mapping_reverse[mapping_text]


# see https://community.letsencrypt.org/t/issuing-for-common-rsa-key-sizes-only/133839
# see https://letsencrypt.org/docs/integration-guide/
ALLOWED_BITS_RSA = [2048, 3072, 4096]
ALLOWED_CURVES_ECDSA = ["P-256", "P-384"]


class KeyTechnology(_mixin_mapping):
    """
    What kind of Certificate/Key is this?
    """

    RSA = 1
    EC = 2  # ECDSA
    # DSA = 3

    _mapping = {
        1: "RSA",
        2: "EC",
        # 3: "DSA",
    }

    _options_AcmeAccount_private_key_technology_id = (
        1,
        2,
    )
    _DEFAULT_AcmeAccount: str = "RSA"
    _DEFAULT_GlobalKey: str = "RSA"
    _DEFAULT_AcmeAccount_id: int
    _DEFAULT_GlobalKey_id: int
    _options_AcmeAccount_private_key_technology: List[str]


class KeyTechnologyEnum(Enum):
    # this is used for typing
    RSA = KeyTechnology.RSA
    EC = KeyTechnology.EC


# Assign

KeyTechnology._options_AcmeAccount_private_key_technology = [
    KeyTechnology._mapping[_id]
    for _id in KeyTechnology._options_AcmeAccount_private_key_technology_id
]
KeyTechnology._DEFAULT_AcmeAccount_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_AcmeAccount
)
KeyTechnology._DEFAULT_GlobalKey_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_GlobalKey
)
