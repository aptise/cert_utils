# stdlib
import datetime
from enum import Enum
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

# pypi
from typing_extensions import Literal
from typing_extensions import TypedDict

# locals
from . import core

# ==============================================================================


class AccountKeyData(object):
    """
    An object encapsulating Account Key data
    """

    key_pem: str
    key_pem_filepath: Optional[str]
    jwk: Dict[str, str]
    thumbprint: str
    alg: str

    def __init__(
        self,
        key_pem: str,
        key_pem_filepath: Optional[str] = None,
    ) -> None:
        """
        :param key_pem: (required) A PEM encoded RSA key
        :param key_pem_filepath: (optional) The filepath of a PEM encoded RSA key
        """
        self.key_pem = key_pem
        self.key_pem_filepath = key_pem_filepath

        _jwk, _thumbprint, _alg = core.account_key__parse(
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

    # General Types
    RSA = 1
    EC = 2

    # Specifics
    RSA_2048 = 11
    RSA_3072 = 12
    RSA_4096 = 13
    EC_P256 = 24
    EC_P384 = 25

    _mapping = {
        1: "RSA",
        2: "EC",
        11: "RSA_2048",
        12: "RSA_3072",
        13: "RSA_4096",
        24: "EC_P256",
        25: "EC_P384",
    }

    @classmethod
    def to_new_args(cls, id_: int) -> "NewKeyArgs":
        kwargs: "NewKeyArgs" = {}
        if id_ in (cls.RSA, cls.RSA_2048, cls.RSA_3072, cls.RSA_4096):
            kwargs["key_technology_id"] = KeyTechnologyEnum.RSA
            if id_ == cls.RSA_2048:
                kwargs["rsa_bits"] = 2048
            elif id_ == cls.RSA_3072:
                kwargs["rsa_bits"] = 3072
            elif id_ == cls.RSA_4096:
                kwargs["rsa_bits"] = 4096
        elif id_ in (cls.EC, cls.EC_P256, cls.EC_P384):
            kwargs["key_technology_id"] = KeyTechnologyEnum.EC
            if id_ == cls.EC_P256:
                kwargs["ec_curve"] = "P-256"
            elif id_ == cls.EC_P384:
                kwargs["ec_curve"] = "P-384"
        else:
            raise ValueError("unknown id: %s" % id_)
        return kwargs


class KeyTechnologyEnum(Enum):
    # this is used for typing
    RSA = KeyTechnology.RSA
    EC = KeyTechnology.EC

    RSA_2048 = KeyTechnology.RSA_2048
    RSA_3072 = KeyTechnology.RSA_3072
    RSA_4096 = KeyTechnology.RSA_4096
    EC_P256 = KeyTechnology.EC_P256
    EC_P384 = KeyTechnology.EC_P384


class NewKeyArgs(TypedDict, total=False):
    key_technology_id: Union[
        Literal[KeyTechnologyEnum.RSA, KeyTechnologyEnum.EC], Literal[1, 2]
    ]
    rsa_bits: Optional[Literal[2048, 3072, 4096]]
    ec_curve: Optional[Literal["P-256", "P-384"]]


class CertificateData(TypedDict):
    issuer: Optional[str]
    subject: Optional[str]
    startdate: Optional[datetime.datetime]
    enddate: Optional[datetime.datetime]
    SubjectAlternativeName: Optional[List[str]]
    key_technology: Optional[Tuple[str, Tuple[Union[int, str], ...]]]
    fingerprint_sha1: Optional[str]
    spki_sha256: Optional[str]
    issuer_uri: Optional[str]
    authority_key_identifier: Optional[str]
    serial: Optional[int]


class CSRData(TypedDict):
    subject: Optional[str]
    SubjectAlternativeName: List[str]
    key_technology: Optional[Tuple[str, Tuple[Union[int, str], ...]]]
    spki_sha256: Optional[str]


KeyData = TypedDict(
    "KeyData",
    {
        "key_technology": Optional[Union[str, Tuple[str, Tuple[Union[int, str], ...]]]],
        "text": Optional[str],
        "modulus_md5": Optional[str],
        "key_technology_basic": Optional[str],
        "spki_sha256": Optional[str],
        "XX-modulus_md5": str,
        "XX-check": str,
    },
    total=False,
)
