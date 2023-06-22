from typing import Dict
from typing import List

# ==============================================================================


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
