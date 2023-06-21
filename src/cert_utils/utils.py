# stdlib
import binascii
import hashlib
import re
from typing import List
from typing import Union

# ==============================================================================


# technically we could end in a dot (\.?)
RE_domain = re.compile(
    r"""^(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))$""",
    re.I,
)

# ------------------------------------------------------------------------------


def validate_domains(domain_names: List[str]) -> bool:
    """
    Ensures each items of the iterable `domain_names` matches a regular expression.

    :param domain_names: (required) An iterable list of strings
    """
    for d in domain_names:
        if not RE_domain.match(d):
            raise ValueError("invalid domain: `%s`", d)
    return True


def domains_from_list(domain_names: List[str]) -> List[str]:
    """
    Turns a list of strings into a standardized list of domain names.

    Will raise `ValueError("invalid domain")` if non-conforming elements are encountered.

    This invokes `validate_domains`, which uses a simple regex to validate each domain in the list.

    :param domain_names: (required) An iterable list of strings
    """
    domain_names = [d for d in [d.strip().lower() for d in domain_names] if d]
    # make the list unique
    domain_names = list(set(domain_names))
    # validate the list
    validate_domains(domain_names)
    return domain_names


def domains_from_string(text: str) -> List[str]:
    """
    :param text: (required) Turns a comma-separated-list of domain names into a list

    This invokes `domains_from_list` which invokes `validate_domains`, which uses a simple regex to validate each domain in the list.

    This will raise a `ValueError("invalid domain")` on the first invalid domain
    """
    # generate list
    domain_names = text.split(",")
    return domains_from_list(domain_names)


def convert_binary_to_hex(input: bytes) -> str:
    """
    the cryptography package surfaces raw binary data
    openssl uses hex encoding, uppercased, with colons
    this function translates the binary to the hex uppercase.
    the colons can be rendered on demand.

    example: isrg-root-x2-cross-signed.pem's authority_key_identifier

        binary (from cryptography)
            y\xb4Y\xe6{\xb6\xe5\xe4\x01s\x80\x08\x88\xc8\x1aX\xf6\xe9\x9bn

        hex (from openssl)
            79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E

        via this function:
            79B459E67BB6E5E40173800888C81A58F6E99B6E
    """
    # input = "y\xb4Y\xe6{\xb6\xe5\xe4\x01s\x80\x08\x88\xc8\x1aX\xf6\xe9\x9bn"
    _as_hex = binascii.b2a_hex(input)
    # _as_hex = "79b459e67bb6e5e40173800888c81a58f6e99b6e"
    _as_hex = _as_hex.upper()
    # _as_hex = "79B459E67BB6E5E40173800888C81A58F6E99B6E"
    _as_hex_str = _as_hex.decode("utf8")
    return _as_hex_str


def hex_with_colons(as_hex: str) -> str:
    # as_hex = '79B459E67BB6E5E40173800888C81A58F6E99B6E'
    _pairs = [as_hex[idx : idx + 2] for idx in range(0, len(as_hex), 2)]
    # _pairs = ['79', 'B4', '59', 'E6', '7B', 'B6', 'E5', 'E4', '01', '73', '80', '08', '88', 'C8', '1A', '58', 'F6', 'E9', '9B', '6E']
    output = ":".join(_pairs)
    # '79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E'
    return output


def md5_text(text: Union[bytes, str]) -> str:
    if isinstance(text, str):
        text = text.encode()
    return hashlib.md5(text).hexdigest()
