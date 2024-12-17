# stdlib
import binascii
import hashlib
import re
from types import ModuleType
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union


cryptography: Optional[ModuleType]
serialization: Optional[ModuleType]


try:
    import cryptography
    from cryptography.hazmat.primitives import serialization
except ImportError:
    cryptography = None
    serialization = None


# ==============================================================================


# from certbot.crypto_util
# Finds one CERTIFICATE stricttextualmsg according to rfc7468#section-3.
# Does not validate the base64text - use crypto.load_certificate.
CERT_PEM_REGEX = re.compile(
    b"""-----BEGIN CERTIFICATE-----\r?
.+?\r?
-----END CERTIFICATE-----\r?
""",
    re.DOTALL,  # DOTALL (/s) because the base64text may include newlines
)

# technically we could end in a dot (\.?)
RE_domain = re.compile(
    r"""^(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))$""",
    re.I,
)


# ------------------------------------------------------------------------------


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


def cryptography__cert_and_chain_from_fullchain(fullchain_pem: str) -> Tuple[str, str]:
    """Split fullchain_pem into cert_pem and chain_pem

    from certbot.crypto_util

    :param str fullchain_pem: concatenated cert + chain

    :returns: tuple of string cert_pem and chain_pem
    :rtype: tuple

    :raises errors.Error: If there are less than 2 certificates in the chain.

    """
    # First pass: find the boundary of each certificate in the chain.
    # TODO: This will silently skip over any "explanatory text" in between boundaries,
    # which is prohibited by RFC8555.
    if TYPE_CHECKING:
        assert cryptography is not None
        assert serialization is not None

    certs = CERT_PEM_REGEX.findall(fullchain_pem.encode())
    if len(certs) < 2:
        raise ValueError(
            "failed to parse fullchain into cert and chain: "
            + "less than 2 certificates in chain"
        )

    # Second pass: for each certificate found, parse it using OpenSSL and re-encode it,
    # with the effect of normalizing any encoding variations (e.g. CRLF, whitespace).
    certs_normalized = []
    for cert_pem in certs:
        cert = cryptography.x509.load_pem_x509_certificate(cert_pem)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        certs_normalized.append(cert_pem)

    # Since each normalized cert has a newline suffix, no extra newlines are required.
    return (certs_normalized[0], "".join(certs_normalized[1:]))


def domains_from_list(domain_names: Iterable[str]) -> List[str]:
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


def validate_domains(domain_names: Iterable[str]) -> bool:
    """
    Ensures each items of the iterable `domain_names` matches a regular expression.

    :param domain_names: (required) An iterable list of strings
    """
    for d in domain_names:
        if not RE_domain.match(d):
            raise ValueError("invalid domain: `%s`", d)
    return True
