# General Utility Functions

# stdlib
import base64
import binascii
import hashlib
import re
import tempfile
from typing import Iterable
from typing import List
from typing import Tuple
from typing import Union

# ==============================================================================

_RE_rn = re.compile(r"\r\n")


# https://github.com/certbot/certbot/blob/master/certbot/certbot/crypto_util.py#L482
#
# Finds one CERTIFICATE stricttextualmsg according to rfc7468#section-3.
# Does not validate the base64text - use crypto.load_certificate.
#
# NOTE: this functions slightly differently as " *?" was added
#       the first two letsencrypt certificates added a trailing space, which may
#       not be compliant with the specification
CERT_PEM_REGEX = re.compile(
    """-----BEGIN CERTIFICATE----- *?\r?
.+?\r?
-----END CERTIFICATE----- *?\r?
""",
    re.DOTALL,  # DOTALL (/s) because the base64text may include newlines
)


# technically we could end in a dot (\.?)
RE_domain = re.compile(
    r"""^(?:\*\.)?(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))$""",
    re.I,
)

# (RSA, (4096,))
# (EC, ("P-384",))
TECHNOLOGY_RETURN_VALUES = Tuple[str, Tuple[Union[str, int]]]


# ------------------------------------------------------------------------------


def cleanup_pem_text(pem_text: str) -> str:
    """
    * standardizes newlines;
    * removes trailing spaces;
    * ensures a trailing newline.

    :param pem_text: PEM formatted string
    :type pem_text: str
    :returns: cleaned PEM text
    :rtype: str
    """
    pem_text = _RE_rn.sub("\n", pem_text)
    _pem_text_lines = [i.strip() for i in pem_text.split("\n")]
    _pem_text_lines = [i for i in _pem_text_lines if i]
    pem_text = "\n".join(_pem_text_lines) + "\n"
    return pem_text


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


def curve_to_nist(curve_name: str) -> str:
    if curve_name == "secp256r1":
        return "P-256"
    elif curve_name == "secp384r1":
        return "P-384"
    raise ValueError("Unknown curve: %s" % curve_name)


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


def jose_b64(b: bytes) -> str:
    # helper function base64 encode for jose spec
    return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")


def md5_text(text: Union[bytes, str]) -> str:
    if isinstance(text, str):
        text = text.encode()
    return hashlib.md5(text).hexdigest()


def new_pem_tempfile(pem_data: str) -> tempfile._TemporaryFileWrapper:
    """
    this is just a convenience wrapper to create a tempfile and seek(0)

    :param pem_data: PEM encoded string to seed the tempfile with
    :type pem_data: str
    :returns: a tempfile instance
    :rtype: tempfile.NamedTemporaryFile
    """
    tmpfile_pem = tempfile.NamedTemporaryFile()
    if isinstance(pem_data, str):
        pem_bytes = pem_data.encode()
    tmpfile_pem.write(pem_bytes)
    tmpfile_pem.seek(0)
    return tmpfile_pem


def new_der_tempfile(der_data: bytes) -> tempfile._TemporaryFileWrapper:
    """
    this is just a convenience wrapper to create a tempfile and seek(0)

    :param der_data: DER encoded string to seed the tempfile with
    :type der_data: str
    :returns: a tempfile instance
    :rtype: `tempfile.NamedTemporaryFile`
    """
    tmpfile_der = tempfile.NamedTemporaryFile()
    tmpfile_der.write(der_data)
    tmpfile_der.seek(0)
    return tmpfile_der


def split_pem_chain(pem_text: str) -> List[str]:
    """
    splits a PEM encoded Certificate chain into multiple Certificates

    :param pem_text: PEM formatted string containing one or more Certificates
    :type pem_text: str
    :returns: a list of PEM encoded Certificates
    :rtype: list
    """
    _certs = CERT_PEM_REGEX.findall(pem_text)
    certs = [cleanup_pem_text(i) for i in _certs]
    return certs


def validate_domains(domain_names: Iterable[str]) -> bool:
    """
    Ensures each items of the iterable `domain_names` matches a regular expression.

    :param domain_names: (required) An iterable list of strings
    """
    for d in domain_names:
        if not RE_domain.match(d):
            raise ValueError("invalid domain: `%s`", d)
    return True


# ------------------------------------------------------------------------------
