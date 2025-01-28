# stdlib
import base64
import binascii
import hashlib
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

# locals
from .. import conditionals
from ..utils import CERT_PEM_REGEX
from ..utils import curve_to_nist
from ..utils import TECHNOLOGY_RETURN_VALUES

if TYPE_CHECKING:
    from cryptography.x509 import Certificate
    from cryptography.x509 import CertificateSigningRequest
    from cryptography.x509.name import Name
    from ..core import _TYPES_CRYPTOGRAPHY_PUBLICKEY
    from ..core import _TYPES_CRYPTOGRAPHY_KEYS
    from ..core import _TYPES_CRYPTOGRAPHY_PUBLICKEY_EXTENDED


# ==============================================================================


def _format_cryptography_components(
    x509_name: "Name",
) -> str:
    """
    :param data: input


    `get_components()` is somewhat structured
    the following are valid:
    * [('CN', 'Pebble Intermediate CA 601ea1')]
    * [('C', 'US'), ('O', 'Internet Security Research Group'), ('CN', 'ISRG Root X2')]
    * [('C', 'US'), ('O', 'Internet Security Research Group'), ('CN', 'ISRG Root X1')]
    * [('O', 'Digital Signature Trust Co.'), ('CN', 'DST Root CA X3')]
    cert = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, cert_pem)
    _issuer = cert.get_issuer().get_components()
    _subject = cert.get_subject().get_components()
    """
    # ";".join(["%s=%s" % (i[0], i[1]) for i in x509_name])
    _out = []
    for attr in x509_name:
        _converted = [i.decode("utf8") if isinstance(i, bytes) else i for i in (attr.rfc4514_attribute_name, attr.value)]  # type: ignore[attr-defined]
        _out.append("=".join(_converted))
    out = "\n".join(_out).strip()
    return out


def _cryptography__public_key_technology(
    publickey: "_TYPES_CRYPTOGRAPHY_PUBLICKEY",
) -> Optional[TECHNOLOGY_RETURN_VALUES]:
    """
    :param key: key object
    :type key: instance of
    :returns: If the key is valid, it will return a Tuple wherein
        - The first element is the Key's technology (EC, RSA)
        - The second element is a Tuple with the key's type.
            (RSA, (bits, ))
            (EC, (curve_name, ))
    """
    if TYPE_CHECKING:
        assert conditionals.crypto_rsa is not None
        assert conditionals.crypto_ec is not None
    if isinstance(publickey, conditionals.crypto_rsa.RSAPublicKey):
        return ("RSA", (publickey.key_size,))
    elif isinstance(publickey, conditionals.crypto_ec.EllipticCurvePublicKey):
        curve_name = curve_to_nist(publickey.curve.name)
        return ("EC", (curve_name,))
    return None


def _cryptography__public_key_spki_sha256(
    cryptography_publickey: Union[
        "_TYPES_CRYPTOGRAPHY_KEYS", "_TYPES_CRYPTOGRAPHY_PUBLICKEY_EXTENDED"
    ],
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param cryptography_publickey: a PublicKey from the cryptography package
    :type cryptography_publickey: cryptography.hazmat.backends.openssl.rsa._RSAPublicKey
    :param as_b64: Should the result be returned in Base64 encoding? default None
    :type as_b64: boolean
    :returns: spki_sha256
    :rtype: str
    """
    assert (
        conditionals.crypto_serialization is not None
    )  # nest under `if TYPE_CHECKING` not needed
    _public_bytes = cryptography_publickey.public_bytes(  # type: ignore[union-attr]
        conditionals.crypto_serialization.Encoding.DER,
        conditionals.crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_sha256 = hashlib.sha256(_public_bytes).digest()
    if as_b64:
        spki_sha256 = base64.b64encode(spki_sha256)
    else:
        spki_sha256 = binascii.b2a_hex(spki_sha256)
        spki_sha256 = spki_sha256.upper()
    _spki_sha256 = spki_sha256.decode("utf8")
    return _spki_sha256


def _cryptography__cert_or_req__all_names(
    loaded_cert_or_req: Union["Certificate", "CertificateSigningRequest"],
) -> List[str]:
    assert conditionals.cryptography is not None
    cn: Optional[str] = None
    try:
        _cn = loaded_cert_or_req.subject.get_attributes_for_oid(
            conditionals.cryptography.x509.oid.NameOID.COMMON_NAME
        )[0].value
        cn = _cn.decode() if isinstance(_cn, bytes) else _cn
    except IndexError:
        pass
    sans: List[str] = []
    try:
        ext = loaded_cert_or_req.extensions.get_extension_for_oid(
            conditionals.cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        _sans = ext.value.get_values_for_type(conditionals.cryptography.x509.DNSName)  # type: ignore[attr-defined]
        sans = [san.decode() if isinstance(san, bytes) else san for san in _sans]

    except conditionals.cryptography.x509.ExtensionNotFound:
        pass
    if cn is None:
        return sans
    return [cn] + [d for d in sans if d != cn]


def cryptography__cert_and_chain_from_fullchain(fullchain_pem: str) -> Tuple[str, str]:
    """Split fullchain_pem into cert_pem and chain_pem

    :param str fullchain_pem: concatenated cert + chain

    :returns: tuple of string cert_pem and chain_pem
    :rtype: tuple

    :raises errors.Error: If there are less than 2 certificates in the chain.

    """
    # First pass: find the boundary of each certificate in the chain.
    # TODO: This will silently skip over any "explanatory text" in between boundaries,
    # which is prohibited by RFC8555.
    if TYPE_CHECKING:
        assert conditionals.cryptography is not None
        assert conditionals.crypto_serialization is not None

    certs = CERT_PEM_REGEX.findall(fullchain_pem)
    if len(certs) < 2:
        raise ValueError(
            "failed to parse fullchain into cert and chain: "
            + "less than 2 certificates in chain"
        )

    # Second pass: for each certificate found, parse it using OpenSSL and re-encode it,
    # with the effect of normalizing any encoding variations (e.g. CRLF, whitespace).
    certs_normalized = []
    for cert_pem in certs:
        cert = conditionals.cryptography.x509.load_pem_x509_certificate(
            cert_pem.encode()
        )
        cert_pem = cert.public_bytes(
            conditionals.crypto_serialization.Encoding.PEM
        ).decode()
        certs_normalized.append(cert_pem)

    # Since each normalized cert has a newline suffix, no extra newlines are required.
    return (certs_normalized[0], "".join(certs_normalized[1:]))
