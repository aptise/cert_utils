# stdlib
import base64
import binascii
import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
import textwrap
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Type
from typing import TYPE_CHECKING
from typing import Union

# pypi
from dateutil import parser as dateutil_parser
import psutil

# localapp
from .errors import FallbackError_FilepathRequired
from .errors import OpenSslError
from .errors import OpenSslError_CsrGeneration
from .errors import OpenSslError_InvalidCertificate
from .errors import OpenSslError_InvalidCSR
from .errors import OpenSslError_InvalidKey
from .errors import OpenSslError_VersionTooLow
from .model import KeyTechnology
from .utils import convert_binary_to_hex

# ==============================================================================

if TYPE_CHECKING:
    import datetime
    from OpenSSL.crypto import PKey
    from OpenSSL.crypto import X509Req
    from cryptography.x509 import Certificate
    from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
    from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

    _TYPES_CRYPTOGRAPHY_KEYS = Union[
        DSAPrivateKey, DSAPublicKey, RSAPrivateKey, RSAPublicKey
    ]
    _TYPES_CRYPTOGRAPHY_PUBLICKEY_EXTENDED = Union[
        DSAPublicKey,
        RSAPublicKey,
        EllipticCurvePublicKey,
        Ed25519PublicKey,
        Ed448PublicKey,
        X25519PublicKey,
        X448PublicKey,
    ]

# ------------------------------------------------------------------------------
# Conditional Imports
try:
    from acme import crypto_util as acme_crypto_util
except ImportError:
    acme_crypto_util = None  # type: ignore[assignment]

try:
    from certbot import crypto_util as certbot_crypto_util
except ImportError:
    certbot_crypto_util = None  # type: ignore[assignment]

try:
    import cryptography
    from cryptography.hazmat.backends import default_backend as crypto_default_backend
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    from cryptography.hazmat.primitives.serialization import pkcs7 as crypto_pkcs7
except ImportError:
    raise
    cryptography = None  # type: ignore[assignment]
    crypto_default_backend = None  # type: ignore[assignment]
    crypto_serialization = None  # type: ignore[assignment]
    crypto_ec = None  # type: ignore[assignment]
    crypto_rsa = None  # type: ignore[assignment]
    crypto_pkcs7 = None  # type: ignore[assignment]

try:
    import josepy
except ImportError:
    josepy = None  # type: ignore[assignment]

try:
    from OpenSSL import crypto as openssl_crypto
except ImportError:
    openssl_crypto = None  # type: ignore[assignment]

# ------------------------------------------------------------------------------

NEEDS_TEMPFILES = True
if (
    acme_crypto_util
    and certbot_crypto_util
    and crypto_serialization
    and josepy
    and openssl_crypto
):
    """
    acme_crypto_util
        make_csr
    certbot_crypto_util
        parse_cert__domains
        validate_key
        validate_csr
        cert_and_chain_from_fullchain
    crypto_serialization
        convert_pkcs7_to_pems
        convert_lejson_to_pem
    josepy:
        account_key__parse
    openssl_crypto and certbot_crypto_util
        parse_csr_domains
        parse_cert__spki_sha256
        parse_csr__spki_sha256
        parse_key__spki_sha256
        parse_key__technology
        parse_key
    openssl_crypto:
        validate_cert
        fingerprint_cert
        modulus_md5_key
        modulus_md5_csr
        modulus_md5_cert
        parse_cert__enddate
        parse_cert__startdate
        parse_cert__key_technology
        parse_cert
        parse_csr__key_technology
        parse_csr
        new_key_ec
        new_key_rsa
        decompose_chain
        ensure_chain
        ensure_chain_order
        account_key__sign
    """
    NEEDS_TEMPFILES = False

# ==============================================================================

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# ------------------------------------------------------------------------------


# set these as vars, so other packages can programatticaly test the env for conflicts
_envvar_SSL_BIN_OPENSSL = "SSL_BIN_OPENSSL"
_envvar_SSL_CONF_OPENSSL = "SSL_CONF_OPENSSL"

openssl_path = os.environ.get(_envvar_SSL_BIN_OPENSSL, None) or "openssl"
openssl_path_conf = (
    os.environ.get(_envvar_SSL_CONF_OPENSSL, None) or "/etc/ssl/openssl.cnf"
)

ACME_VERSION = "v2"
openssl_version = None
_RE_openssl_version = re.compile(r"OpenSSL ((\d+\.\d+\.\d+)\w*) ", re.I)
_RE_rn = re.compile(r"\r\n")
_openssl_behavior = None  # 'a' or 'b'


# If True, will:
# * disable SSL Verification
# * disable HTTP Challenge pre-Read
TESTING_ENVIRONMENT = False

# LetsEncrypt max
MAX_DOMAINS_PER_CERTIFICATE = 100


def update_from_appsettings(appsettings: Dict[str, Any]) -> None:
    """
    update the module data based on settings

    :param appsettings: a dict containing the Pyramid application settings
    :type appsettings: dict or dict-like
    """
    global openssl_path
    global openssl_path_conf
    # but first check for conflicts
    # was the env set?
    _openssl_env = os.environ.get(_envvar_SSL_BIN_OPENSSL, None) or os.environ.get(
        _envvar_SSL_CONF_OPENSSL, None
    )
    # was the ini set?
    _openssl_ini = appsettings.get("openssl_path", None) or appsettings.get(
        "openssl_path_conf", None
    )
    if _openssl_env and _openssl_ini:
        raise ValueError("OpenSSL values specified in .ini and environment")
    # did we set the ini?
    _changed_openssl = False
    if "openssl_path" in appsettings:
        openssl_path = appsettings["openssl_path"]
        _changed_openssl = True
    if "openssl_path_conf" in appsettings:
        openssl_path_conf = appsettings["openssl_path_conf"]
        _changed_openssl = True
    if _changed_openssl:
        check_openssl_version(replace=True)


# ==============================================================================


# note the conditional whitespace before/after `CN`
# this is because of differing openssl versions
RE_openssl_x509_subject = re.compile(r"Subject:.*? CN ?= ?([^\s,;/]+)")
RE_openssl_x509_san = re.compile(
    r"X509v3 Subject Alternative Name: ?\n +([^\n]+)\n?", re.MULTILINE | re.DOTALL
)


# openssl 3 does not have "keyid:" as a prefix
RE_openssl_x509_authority_key_identifier = re.compile(
    r"X509v3 Authority Key Identifier: ?\n +(?:keyid:)?([^\n]+)\n?",
    re.MULTILINE | re.DOTALL,
)
# we have a potential line in there for the OSCP or something else.
RE_openssl_x509_issuer_uri = re.compile(
    r"Authority Information Access: ?\n(?:[^\n]*^\n)? +CA Issuers - URI:([^\n]+)\n?",
    re.MULTILINE | re.DOTALL,
)


#
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

# depending on openssl version, the "Public key: " text might list the bits
# it may or may not also have a dash in the phrase "Public Key"
# it may or may not be prefaced with the PublicKey type
RE_openssl_x509_keytype_rsa = re.compile(
    r"Subject Public Key Info:\n"
    r"\s+Public Key Algorithm: rsaEncryption\n"
    r"\s+(RSA )?Public(\ |\-)Key:",
    re.MULTILINE,
)
RE_openssl_x509_keytype_ec = re.compile(
    r"Subject Public Key Info:\n"
    r"\s+Public Key Algorithm: id-ecPublicKey\n"
    r"\s+(EC )?Public(\ |\-)Key:",
    re.MULTILINE,
)


# see https://community.letsencrypt.org/t/issuing-for-common-rsa-key-sizes-only/133839
# see https://letsencrypt.org/docs/integration-guide/
ALLOWED_BITS_RSA = [2048, 3072, 4096]
ALLOWED_BITS_ECDSA = [256, 384]

# ==============================================================================


EXTENSION_TO_MIME = {
    "pem": {
        "*": "application/x-pem-file",
    },
    "cer": {
        "*": "application/pkix-cert",
    },
    "crt": {
        "CertificateCA": "application/x-x509-ca-cert",
        "CertificateSigned": "application/x-x509-server-cert",
    },
    "p7c": {
        "*": "application/pkcs7-mime",
    },
    "der": {
        "CertificateCA": "application/x-x509-ca-cert",
        "CertificateSigned": "application/x-x509-server-cert",
    },
    "key": {
        "*": "application/pkcs8",
    },
}


# ==============================================================================

# General Utility Functions


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


def convert_der_to_pem(der_data: bytes) -> str:
    """
    :param der_data: DER encoded string
    :type der_data: str
    :returns: PEM encoded version of the DER Certificate
    :rtype: str
    """
    # PEM is just a b64 encoded DER Certificate with the header/footer
    as_pem = """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(der_data).decode("utf8"), 64))
    )
    return as_pem


def convert_der_to_pem__csr(der_data: bytes) -> str:
    """
    :param der_data: CSR in DER encoding
    :type der_data: str
    :returns: PEM encoded version of the DER encoded CSR
    :rtype: str
    """
    # PEM is just a b64 encoded DER CertificateRequest with the header/footer
    as_pem = """-----BEGIN CERTIFICATE REQUEST-----\n{0}\n-----END CERTIFICATE REQUEST-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(der_data).decode("utf8"), 64))
    )
    return as_pem


def convert_der_to_pem__rsakey(der_data: bytes) -> str:
    """
    :param der_data: RSA Key in DER encoding
    :type der_data: str
    :returns: PEM encoded version of the RSA Key
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl rsa -in {FILEPATH} -inform der -outform pem
    """
    # PEM is just a b64 encoded DER RSA KEY with the header/footer
    as_pem = """-----BEGIN RSA PRIVATE KEY-----\n{0}\n-----END RSA PRIVATE KEY-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(der_data).decode("utf8"), 64))
    )
    return as_pem


def convert_pem_to_der(pem_data: str) -> bytes:
    """
    :param pem_data: PEM encoded data
    :type pem_data: str
    :returns: DER encoded version of the PEM data
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl req -in {FILEPATH} -outform DER

    The RFC requires the PEM header/footer to start/end with 5 dashes
    This function is a bit lazy and does not check that.
    """
    # PEM is just a b64 encoded DER data with the appropiate header/footer
    lines = [_l.strip() for _l in pem_data.strip().split("\n")]
    # remove the BEGIN CERT
    if (
        ("BEGIN CERTIFICATE" in lines[0])
        or ("BEGIN RSA PRIVATE KEY" in lines[0])
        or ("BEGIN PRIVATE KEY" in lines[0])
        or ("BEGIN CERTIFICATE REQUEST" in lines[0])
    ):
        lines = lines[1:]
    if (
        ("END CERTIFICATE" in lines[-1])
        or ("END RSA PRIVATE KEY" in lines[-1])
        or ("END PRIVATE KEY" in lines[-1])
        or ("END CERTIFICATE REQUEST" in lines[-1])
    ):
        lines = lines[:-1]
    stringed = "".join(lines)
    result = base64.b64decode(stringed)
    return result


def convert_pkcs7_to_pems(pkcs7_data: bytes) -> List[str]:
    """
    :param pkcs7_data: pkcs7 encoded Certifcate Chain
    :type pem_data: str
    :returns: list of PEM encoded Certificates in the pkcs7_data
    :rtype: list

    The OpenSSL Equivalent / Fallback is::

        openssl pkcs7 -inform DER -in {FILEPATH} -print_certs -outform PEM
    """
    # TODO: accept a pkcs7 filepath; FallbackError_FilepathRequired
    log.info("convert_pkcs7_to_pems >")
    if crypto_pkcs7 and crypto_serialization:
        certs_loaded = crypto_pkcs7.load_der_pkcs7_certificates(pkcs7_data)
        certs_bytes = [
            cert.public_bytes(crypto_serialization.Encoding.PEM)
            for cert in certs_loaded
        ]
        certs_string = [cert.decode("utf8") for cert in certs_bytes]
        certs_string = [cleanup_pem_text(cert) for cert in certs_string]
        return certs_string

    log.debug(".convert_pkcs7_to_pems > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    _tmpfile_der = new_der_tempfile(pkcs7_data)
    try:
        cert_der_filepath = _tmpfile_der.name
        with psutil.Popen(
            [
                openssl_path,
                "pkcs7",
                "-inform",
                "DER",
                "-in",
                cert_der_filepath,
                "-print_certs",
                "-outform",
                "PEM",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data_bytes, err = proc.communicate()
            if not data_bytes:
                raise OpenSslError_InvalidCertificate(err)
            data_str = data_bytes.decode()
            # OpenSSL might return extra info
            # for example: "subject=/O=Digital Signature Trust Co./CN=DST Root CA X3\nissuer=/O=Digital Signature Trust Co./CN=DST Root CA X3\n-----BEGIN CERTIFICATE---[...]"
            # split_pem_chain works perfectly with this payload!
            certs = split_pem_chain(data_str)
        return certs
    except Exception as exc:  # noqa: F841
        raise
    finally:
        _tmpfile_der.close()


def san_domains_from_text(text: str) -> List[str]:
    """
    Helper function to extract SAN domains from a chunk of text in a x509 object

    :param text: string extracted from a x509 document
    :type text: str
    :returns: list of domains
    :rtype: list
    """
    san_domains = set([])
    _subject_alt_names = RE_openssl_x509_san.search(text)
    if _subject_alt_names is not None:
        for _san in _subject_alt_names.group(1).split(", "):
            if _san.startswith("DNS:"):
                san_domains.add(_san[4:].lower())
    return sorted(list(san_domains))


def authority_key_identifier_from_text(text: str) -> Optional[str]:
    """
    :param text: string extracted from a x509 document
    :type text: str
    :returns: authority_key_identifier
    :rtype: str

    openssl will print a uppercase hex pairs, separated by a colon
    we should remove the colons
    """
    results = RE_openssl_x509_authority_key_identifier.findall(text)
    if results:
        authority_key_identifier = results[0]
        return authority_key_identifier.replace(":", "")
    return None


def issuer_uri_from_text(text: str) -> Optional[str]:
    """
    :param text: string extracted from a x509 document
    :type text: str
    :returns: issuer_uri
    :rtype: str
    """
    results = RE_openssl_x509_issuer_uri.findall(text)
    if results:
        return results[0]
    return None


def _cert_pubkey_technology__text(cert_text: str) -> Optional[str]:
    """
    :param cert_text: string extracted from a x509 document
    :type cert_text: str
    :returns: Pubkey type: "RSA" or "EC"
    :rtype: str
    """
    # `cert_text` is the output of of `openssl x509 -noout -text -in MYCERT `
    if RE_openssl_x509_keytype_rsa.search(cert_text):
        return "RSA"
    elif RE_openssl_x509_keytype_ec.search(cert_text):
        return "EC"
    return None


def _csr_pubkey_technology__text(csr_text: str) -> Optional[str]:
    """
    :param csr_text: string extracted from a CSR document
    :type csr_text: str
    :returns: Pubkey type: "RSA" or "EC"
    :rtype: str
    """
    # `csr_text` is the output of of `openssl req -noout -text -in MYCERT`
    if RE_openssl_x509_keytype_rsa.search(csr_text):
        return "RSA"
    elif RE_openssl_x509_keytype_ec.search(csr_text):
        return "EC"
    return None


# ==============================================================================


def check_openssl_version(replace: bool = False) -> List[int]:
    """
    :param replace: should this run if the value is already known? (default False)
    :type replace: boolean
    :returns: current openssl version on the commandline
    :rtype: str
    """
    global openssl_version
    global _openssl_behavior
    if (openssl_version is None) or replace:
        with psutil.Popen(
            [
                openssl_path,
                "version",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data_bytes, err = proc.communicate()
        if err:
            raise OpenSslError("could not check version")
        version_text = data_bytes.decode("utf8")
        # version_text will be something like "OpenSSL 1.0.2g  1 Mar 2016\n"
        # version_text.strip().split(' ')[1] == '1.0.2g'
        # but... regex!
        m = _RE_openssl_version.search(version_text)
        if not m:
            raise ValueError(
                "Could not regex OpenSSL",
                "openssl_path: %s" % openssl_path,
                "version: %s" % version_text,
            )
        # m.groups == ('1.0.2g', '1.0.2')
        v = m.groups()[1]
        v = [int(i) for i in v.split(".")]
        openssl_version = v
        _openssl_behavior = "a"  # default to old behavior
        # OpenSSL 1.1.1 doesn't need a tempfile for SANs
        if (v[0] >= 1) and (v[1] >= 1) and (v[2] >= 1):
            _openssl_behavior = "b"
        elif v[0] == 3:
            # some regex are different, but the behavior should be the same
            _openssl_behavior = "b"
    return openssl_version


def _openssl_cert__normalize_pem(cert_pem: str) -> str:
    """
    normalize a cert using openssl
    NOTE: this is an openssl fallback routine

    :param cert_pem: PEM encoded Certificate data
    :type cert_pem: str
    :returns: normalized Certificate
    :rtype: str

    This runs via OpenSSL:

        openssl x509 -in {FILEPATH}
    """
    if openssl_version is None:
        check_openssl_version()

    _tmpfile_pem = new_pem_tempfile(cert_pem)
    try:
        cert_pem_filepath = _tmpfile_pem.name
        with psutil.Popen(
            [openssl_path, "x509", "-in", cert_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data_bytes, err = proc.communicate()
            if not data_bytes:
                raise OpenSslError_InvalidCertificate(err)
            data_str = data_bytes.decode("utf8")
            data_str = data_str.strip()
        return data_str
    except Exception as exc:  # noqa: F841
        raise
    finally:
        _tmpfile_pem.close()


def _openssl_spki_hash_cert(
    key_technology: str = "",
    cert_pem_filepath: str = "",
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param key_technology: Is the key an "EC" or "RSA" key?
    :type key_technology: str
    :param cert_pem_filepath: REQUIRED filepath to PEM Certificate.
                              Used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :param as_b64: Should the result be returned in Base64 encoding? default None
    :type as_b64: boolean
    :returns: spki_hash
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl x509 -pubkey -noout -in {CERT_FILEPATH} | \
        openssl {key_technology} -pubout -outform DER -pubin | \
        openssl dgst -sha256 -binary | \
        openssl enc -base64
    """
    if key_technology not in ("EC", "RSA"):
        raise ValueError("must submit `key_technology`")
    key_technology = key_technology.lower()
    if not cert_pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `cert_pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    spki_hash = None
    # convert to DER
    p1 = p2 = p3 = proc4 = None
    try:
        # extract the key
        p1 = psutil.Popen(
            [
                openssl_path,
                "x509",
                "-pubkey",
                "-noout",
                "-in",
                cert_pem_filepath,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # convert to DER
        p2 = psutil.Popen(
            [
                openssl_path,
                key_technology,
                "-pubin",
                "-pubout",
                "-outform",
                "DER",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # digest
        p3 = psutil.Popen(
            [
                openssl_path,
                "dgst",
                "-sha256",
                "-binary",
            ],
            stdin=p2.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # encode
        spki_hash = None
        if as_b64:
            with psutil.Popen(
                [
                    openssl_path,
                    "enc",
                    "-base64",
                ],
                stdin=p3.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc4:
                spki_hash, err = proc4.communicate()
                if err:
                    raise OpenSslError("could not generate SPKI Hash")
        else:
            spki_hash, err = p3.communicate()
            if err:
                raise OpenSslError("could not generate SPKI Hash")
            spki_hash = binascii.b2a_hex(spki_hash)
            spki_hash = spki_hash.upper()
        spki_hash = spki_hash.strip()
        spki_hash = spki_hash.decode("utf8")

    finally:
        # Note: explicitly close what we opened
        for _p in (
            p1,
            p2,
            p3,
        ):
            if _p is not None:
                try:
                    _p.stdout.close()
                    _p.stderr.close()
                    _p.terminate()
                    _p.wait()
                except psutil.NoSuchProcess:
                    pass
    return spki_hash


def _openssl_spki_hash_csr(
    key_technology: str = "",
    csr_pem_filepath: str = "",
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param key_technology: Is the key an "EC" or "RSA" key?
    :type key_technology: str
    :param csr_pem_filepath: REQUIRED filepath to PEM CSR.
                             Used for commandline OpenSSL fallback operations.
    :type csr_pem_filepath: str
    :param as_b64: Should the result be returned in Base64 encoding? default None
    :type as_b64: boolean
    :returns: spki_hash
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl REQ -pubkey -noout -in {CSR_FILEPATH} | \
        openssl {key_technology} -pubout -outform DER -pubin | \
        openssl dgst -sha256 -binary | \
        openssl enc -base64
    """
    if key_technology not in ("EC", "RSA"):
        raise ValueError("must submit `key_technology`")
    key_technology = key_technology.lower()
    if not csr_pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `csr_pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    spki_hash = None
    # convert to DER
    p1 = p2 = p3 = proc4 = None
    try:
        # extract the key
        p1 = psutil.Popen(
            [
                openssl_path,
                "req",
                "-pubkey",
                "-noout",
                "-in",
                csr_pem_filepath,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # convert to DER
        p2 = psutil.Popen(
            [
                openssl_path,
                key_technology,
                "-pubin",
                "-pubout",
                "-outform",
                "DER",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # digest
        p3 = psutil.Popen(
            [
                openssl_path,
                "dgst",
                "-sha256",
                "-binary",
            ],
            stdin=p2.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # encode
        spki_hash = None
        if as_b64:
            with psutil.Popen(
                [
                    openssl_path,
                    "enc",
                    "-base64",
                ],
                stdin=p3.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc4:
                spki_hash, err = proc4.communicate()
                if err:
                    raise OpenSslError("could not generate SPKI Hash")
        else:
            spki_hash, err = p3.communicate()
            if err:
                raise OpenSslError("could not generate SPKI Hash")
            spki_hash = binascii.b2a_hex(spki_hash)
            spki_hash = spki_hash.upper()
        spki_hash = spki_hash.strip()
        spki_hash = spki_hash.decode("utf8")
    finally:
        # Note: explicitly close what we opened
        for _p in (
            p1,
            p2,
            p3,
        ):
            if _p is not None:
                try:
                    _p.stdout.close()
                    _p.stderr.close()
                    _p.terminate()
                    _p.wait()
                except psutil.NoSuchProcess:
                    pass
    return spki_hash


def _openssl_spki_hash_pkey(
    key_technology: str = "",
    key_pem_filepath: str = "",
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param key_technology: Is the key an "EC" or "RSA" key?
    :type key_technology: str
    :param key_pem_filepath: REQUIRED filepath to PEM encoded PrivateKey.
                             Used for commandline OpenSSL fallback operations.
    :type key_pem_filepath: str
    :param as_b64: Should the result be returned in Base64 encoding? default None
    :type as_b64: boolean
    :returns: spki_hash
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl rsa -in {KEY_FILEPATH} -pubout -outform der | \
        openssl dgst -sha256 -binary | \
        openssl enc -base64
    """
    if key_technology not in ("EC", "RSA"):
        raise ValueError("must submit `key_technology`")
    key_technology = key_technology.lower()
    if not key_pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `key_pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    spki_hash = None
    # convert to DER
    p1 = p2 = proc3 = None
    try:
        # convert to DER
        p1 = psutil.Popen(
            [
                openssl_path,
                key_technology,
                "-pubout",
                "-outform",
                "DER",
                "-in",
                key_pem_filepath,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # digest
        p2 = psutil.Popen(
            [
                openssl_path,
                "dgst",
                "-sha256",
                "-binary",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # encode
        if as_b64:
            with psutil.Popen(
                [
                    openssl_path,
                    "enc",
                    "-base64",
                ],
                stdin=p2.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc3:
                spki_hash, err = proc3.communicate()
                if err:
                    raise OpenSslError("could not generate SPKI Hash")
        else:
            spki_hash, err = p2.communicate()
            if err:
                raise OpenSslError("could not generate SPKI Hash")
            spki_hash = binascii.b2a_hex(spki_hash)
            spki_hash = spki_hash.upper()
        spki_hash = spki_hash.strip()
        spki_hash = spki_hash.decode("utf8")
    finally:
        # Note: explicitly close what we opened
        for _p in (
            p1,
            p2,
        ):
            if _p is not None:
                try:
                    _p.stdout.close()
                    _p.stderr.close()
                    _p.terminate()
                    _p.wait()
                except psutil.NoSuchProcess:
                    pass
    return spki_hash


# ==============================================================================


def _openssl_crypto__key_technology(
    key: Union[Type, "PKey"],
) -> Optional[str]:
    """
    :param key: key object, with a `type()` method
    :type key: instance of
      * `openssl_crypto.load_certificate.get_pubkey()`, or
      * `openssl_crypto.load_privatekey()`, or
      * similar
    :returns: type of key: RSA, EC, DSA
    :rtype: str
    """
    cert_type = key.type()
    if cert_type == openssl_crypto.TYPE_RSA:
        return "RSA"
    elif cert_type == openssl_crypto.TYPE_EC:
        return "EC"
    elif cert_type == openssl_crypto.TYPE_DSA:
        return "DSA"
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
    _public_bytes = cryptography_publickey.public_bytes(  # type: ignore[union-attr]
        crypto_serialization.Encoding.DER,
        crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_sha256 = hashlib.sha256(_public_bytes).digest()
    if as_b64:
        spki_sha256 = base64.b64encode(spki_sha256)
    else:
        spki_sha256 = binascii.b2a_hex(spki_sha256)
        spki_sha256 = spki_sha256.upper()
    _spki_sha256 = spki_sha256.decode("utf8")
    return _spki_sha256


# ==============================================================================


def make_csr(
    domain_names: List[str],
    key_pem: Optional[str] = None,
    key_pem_filepath: Optional[str] = None,
) -> str:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param domain_names: a list of fully qualified domain names
    :type domain_names: list of strings
    :param key_pem: a PEM encoded PrivateKey
    :type key_pem: str
    :param key_pem_filepath: Optional filepath to the PEM encoded PrivateKey.
                             Only used for commandline OpenSSL fallback operations.
    :type key_pem_filepath: str
    :returns: CSR, likely PEM encoded
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl req -new -sha256 -k {FILEPATH_KEY} -subj "/CN=example.com"
        ===
        vi FILEPATH_SAN
            [SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com
        openssl req -new -sha256 -k {FILEPATH_KEY} -subj "/" -reqexts SAN -config < /bin/cat {FILEPATH_SAN}
        ===
        vi FILEPATH_SAN
            subjectAltName=DNS:example.com,DNS:www.example.com
        openssl req -new -sha256 -k {FILEPATH_KEY} -subj "/" -addext {FILEPATH_SAN}
    """
    log.info("make_csr >")
    # keep synced with: lib.letsencrypt_info.LIMITS["names/certificate"]["limit"]
    if len(domain_names) > MAX_DOMAINS_PER_CERTIFICATE:
        raise OpenSslError_CsrGeneration(
            "LetsEncrypt can only allow `%s` domains per certificate"
            % MAX_DOMAINS_PER_CERTIFICATE
        )

    # first try with python
    if acme_crypto_util:
        if not key_pem:
            raise ValueError("Must submit `key_pem`")
        try:
            csr_bytes = acme_crypto_util.make_csr(key_pem.encode(), domain_names)
        except Exception as exc:
            raise OpenSslError_CsrGeneration(exc)
        csr_string = csr_bytes.decode("utf8")
        return csr_string

    log.debug(".make_csr > openssl fallback")
    if key_pem_filepath is None:
        # TODO: generate a tempfile?
        raise FallbackError_FilepathRequired("Must submit `key_pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    _acme_generator_strategy = None
    if ACME_VERSION == "v1":
        if len(domain_names) == 1:
            _acme_generator_strategy = 1
        else:
            _acme_generator_strategy = 2
    elif ACME_VERSION == "v2":
        _acme_generator_strategy = 2

    if _acme_generator_strategy == 1:
        """
        This is the ACME-V1 method for single domain Certificates
        * the Certificate's subject (commonName) is `/CN=yourdomain`
        """
        _csr_subject = "/CN=%s" % domain_names[0]
        with psutil.Popen(
            [
                openssl_path,
                "req",
                "-new",
                "-sha256",
                "-key",
                key_pem_filepath,
                "-subj",
                _csr_subject,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data_bytes, err = proc.communicate()
            if err:
                raise OpenSslError_CsrGeneration("could not create a CSR")
            csr_text = data_bytes.decode("utf8")

    elif _acme_generator_strategy == 2:
        """
        This is the ACME-V2 method for single domain Certificates. It works on ACME-V1.
        * the Certificate's subject (commonName) is `/`
        * ALL domains appear in subjectAltName

        The ACME Spec allows for the domain to be provided in:
            * commonName
            * SAN
            * both

        LetsEncrypt interpreted the relevant passage as not requiring the server to accept each of these.
        """

        # getting subprocess to work right is a pain, because we need to chain a bunch of commands
        # to get around this, we'll do two things:
        # 1. cat the [SAN] and openssl path file onto a tempfile
        # 2. use shell=True

        domain_names = sorted(domain_names)

        # the subject should be /, which will become the serial number
        # see https://community.letsencrypt.org/t/certificates-with-serialnumber-in-subject/11891
        _csr_subject = "/"

        if _openssl_behavior == "a":
            # earlier OpenSSL versions require us to pop in the subjectAltName via a cat'd file

            # generate the [SAN]
            _csr_san = "[SAN]\nsubjectAltName=" + ",".join(
                ["DNS:%s" % d for d in domain_names]
            )

            # store some data in a tempfile
            with open(openssl_path_conf, "rt", encoding="utf-8") as _f_conf:
                _conf_data = _f_conf.read()

            _newline = "\n\n"
            with tempfile.NamedTemporaryFile() as tmpfile_csr_san:
                # `.encode()` to bytes
                tmpfile_csr_san.write(_conf_data.encode())
                tmpfile_csr_san.write(_newline.encode())
                tmpfile_csr_san.write(_csr_san.encode())
                tmpfile_csr_san.seek(0)

                # note that we use /bin/cat (!)
                _command = (
                    """%s req -new -sha256 -key %s -subj "/" -reqexts SAN -config < /bin/cat %s"""
                    % (openssl_path, key_pem_filepath, tmpfile_csr_san.name)
                )
                with psutil.Popen(
                    _command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                ) as proc:
                    data_bytes, err = proc.communicate()
                    if err:
                        raise OpenSslError_CsrGeneration("could not create a CSR")
                    csr_text = data_bytes.decode("utf8")
                    csr_text = cleanup_pem_text(csr_text)

        elif _openssl_behavior == "b":
            # new OpenSSL versions support passing in the `subjectAltName` via the commandline

            # generate the [SAN]
            _csr_san = "subjectAltName = " + ", ".join(
                ["DNS:%s" % d for d in domain_names]
            )
            _command = '''%s req -new -sha256 -key %s -subj "/" -addext "%s"''' % (
                openssl_path,
                key_pem_filepath,
                _csr_san,
            )
            with psutil.Popen(
                _command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ) as proc:
                data_bytes, err = proc.communicate()
                if err:
                    raise OpenSslError_CsrGeneration("could not create a CSR")
                csr_text = data_bytes.decode("utf8")
                csr_text = cleanup_pem_text(csr_text)
    else:
        raise OpenSslError_CsrGeneration("invalid ACME generator")

    return csr_text


def parse_cert__domains(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> List[str]:
    """
    gets ALL domains from a Certificate
        * san (subjectAlternateName)
        * subject (commonName)

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param cert_pem: a PEM encoded Certificate
    :type cert_pem: str
    :param cert_pem_filepath: Optional filepath to the PEM encoded Certificate.
                              Only used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :returns: List of Fully Qualified Domain Names (str) in the Certificate
    :rtype: list

    The OpenSSL Equivalent / Fallback is::

        openssl x509 -in {FILEPATH} -noout -text
    """
    log.info("parse_cert__domains >")
    if certbot_crypto_util:
        # !!!: `get_names_from_cert` is typed for `bytes`, but doctring is `string`
        #    :  both work, but lets go with the typing
        all_domains = certbot_crypto_util.get_names_from_cert(cert_pem.encode())
        return all_domains

    log.debug(".parse_cert__domains > openssl fallback")
    # fallback onto OpenSSL
    # `openssl x509 -in MYCERT -noout -text`
    if cert_pem_filepath is None:
        # TODO: generate a tempfile?
        raise FallbackError_FilepathRequired("Must submit `cert_pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, "x509", "-in", cert_pem_filepath, "-noout", "-text"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data_bytes, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("Error loading {0}: {1}".format(cert_pem_filepath, err))
        data_str = data_bytes.decode("utf8")
    # init
    subject_domain = None
    san_domains = []
    # regex!
    _common_name = RE_openssl_x509_subject.search(data_str)
    if _common_name is not None:
        subject_domain = _common_name.group(1).lower()
    san_domains = san_domains_from_text(data_str)
    if subject_domain is not None and subject_domain not in san_domains:
        san_domains.insert(0, subject_domain)
    san_domains.sort()
    return san_domains


def parse_csr_domains(
    csr_pem: str,
    csr_pem_filepath: Optional[str] = None,
    submitted_domain_names: Optional[List[str]] = None,
) -> List[str]:
    """
    checks found names against `submitted_domain_names`

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    `submitted_domain_names` should be all lowecase

    :param csr_pem: a PEM encoded CSR, required
    :type csr_pem: str
    :param csr_pem_filepath: Optional filepath to the PEM encoded CSR.
                             Only used for commandline OpenSSL fallback operations.
    :type csr_pem_filepath: str
    :param submitted_domain_names: Optional. Default `None``. A list of fully
      qualified domain names, all lowercase. If provided, parity between the
      detected and submitted domains will be checked, and a `ValueError` will be
      raised if the lists are not identical.
    :type submitted_domain_names: list
    :returns: List of Fully Qualified Domain Names (str) in the CSR
    :rtype: list

    The OpenSSL Equivalent / Fallback is::

        openssl req -in {FILEPATH} -noout -text
    """
    log.info("parse_csr_domains >")
    if certbot_crypto_util and openssl_crypto:
        load_func = openssl_crypto.load_certificate_request
        # !!!: `_get_names_from_cert_or_req` is typed for `bytes`, but doctring is `string`
        #    :  both work, but lets go with the typing
        found_domains = certbot_crypto_util._get_names_from_cert_or_req(
            csr_pem.encode(), load_func, typ=openssl_crypto.FILETYPE_PEM
        )
    else:
        log.debug(".parse_csr_domains > openssl fallback")
        # fallback onto OpenSSL
        # openssl req -in MYCSR -noout -text
        if not csr_pem_filepath:
            # TODO: generate csr_pem_filepath if needed?
            raise FallbackError_FilepathRequired("Must submit `csr_pem_filepath`.")
        if openssl_version is None:
            check_openssl_version()

        with psutil.Popen(
            [openssl_path, "req", "-in", csr_pem_filepath, "-noout", "-text"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data_bytes, err = proc.communicate()
            if proc.returncode != 0:
                raise IOError("Error loading {0}: {1}".format(csr_pem_filepath, err))
            data_str = data_bytes.decode("utf8")

        # parse the sans first, then add the commonname
        found_domains = san_domains_from_text(data_str)

        # note the conditional whitespace before/after CN
        common_name = RE_openssl_x509_subject.search(data_str)
        if common_name is not None:
            found_domains.insert(0, common_name.group(1))

    # ensure our CERT matches our submitted_domain_names
    if submitted_domain_names is not None:
        for domain in found_domains:
            if domain not in submitted_domain_names:
                raise ValueError("domain %s not in submitted_domain_names" % domain)
        for domain in submitted_domain_names:
            if domain not in found_domains:
                raise ValueError("domain %s not in found_domains" % domain)

    return sorted(found_domains)


def validate_key(
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
) -> Optional[str]:
    """
    raises an Exception if invalid
    returns the key_technology if valid

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    This may have issues on older openssl systems

    :param key_pem: a PEM encoded PrivateKey
    :type key_pem: str
    :param key_pem_filepath: Optional filepath to the PEM encoded PrivateKey.
                             Only used for commandline OpenSSL fallback operations.
    :type key_pem_filepath: str
    :returns: If the key is valid, it will return the Key's technology (EC, RSA).
      If the key is not valid, an exception will be raised.
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl EC -in {FILEPATH}
        openssl RSA -in {FILEPATH}
    """
    log.info("validate_key >")
    if crypto_serialization and crypto_rsa and crypto_ec:
        log.debug(".validate_key > crypto")
        try:
            # rsa
            # try:
            #   data = certbot_crypto_util.valid_privkey(key_pem)
            # except OpenSslError_InvalidKey as exc:
            #   return None
            data = crypto_serialization.load_pem_private_key(
                key_pem.encode(), None, crypto_default_backend()
            )
            if isinstance(data, crypto_rsa.RSAPrivateKey):
                return "RSA"
            elif isinstance(data, crypto_ec.EllipticCurvePrivateKey):
                return "EC"
        except Exception as exc:
            raise OpenSslError_InvalidKey(exc)
    log.debug(".validate_key > openssl fallback")
    if not key_pem_filepath:
        # TODO: generate a tempfile if needed?
        raise FallbackError_FilepathRequired("Must submit `key_pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    def _check_fallback(_technology: str):
        log.debug(".validate_key > openssl fallback: _check_fallback[%s]", _technology)
        # openssl rsa -in {KEY} -check
        try:
            with psutil.Popen(
                [openssl_path, _technology, "-in", key_pem_filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                data_bytes, err = proc.communicate()
                if not data_bytes:
                    raise OpenSslError_InvalidKey(err)
                data_str = data_bytes.decode("utf8")
                return data_str
        except OpenSslError_InvalidKey as exc:  # noqa: F841
            return None

    if _check_fallback("rsa"):
        return "RSA"
    elif _check_fallback("ec"):
        return "EC"

    raise OpenSslError_InvalidKey()


def validate_csr(
    csr_pem: str,
    csr_pem_filepath: Optional[str] = None,
) -> bool:
    """
    raises an error if invalid

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param csr_pem: a PEM encoded CSR, required
    :type csr_pem: str
    :param csr_pem_filepath: Optional filepath to the PEM encoded CSR.
                             Only used for commandline OpenSSL fallback operations.
    :type csr_pem_filepath: str
    :returns: True
    :rtype: bool

    The OpenSSL Equivalent / Fallback is::

        openssl req -text -noout -verify -in {FILEPATH}
    """
    log.info("validate_csr >")
    if certbot_crypto_util:
        # !!!: `valid_csr` is typed for `bytes`, but doctring is `string`
        #    :  both work, but lets go with the typing
        data = certbot_crypto_util.valid_csr(csr_pem.encode())
        if not data:
            raise OpenSslError_InvalidCSR()
        return True

    log.debug(".validate_csr > openssl fallback")
    # openssl req -text -noout -verify -in {CSR}
    if not csr_pem_filepath:
        # TODO: generate tempfile if needed?
        raise FallbackError_FilepathRequired("Must submit `csr_pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, "req", "-text", "-noout", "-verify", "-in", csr_pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data_bytes, err = proc.communicate()
        if not data_bytes:
            raise OpenSslError_InvalidCSR(err)
        # this may be True or bytes, depending on the version
        # in any event, being here means we passed
    return True


def validate_cert(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> bool:
    """
    raises an error if invalid

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param cert_pem: a PEM encoded Certificate
    :type cert_pem: str
    :param cert_pem_filepath: Optional filepath to the PEM encoded Certificate.
                              Only used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :returns: True
    :rtype: bool

    The OpenSSL Equivalent / Fallback is::

        openssl x509 -in {FILEPATH} -inform PEM -noout -text
    """
    log.info("validate_cert >")
    if openssl_crypto:
        try:
            data = openssl_crypto.load_certificate(
                openssl_crypto.FILETYPE_PEM, cert_pem.encode()
            )
        except Exception as exc:
            raise OpenSslError_InvalidCertificate(exc)
        if not data:
            raise OpenSslError_InvalidCertificate()
        return True

    log.debug(".validate_cert > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    # generate `cert_pem_filepath` if needed.
    _tmpfile_cert = None
    if not cert_pem_filepath:
        _tmpfile_cert = new_pem_tempfile(cert_pem)
        cert_pem_filepath = _tmpfile_cert.name
    try:
        # openssl x509 -in {CERTIFICATE} -inform pem -noout -text
        with psutil.Popen(
            [
                openssl_path,
                "x509",
                "-in",
                cert_pem_filepath,
                "-inform",
                "PEM",
                "-noout",
                "-text",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data_bytes, err = proc.communicate()
            if not data_bytes:
                raise OpenSslError_InvalidCertificate(err)
            # this may be True or bytes, depending on the version
            # in any event, being here means we passed
    finally:
        if _tmpfile_cert:
            _tmpfile_cert.close()
    return True


def fingerprint_cert(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
    algorithm: str = "sha1",
) -> str:
    """
    Derives the Certificate's fingerprint

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    colons will be removed, they can be reintroduced on render

    Every openssl version tested so-far defaults to sha1

        openssl x509 -noout -fingerprint -inform pem -in isrgrootx1.pem
        SHA1 Fingerprint=CA:BD:2A:79:A1:07:6A:31:F2:1D:25:36:35:CB:03:9D:43:29:A5:E8

        openssl x509 -noout -fingerprint -sha1 -inform pem -in isrgrootx1.pem
        SHA1 Fingerprint=CA:BD:2A:79:A1:07:6A:31:F2:1D:25:36:35:CB:03:9D:43:29:A5:E8

        openssl x509 -noout -fingerprint -md5 -inform pem -in isrgrootx1.pem
        MD5 Fingerprint=0C:D2:F9:E0:DA:17:73:E9:ED:86:4D:A5:E3:70:E7:4E

        openssl x509 -noout -fingerprint -sha256 -inform pem -in isrgrootx1.pem
        SHA256 Fingerprint=96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6

    :param cert_pem: a PEM encoded Certificate
    :type cert_pem: str
    :param cert_pem_filepath: Optional filepath to the PEM encoded Certificate.
                              Only used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :param algorithm: default "sha1"
    :type algorithm: str
    :returns: Raw fingerprint data (e.g. without notation to separate pairs with colons)
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl x509 -noout -fingerprint -{algorithm} -inform PEM -in {CERTIFICATE}
    """
    log.info("fingerprint_cert >")
    _accepted_algorithms = ("sha1", "sha256", "md5")
    if algorithm not in _accepted_algorithms:
        raise ValueError(
            "algorithm `%s` not in `%s`" % (algorithm, _accepted_algorithms)
        )
    if openssl_crypto:
        try:
            data = openssl_crypto.load_certificate(
                openssl_crypto.FILETYPE_PEM, cert_pem.encode()
            )
        except Exception as exc:
            raise OpenSslError_InvalidCertificate(exc)
        if not data:
            raise OpenSslError_InvalidCertificate()
        fingerprint = data.digest(algorithm)
        _fingerprint = fingerprint.decode("utf8")
        _fingerprint = _fingerprint.replace(":", "")
        return _fingerprint

    log.debug(".fingerprint_cert > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    # generate tempfile if needed
    _tmpfile_cert = None
    if not cert_pem_filepath:
        _tmpfile_cert = new_pem_tempfile(cert_pem)
        cert_pem_filepath = _tmpfile_cert.name
    try:
        with psutil.Popen(
            [
                openssl_path,
                "x509",
                "-noout",
                "-fingerprint",
                "-%s" % algorithm,
                "-inform",
                "PEM",
                "-in",
                cert_pem_filepath,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data_bytes, err = proc.communicate()
            if not data_bytes:
                raise OpenSslError_InvalidCertificate(err)
            data_str = data_bytes.decode("utf8")

            # the output will look something like this:
            # 'SHA1 Fingerprint=F6:3C:5C:66:B5:25:51:EE:DA:DF:7C:E4:43:01:D6:46:68:0B:8F:5D\n'
            data_str = data_str.strip().split("=")[1]
            data_str = data_str.replace(":", "")
    finally:
        if _tmpfile_cert:
            _tmpfile_cert.close()
    return data_str


def _cleanup_openssl_md5(data: bytes) -> str:
    """
    some versions of openssl handle the md5 as:
        '1231231231'
    others handle as
        "(stdin)= 123123'
    """
    data = data.strip()
    data_str = data.decode("utf8")
    if len(data_str) == 32 and (data_str[:9] != "(stdin)= "):
        return data_str
    if data_str[:9] != "(stdin)= " or not data_str:
        raise OpenSslError("error reading md5 (i)")
    data_str = data_str[9:]
    if len(data_str) != 32:
        raise OpenSslError("error reading md5 (ii)")
    return data_str


def _cleanup_openssl_modulus(data: str) -> str:
    data = data.strip()
    if data[:8] == "Modulus=":
        data = data[8:]
    return data


def _format_crypto_components(
    data: Union[
        List[str],
        List[Tuple[str, ...]],
        List[Tuple[bytes, bytes]],
    ],
    fieldset: Optional[str] = None,
) -> str:
    """
    :param data: input
    :param fieldset: is unused. would be "issuer" or "subject"

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
    _out = []
    for _in_set in data:
        _converted = [i.decode("utf8") if isinstance(i, bytes) else i for i in _in_set]  # type: ignore[attr-defined]
        _out.append("=".join(_converted))
    out = "\n".join(_out).strip()
    return out


def _format_openssl_components(
    data: str,
    fieldset: Optional[str] = None,
) -> str:
    """
    different openssl versions give different responses. FUN.

    To make things easier, just format this into the crypto compatible payload,
    then invoke the crypto formattter

    openssl = [0, 9, 8]
    subject= /C=US/O=Internet Security Research Group/CN=ISRG Root X2

    openssl = [1, 1, 1]
    issuer=C = US, O = Internet Security Research Group, CN = ISRG Root X2
    """
    # print(openssl_version, data)
    if fieldset in ("issuer", "subject"):
        if fieldset == "issuer":
            if data.startswith("issuer= "):
                data = data[8:]
            elif data.startswith("issuer="):
                data = data[7:]
        elif fieldset == "subject":
            if data.startswith("subject= "):
                data = data[9:]
            elif data.startswith("subject="):
                data = data[8:]
        data_list: List[str]
        if "/" in data:
            data_list = [i.strip() for i in data.split("/")]
        elif "," in data:
            data_list = [i.strip() for i in data.split(",")]
        else:
            data_list = [
                data,
            ]
        _out = []
        for _cset in data_list:
            _cset_split = _cset.split("=")
            _cset_edited = tuple(i.strip() for i in _cset_split)
            _out.append(_cset_edited)
        return _format_crypto_components(_out, fieldset=fieldset)
    else:
        raise ValueError("invalid fieldset")


def modulus_md5_key(
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
) -> Optional[str]:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param key_pem: a PEM encoded PrivateKey
    :type key_pem: str
    :param key_pem_filepath: Optional filepath to the PEM encoded PrivateKey.
                             Only used for commandline OpenSSL fallback operations.
    :type key_pem_filepath: str
    :returns: md5 digest of key's modulus
    :rtype: str or None

    The OpenSSL Equivalent / Fallback is::

        md5(openssl rsa -noout -modulus -in {FILEPATH})
    """
    # ???: Should this raise an Exception instead of returning `None`?
    log.info("modulus_md5_key >")
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        privkey = openssl_crypto.load_privatekey(
            openssl_crypto.FILETYPE_PEM, key_pem.encode()
        )
        if _openssl_crypto__key_technology(privkey) == "RSA":
            modn = privkey.to_cryptography_key().public_key().public_numbers().n  # type: ignore[union-attr]
            data_str = "{:X}".format(modn)
        else:
            return None
    else:
        log.debug(".modulus_md5_key > openssl fallback")
        if not key_pem_filepath:
            # TODO: generate if needed?
            raise FallbackError_FilepathRequired("Must submit `key_pem_filepath`.")
        if openssl_version is None:
            check_openssl_version()

        # original code was:
        # openssl rsa -noout -modulus -in {KEY} | openssl md5
        # BUT
        # that pipes into md5: "Modulus={MOD}\n"
        with psutil.Popen(
            [openssl_path, "rsa", "-noout", "-modulus", "-in", key_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_modulus:
            data_bytes, err = proc_modulus.communicate()
            data_str = data_bytes.decode("utf8")
            data_str = _cleanup_openssl_modulus(data_str)
            if not data_str:
                return None
    data_bytes = data_str.encode()
    data_str = hashlib.md5(data_bytes).hexdigest()
    return data_str


def modulus_md5_csr(
    csr_pem: str,
    csr_pem_filepath: Optional[str] = None,
) -> Optional[str]:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param csr_pem: a PEM encoded CSR
    :type csr_pem: str
    :param csr_pem_filepath: Optional filepath to the PEM encoded CSR.
                             Only used for commandline OpenSSL fallback operations.
    :type csr_pem_filepath: str
    :returns: md5 digest of CSR's modulus
    :rtype: str or None

    The OpenSSL Equivalent / Fallback is::

        md5(openssl req -noout -modulus -in {FILEPATH})
    """
    # ???: Should this raise an Exception instead of returning `None`?
    log.info("modulus_md5_csr >")
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        csr = openssl_crypto.load_certificate_request(
            openssl_crypto.FILETYPE_PEM, csr_pem.encode()
        )
        _pubkey = csr.get_pubkey()
        if _openssl_crypto__key_technology(_pubkey) == "RSA":
            modn = _pubkey.to_cryptography_key().public_numbers().n  # type: ignore[union-attr]
            data_str = "{:X}".format(modn)
        else:
            return None
    else:
        log.debug(".modulus_md5_csr > openssl fallback")
        # original code was:
        # openssl req -noout -modulus -in {CSR} | openssl md5
        # BUT
        # that pipes into md5: "Modulus={MOD}\n"
        if not csr_pem_filepath:
            # TODO: generate if needed?
            raise FallbackError_FilepathRequired("Must submit `csr_pem_filepath`.")
        if openssl_version is None:
            check_openssl_version()

        with psutil.Popen(
            [openssl_path, "req", "-noout", "-modulus", "-in", csr_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_modulus:
            data_bytes, err = proc_modulus.communicate()
            data_str = data_bytes.decode("utf8")
            data_str = _cleanup_openssl_modulus(data_str)
            if not data_str:
                return None
    data_bytes = data_str.encode()
    data_str = hashlib.md5(data_bytes).hexdigest()
    return data_str


def modulus_md5_cert(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> Optional[str]:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param cert_pem: a PEM encoded Certificate
    :type cert_pem: str
    :param cert_pem_filepath: Optional filepath to the PEM encoded Certificate.
                              Only used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :returns: md5 digest of Certificate's modulus
    :rtype: str or None

    The OpenSSL Equivalent / Fallback is::

        md5(openssl x509 -noout -modulus -in {FILEPATH})
    """
    log.info("modulus_md5_cert >")
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        cert = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, cert_pem.encode()
        )
        _pubkey = cert.get_pubkey()
        if _openssl_crypto__key_technology(_pubkey) == "RSA":
            modn = cert.get_pubkey().to_cryptography_key().public_numbers().n  # type: ignore[union-attr]
            data_str = "{:X}".format(modn)
        else:
            return None
    else:
        log.debug(".modulus_md5_cert > openssl fallback")
        # original code was:
        # openssl x509 -noout -modulus -in {CERT} | openssl md5
        # BUT
        # that pipes into md5: "Modulus={MOD}\n"
        if not cert_pem_filepath:
            # TODO: generate if needed?
            raise FallbackError_FilepathRequired("Must submit `cert_pem_filepath`.")
        if openssl_version is None:
            check_openssl_version()

        with psutil.Popen(
            [openssl_path, "x509", "-noout", "-modulus", "-in", cert_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_modulus:
            data_bytes, err = proc_modulus.communicate()
            data_str = data_bytes.decode("utf8")
            data_str = _cleanup_openssl_modulus(data_str)
            if "Wrong Algorithm type" in data_str:
                # openssl 1.1.x
                return None
            if "No modulus for this public key type" in data_str:
                # openssl 3.0.x
                return None
    data_bytes = data_str.encode()
    data_str = hashlib.md5(data_bytes).hexdigest()
    return data_str


def _openssl_cert_single_op__pem(
    cert_pem: str,
    single_op: str,
) -> str:
    """
    this just invokes `_openssl_cert_single_op__pem_filepath` with a tempfile
    """
    _tmpfile_pem = new_pem_tempfile(cert_pem)
    try:
        cert_pem_filepath = _tmpfile_pem.name
        return _openssl_cert_single_op__pem_filepath(cert_pem_filepath, single_op)
    except Exception as exc:  # noqa: F841
        raise
    finally:
        _tmpfile_pem.close()


def _openssl_cert_single_op__pem_filepath(
    pem_filepath: str,
    single_op: str,
) -> str:
    """
    handles a single pem operation to `openssl x509`

    :param pem_filepath: filepath to pem encoded cert
    :type pem_filepath: str
    :param single_op: operation
    :type single_op: str
    :returns: openssl output
    :rtype: str

    openssl x509 -noout -issuer -in cert.pem
    openssl x509 -noout -issuer_hash -in cert.pem

    openssl x509 -noout -issuer_hash -in {CERT}
    returns the data found in
       X509v3 extensions:
           X509v3 Authority Key Identifier:
               keyid:{VALUE}

    openssl x509 -noout -subject_hash -in {CERT}
    returns the data found in
       X509v3 extensions:
           X509v3 Subject Key Identifier:
               {VALUE}

    The OpenSSL Equivalent / Fallback is::

        openssl x509 -noout {OPERATION} -in {FILEPATH})
    """
    if single_op not in (
        "-issuer_hash",
        "-issuer",
        "-subject_hash",
        "-subject",
        "-startdate",
        "-enddate",
    ):
        raise ValueError("invalid `single_op`")
    if not pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, "x509", "-noout", single_op, "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data_bytes, err = proc.communicate()
        if not data_bytes:
            raise OpenSslError_InvalidCertificate(err)
        data_str = data_bytes.decode("utf8")
        data_str = data_str.strip()
    return data_str


def cert_ext__pem_filepath(
    pem_filepath: str,
    ext: str,
) -> str:
    """
    handles a single pem operation to `openssl x509` with EXTENSION
    /usr/local/bin/openssl x509  -noout -ext subjectAltName -in cert.pem
    /usr/local/bin/openssl x509  -noout -ext authorityKeyIdentifier -in cert.pem
    /usr/local/bin/openssl x509  -noout -ext authorityInfoAccess -in cert.pem

    :param pem_filepath: filepath to the PEM encoded Certificate
    :type pem_filepath: str
    :param ext: a supported x509 extension
    :type ext: str
    :returns: openssl output value
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl x509 -noout -ext {EXT} -in {FILEPATH})
    """
    if ext not in ("subjectAltName", "authorityKeyIdentifier", "authorityInfoAccess"):
        raise ValueError("invalid `ext`")
    if not pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, "x509", "-noout", "-ext", ext, "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data_bytes, err = proc.communicate()
        if not data_bytes:
            raise OpenSslError_InvalidCertificate(err)
        data_str = data_bytes.decode("utf8")
        data_str = data_str.strip()
    return data_str


def csr_single_op__pem_filepath(
    pem_filepath: str,
    single_op: str,
) -> str:
    """
    handles a single pem operation to `openssl req` with EXTENSION

    openssl req -noout -subject -in csr.pem

    :param pem_filepath: filepath to the PEM encoded CSR.
    :type pem_filepath: str
    :param single_op: a supported `openssl req` operation
    :type single_op: str
    :returns: openssl output value
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl req -noout {OPERATION} -in {FILEPATH})
    """
    if single_op not in ("-subject",):
        raise ValueError("invalid `single_op`")
    if not pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, "req", "-noout", single_op, "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data_bytes, err = proc.communicate()
        if not data_bytes:
            raise OpenSslError_InvalidCSR(err)
        data_str = data_bytes.decode("utf8")
        data_str = data_str.strip()
    return data_str


def key_single_op__pem_filepath(
    keytype: str = "RSA",
    pem_filepath: str = "",
    single_op: str = "",
) -> str:
    """
    :param keytype: the type of key: RSA or EC
    :type keytype: str
    :param pem_filepath: filepath to the PEM encoded Key
    :type pem_filepath: str
    :param single_op: a supported `openssl rsa/ec` operation
    :type single_op: str
    :returns: openssl output value
    :rtype: str

    THIS SHOULD NOT BE USED BY INTERNAL CODE

    This is a bit odd...

    1. If "-check" is okay (or reading is okay), there may be no output on stdout
       HOWEVER
       the read message (success) may happen on stderr
    2. If openssl can't read the file, it will raise an exception

    earlier versions of openssl DO NOT HAVE `ec --check`
    current versions do

    The OpenSSL Equivalent / Fallback is::

        openssl {KEYTYPE} -noout {OPERATION} -in {FILEPATH})

    Such as:

        openssl rsa -noout -check -in {KEY}
        openssl rsa -noout -modulus -in {KEY}
        openssl rsa -noout -text -in {KEY}

        openssl ec -noout -in {KEY}
        openssl ec -noout -modulus -in {KEY}
        openssl ec -noout -text -in {KEY}
    """
    if keytype not in ("RSA", "EC"):
        raise ValueError("keytype must be `RSA or EC`")
    if single_op not in ("-check", "-modulus", "-text"):
        raise ValueError("invalid `single_op`")
    if not pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, keytype.lower(), "-noout", single_op, "-in", pem_filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data_bytes, err = proc.communicate()
        if not data_bytes:
            if err.startswith(b"unknown option -check"):
                raise OpenSslError_VersionTooLow(err)
            elif err != b"read EC key\nEC Key valid.\n":
                # this happens, where some versions give an error and no data!
                raise OpenSslError_InvalidKey(err)
        data_str = data_bytes.decode("utf8")
        data_str = data_str.strip()
    return data_str


def parse_cert__enddate(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> "datetime.datetime":
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param cert_pem: PEM encoded Certificate
    :type cert_pem: str
    :param cert_pem_filepath: Optional filepath to the PEM encoded Certificate.
                              Only used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :returns: end date
    :rtype: datetime.datetime

    The OpenSSL Equivalent / Fallback is::

        openssl x509 -noout -enddate -in {FILEPATH})
    """
    log.info("parse_cert__enddate >")
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        cert = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, cert_pem.encode()
        )
        date = cert.to_cryptography().not_valid_after
    else:
        log.debug(".parse_cert__enddate > openssl fallback")
        # openssl x509 -enddate -noout -in {CERT}
        if not cert_pem_filepath:
            raise FallbackError_FilepathRequired("Must submit `cert_pem_filepath`.")
        data = _openssl_cert_single_op__pem_filepath(cert_pem_filepath, "-enddate")
        if data[:9] != "notAfter=":
            raise OpenSslError_InvalidCertificate("unexpected format")
        data_date = data[9:]
        date = dateutil_parser.parse(data_date)
        date = date.replace(tzinfo=None)
    return date


def parse_cert__startdate(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> "datetime.datetime":
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param cert_pem: PEM encoded Certificate
    :type cert_pem: str
    :param cert_pem_filepath: Optional filepath to the PEM encoded Certificate.
                              Only used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :returns: start date
    :rtype: datetime.datetime

    The OpenSSL Equivalent / Fallback is::

        openssl x509 -noout -startdate -in {FILEPATH})
    """
    log.info("parse_cert__startdate >")
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        cert = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, cert_pem.encode()
        )
        date = cert.to_cryptography().not_valid_before
    else:
        log.debug(".parse_cert__startdate > openssl fallback")
        # openssl x509 -startdate -noout -in {CERT}
        if not cert_pem_filepath:
            raise FallbackError_FilepathRequired("Must submit `cert_pem_filepath`.")
        data = _openssl_cert_single_op__pem_filepath(cert_pem_filepath, "-startdate")
        if data[:10] != "notBefore=":
            raise OpenSslError_InvalidCertificate("unexpected format")
        data_date = data[10:]
        date = dateutil_parser.parse(data_date)
        date = date.replace(tzinfo=None)
    return date


def parse_cert__spki_sha256(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
    cryptography_cert: Optional["Certificate"] = None,
    key_technology: Optional[str] = None,
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param str cert_pem: PEM encoded Certificate
    :param str cert_pem_filepath: Optional filepath to PEM encoded Certificate.
                                  Only used for commandline OpenSSL fallback operations.
    :param cryptography_cert: optional hint to aid in crypto commands
    :type cryptography_cert: `OpenSSL.crypto.load_certificate(...).to_cryptography()``
    :param str key_technology: optional hint to aid in openssl fallback
    :param bool as_b64: encode with b64?
    :returns: spki sha256
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        :function :_openssl_spki_hash_cert
    """
    log.info("parse_cert__spki_sha256 >")
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        if not cryptography_cert:
            cert = openssl_crypto.load_certificate(
                openssl_crypto.FILETYPE_PEM, cert_pem.encode()
            )
            cryptography_cert = cert.to_cryptography()
        cryptography_publickey = cryptography_cert.public_key()
        return _cryptography__public_key_spki_sha256(
            cryptography_publickey,
            as_b64=as_b64,
        )
    log.debug(".parse_cert__spki_sha256 > openssl fallback")
    if not cert_pem_filepath:
        # TODO: generate tempfile?
        raise FallbackError_FilepathRequired("Must submit `cert_pem_filepath`.")
    tmpfile_pem = None
    try:
        if key_technology is None:
            key_technology = parse_cert__key_technology(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
        spki_sha256 = _openssl_spki_hash_cert(
            key_technology=key_technology,
            cert_pem_filepath=cert_pem_filepath,
            as_b64=as_b64,
        )
        return spki_sha256
    except Exception as exc:  # noqa: F841
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_cert__key_technology(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> Optional[str]:
    """
    :param cert_pem: PEM encoded Certificate
    :type cert_pem: str
    :param cert_pem_filepath: Optional filepath to PEM encoded Certificate.
                              Only used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :returns: key technology type
    :rtype: str

    The OpenSSL Equivalent / Fallback is::
    Regex the output of::

        openssl x509 -in {FILEPATH} -noout -text
    """
    log.info("parse_cert__key_technology >")
    if openssl_crypto:
        cert = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, cert_pem.encode()
        )
        return _openssl_crypto__key_technology(cert.get_pubkey())
    log.debug(".parse_cert__key_technology > openssl fallback")
    # `openssl x509 -in MYCERT -noout -text`
    if openssl_version is None:
        check_openssl_version()

    if not cert_pem_filepath:
        # TODO: generate tempfile?
        raise FallbackError_FilepathRequired("Must submit `cert_pem_filepath`.")
    with psutil.Popen(
        [openssl_path, "x509", "-in", cert_pem_filepath, "-noout", "-text"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        _data_bytes, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("Error loading {0}: {1}".format(cert_pem_filepath, err))
        data_str = _data_bytes.decode("utf8")
    return _cert_pubkey_technology__text(data_str)


def parse_cert(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> Dict:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param cert_pem: PEM encoded Certificate
    :type cert_pem: str
    :param cert_pem_filepath: Optional filepath to PEM encoded Certificate
                              Only used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :returns: dict representation of select Certificate information
    :rtype: dict
    """
    log.info("parse_cert >")
    rval: Dict[str, Union[None, str, "datetime.datetime", List[str]]] = {
        "issuer": None,
        "subject": None,
        "enddate": None,
        "startdate": None,
        "SubjectAlternativeName": None,
        "key_technology": None,
        "fingerprint_sha1": None,
        "spki_sha256": None,
        "issuer_uri": None,
        "authority_key_identifier": None,
    }

    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        cert = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, cert_pem.encode()
        )
        cert_cryptography = cert.to_cryptography()
        _issuer = cert.get_issuer().get_components()
        _subject = cert.get_subject().get_components()
        rval["issuer"] = _format_crypto_components(_issuer, fieldset="issuer")
        rval["subject"] = _format_crypto_components(_subject, fieldset="subject")
        rval["enddate"] = cert_cryptography.not_valid_after
        rval["startdate"] = cert_cryptography.not_valid_before
        rval["key_technology"] = _openssl_crypto__key_technology(cert.get_pubkey())
        fingerprint_bytes = cert.digest("sha1")
        fingerprint = fingerprint_bytes.decode("utf8")
        rval["fingerprint_sha1"] = fingerprint.replace(":", "")
        rval["spki_sha256"] = parse_cert__spki_sha256(
            cert_pem=cert_pem,
            cert_pem_filepath=cert_pem_filepath,
            cryptography_cert=cert_cryptography,
            as_b64=False,
        )
        try:
            ext = cert_cryptography.extensions.get_extension_for_oid(
                cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            if ext:
                _names: List[str] = ext.value.get_values_for_type(cryptography.x509.DNSName)  # type: ignore[attr-defined]
                rval["SubjectAlternativeName"] = sorted(_names)
        except Exception as exc:  # noqa: F841
            pass
        try:
            ext = cert_cryptography.extensions.get_extension_for_oid(
                cryptography.x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            )
            if ext:
                # this comes out as binary, so we need to convert it to the
                # openssl version, which is an list of uppercase hex pairs
                _as_binary = ext.value.key_identifier  # type: ignore[attr-defined]
                rval["authority_key_identifier"] = convert_binary_to_hex(_as_binary)
        except Exception as exc:  # noqa: F841
            pass
        try:
            ext = cert_cryptography.extensions.get_extension_for_oid(
                cryptography.x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            if ext:
                for _item in ext.value:  # type: ignore[attr-defined]
                    if not isinstance(
                        _item, cryptography.x509.extensions.AccessDescription
                    ):
                        continue
                    # _item.access_method is either:
                    # * cryptography.x509.oid.AuthorityInformationAccessOID.OCSP
                    # * cryptography.x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
                    # we only care about CA_ISSUERS
                    if (
                        _item.access_method
                        == cryptography.x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
                    ):
                        if isinstance(
                            _item.access_location,
                            cryptography.x509.UniformResourceIdentifier,
                        ):
                            rval["issuer_uri"] = _item.access_location.value
        except Exception as exc:  # noqa: F841
            pass
        return rval

    log.debug(".parse_cert > openssl fallback")
    global openssl_version
    global _openssl_behavior
    tmpfile_pem = None
    try:
        if not cert_pem_filepath:
            tmpfile_pem = new_pem_tempfile(cert_pem)
            cert_pem_filepath = tmpfile_pem.name

        _issuer_b = _openssl_cert_single_op__pem_filepath(cert_pem_filepath, "-issuer")
        _subject_b = _openssl_cert_single_op__pem_filepath(
            cert_pem_filepath, "-subject"
        )
        rval["issuer"] = _format_openssl_components(_issuer_b, fieldset="issuer")
        rval["subject"] = _format_openssl_components(_subject_b, fieldset="subject")
        rval["startdate"] = parse_cert__startdate(
            cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
        )
        rval["enddate"] = parse_cert__enddate(
            cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
        )
        rval["key_technology"] = _key_technology = parse_cert__key_technology(
            cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
        )
        rval["fingerprint_sha1"] = fingerprint_cert(
            cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath, algorithm="sha1"
        )
        rval["spki_sha256"] = parse_cert__spki_sha256(
            cert_pem=cert_pem,
            cert_pem_filepath=cert_pem_filepath,
            key_technology=_key_technology,
            as_b64=False,
        )

        if openssl_version is None:
            check_openssl_version()

        if _openssl_behavior == "b":
            try:
                _text = cert_ext__pem_filepath(cert_pem_filepath, "subjectAltName")
                found_domains = san_domains_from_text(_text)
                rval["SubjectAlternativeName"] = found_domains
            except Exception as exc:  # noqa: F841
                pass
            try:
                _text = cert_ext__pem_filepath(
                    cert_pem_filepath, "authorityKeyIdentifier"
                )
                authority_key_identifier = authority_key_identifier_from_text(_text)
                rval["authority_key_identifier"] = authority_key_identifier
            except Exception as exc:  # noqa: F841
                pass
            try:
                _text = cert_ext__pem_filepath(cert_pem_filepath, "authorityInfoAccess")
                issuer_uri = issuer_uri_from_text(_text)
                rval["issuer_uri"] = issuer_uri
            except Exception as exc:  # noqa: F841
                pass
        else:
            if openssl_version is None:
                check_openssl_version()

            with psutil.Popen(
                [openssl_path, "x509", "-text", "-noout", "-in", cert_pem_filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc_text:
                data, err = proc_text.communicate()
                data = data.decode("utf8")
                found_domains = san_domains_from_text(data)
                rval["SubjectAlternativeName"] = found_domains

                authority_key_identifier = authority_key_identifier_from_text(data)
                rval["authority_key_identifier"] = authority_key_identifier

                issuer_uri = issuer_uri_from_text(data)
                rval["issuer_uri"] = issuer_uri

        return rval
    except Exception as exc:  # noqa: F841
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_csr__key_technology(
    csr_pem: str,
    csr_pem_filepath: Optional[str] = None,
    crypto_csr: Optional["X509Req"] = None,
) -> Optional[str]:
    """
    :param csr_pem: PEM encoded CSR
    :type csr_pem: str
    :param csr_pem_filepath: Optional filepath to PEM encoded CSR.
                             Only used for commandline OpenSSL fallback operations.
    :type csr_pem_filepath: str
    :param crypto_csr: openssl cryptography object
    :type crypto_csr: `OpenSSL.crypto.X509Req`
    :returns: key technology type
    :rtype: str or None

    The OpenSSL Equivalent / Fallback is::
    Regex the output of::

        openssl req -in {FILEPATH} -noout -text
    """
    log.info("parse_csr__key_technology >")
    if openssl_crypto:
        if not crypto_csr:
            crypto_csr = openssl_crypto.load_certificate_request(
                openssl_crypto.FILETYPE_PEM, csr_pem.encode()
            )
        return _openssl_crypto__key_technology(crypto_csr.get_pubkey())
    log.debug(".parse_csr__key_technology > openssl fallback")
    # `openssl req -in MYCERT -noout -text`
    if not csr_pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `csr_pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, "req", "-in", csr_pem_filepath, "-noout", "-text"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data_bytes, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("Error loading {0}: {1}".format(csr_pem_filepath, err))
        data_str = data_bytes.decode("utf8")
    return _csr_pubkey_technology__text(data_str)


def parse_csr__spki_sha256(
    csr_pem: str,
    csr_pem_filepath: Optional[str] = None,
    crypto_csr: Optional["X509Req"] = None,
    key_technology: Optional[str] = None,
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param str csr_pem: CSR in PEM encoding
    :param str csr_pem_filepath: Optional filepath to PEM encoded CSR.
                                 Only used for commandline OpenSSL fallback operations.
    :param object crypto_csr: optional hint to aid in crypto commands
    :param str key_technology: optional hint to aid in openssl fallback
    :param bool as_b64: encode with b64?
    :returns: spki sha256
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        :_see:_openssl_spki_hash_csr
    """
    log.info("parse_csr__spki_sha256 >")
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        if not crypto_csr:
            crypto_csr = openssl_crypto.load_certificate_request(
                openssl_crypto.FILETYPE_PEM, csr_pem.encode()
            )
        cryptography_publickey = crypto_csr.get_pubkey().to_cryptography_key()
        spki_sha256 = _cryptography__public_key_spki_sha256(
            cryptography_publickey, as_b64=as_b64
        )
        return spki_sha256
    log.debug(".parse_csr__spki_sha256 > openssl fallback")
    if not csr_pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `csr_pem_filepath`.")
    tmpfile_pem = None
    try:
        if key_technology is None:
            key_technology = parse_csr__key_technology(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
        spki_sha256 = _openssl_spki_hash_csr(
            key_technology=key_technology,
            csr_pem_filepath=csr_pem_filepath,
            as_b64=as_b64,
        )
        return spki_sha256
    except Exception as exc:  # noqa: F841
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_csr(
    csr_pem: str,
    csr_pem_filepath: Optional[str] = None,
) -> Dict:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param str csr_pem: CSR in PEM encoding
    :param str csr_pem_filepath: Optional filepath to PEM encoded CSR.
                                 Only used for commandline OpenSSL fallback operations.
    :returns: dict of select CSR data
    :rtype: dict
    """
    log.info("parse_csr >")
    rval: Dict[str, Union[None, List, str]] = {
        "key_technology": None,
        "spki_sha256": None,
        "SubjectAlternativeName": [],
        "subject": None,
    }

    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        _crypto_csr = openssl_crypto.load_certificate_request(
            openssl_crypto.FILETYPE_PEM, csr_pem.encode()
        )
        _subject = _crypto_csr.get_subject().get_components()
        rval["subject"] = _format_crypto_components(_subject, fieldset="subject")
        _cryptography_csr = _crypto_csr.to_cryptography()
        try:
            ext = _cryptography_csr.extensions.get_extension_for_oid(
                cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            if ext:
                _names = ext.value.get_values_for_type(cryptography.x509.DNSName)  # type: ignore[attr-defined]
                rval["SubjectAlternativeName"] = sorted(_names)
        except Exception as exc:  # noqa: F841
            pass
        rval["key_technology"] = _openssl_crypto__key_technology(
            _crypto_csr.get_pubkey()
        )
        rval["spki_sha256"] = parse_csr__spki_sha256(
            csr_pem=csr_pem,
            csr_pem_filepath=csr_pem_filepath,
            crypto_csr=_crypto_csr,
            as_b64=False,
        )
        return rval

    log.debug(".parse_csr > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    tmpfile_pem = None
    try:
        if not csr_pem_filepath:
            tmpfile_pem = new_pem_tempfile(csr_pem)
            csr_pem_filepath = tmpfile_pem.name
        _subject2 = csr_single_op__pem_filepath(csr_pem_filepath, "-subject")
        rval["subject"] = _format_openssl_components(_subject2, fieldset="subject")
        rval["key_technology"] = _key_technology = parse_csr__key_technology(
            csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
        )
        rval["spki_sha256"] = parse_csr__spki_sha256(
            csr_pem=csr_pem,
            csr_pem_filepath=csr_pem_filepath,
            key_technology=_key_technology,
            as_b64=False,
        )
        with psutil.Popen(
            [openssl_path, "req", "-text", "-noout", "-in", csr_pem_filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc_text:
            data, err = proc_text.communicate()
            data = data.decode("utf8")
            found_domains = san_domains_from_text(data)
            rval["SubjectAlternativeName"] = found_domains
        return rval
    except Exception as exc:  # noqa: F841
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_key__spki_sha256(
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
    cryptography_publickey: Optional["_TYPES_CRYPTOGRAPHY_KEYS"] = None,
    key_technology: Optional[str] = None,
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param str key_pem: Key in PEM form
    :param str key_pem_filepath: Optional filepath to PEM.
                                 Only used for commandline OpenSSL fallback operations.
    :param cryptography_publickey: optional hint to aid in crypto commands
    :type cryptography_publickey: cryptography.hazmat.backends.openssl.rsa._RSAPublicKey
        openssl_crypto.load_privatekey(...).to_cryptography_key().public_key()
    :param str key_technology: optional hint to aid in openssl fallback
    :param bool as_b64: encode with b64?
    :returns: spki sha256
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        :_see:_openssl_spki_hash_pkey
    """
    log.info("parse_key__spki_sha256 >")
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        if not cryptography_publickey:
            _crypto_privkey = openssl_crypto.load_privatekey(
                openssl_crypto.FILETYPE_PEM, key_pem
            )
            _cryptography_privkey = _crypto_privkey.to_cryptography_key()
            cryptography_publickey = _cryptography_privkey.public_key()  # type: ignore[union-attr]
        spki_sha256 = _cryptography__public_key_spki_sha256(
            cryptography_publickey, as_b64=as_b64
        )
        return spki_sha256
    log.debug(".parse_key__spki_sha256 > openssl fallback")
    if not key_pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `key_pem_filepath`.")
    tmpfile_pem = None
    try:
        if key_technology is None:
            key_technology = parse_key__technology(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
        spki_sha256 = _openssl_spki_hash_pkey(
            key_technology=key_technology,
            key_pem_filepath=key_pem_filepath,
            as_b64=as_b64,
        )
        return spki_sha256
    except Exception as exc:  # noqa: F841
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_key__technology(
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
    crypto_privatekey: Optional["PKey"] = None,
) -> str:
    """
    :param str key_pem: Key in PEM form
    :param str key_pem_filepath: Optional filepath to PEM.
                                 Only used for commandline OpenSSL fallback operations.
    :param object crypto_privatekey: optional hint to aid in crypto commands
    :returns: key technology
    :rtype: str
    """
    log.info("parse_key__technology >")
    if openssl_crypto:
        if not crypto_privatekey:
            crypto_privatekey = openssl_crypto.load_privatekey(
                openssl_crypto.FILETYPE_PEM, key_pem
            )
        _cert_type = crypto_privatekey.type()
        if _cert_type == openssl_crypto.TYPE_RSA:
            return "RSA"
        elif _cert_type == openssl_crypto.TYPE_EC:
            return "EC"
        raise OpenSslError_InvalidKey("I don't know what kind of key this is")
    log.debug(".parse_key__technology > openssl fallback")
    tmpfile_pem = None
    try:
        if not key_pem_filepath:
            tmpfile_pem = new_pem_tempfile(key_pem)
            key_pem_filepath = tmpfile_pem.name
        try:
            _checked = key_single_op__pem_filepath(  # noqa: F841
                "RSA", key_pem_filepath, "-check"
            )
            return "RSA"
        except OpenSslError_InvalidKey as exc1:  # noqa: F841
            try:
                _checked = key_single_op__pem_filepath(  # noqa: F841
                    "EC", key_pem_filepath, "-check"
                )
                return "EC"
            except OpenSslError_VersionTooLow as exc2:  # noqa: F841
                # TODO: make this conditional
                # i doubt many people have old versions but who knows?
                raise
    except Exception as exc0:  # noqa: F841
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_key(
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
) -> Dict:
    """
    !!!: This is a debugging display function. The output is not guaranteed across installations.

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param str key_pem: Key in PEM encoding
    :param str key_pem_filepath: Optional filepath to PEM encoded Key.
                                 Only used for commandline OpenSSL fallback operations.
    :returns: dict of select CSR data
    :rtype: dict
    """
    log.info("parse_key >")
    rval: Dict[str, Union[None, str]] = {
        "check": None,
        "text": None,
        "modulus_md5": None,
        "key_technology": None,
        "spki_sha256": None,
    }
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and cryptography:
        # TODO: crypto version of `--text`

        # this part ONLY works on RSA keys
        # can't do this with certbot/pyopenssl yet
        # see https://github.com/pyca/pyopenssl/issues/291
        # certbot just wraps that
        try:
            # note: we don't need to provide key_pem_filepath because we already rely on openssl
            rval["check"] = validate_key(key_pem=key_pem)
        except Exception as exc:
            rval["check"] = str(exc)

        _crypto_privkey = openssl_crypto.load_privatekey(
            openssl_crypto.FILETYPE_PEM, key_pem
        )
        _cert_type = _crypto_privkey.type()
        _cryptography_privkey = _crypto_privkey.to_cryptography_key()
        _cryptography_publickey = _cryptography_privkey.public_key()  # type: ignore[union-attr]
        if _cert_type == openssl_crypto.TYPE_RSA:
            rval["key_technology"] = "RSA"
            try:
                modn = _cryptography_publickey.public_numbers().n  # type: ignore[union-attr]
                modn = "{:X}".format(modn)
                modn = modn.encode()
                rval["modulus_md5"] = hashlib.md5(modn).hexdigest()
            except Exception as exc:
                rval["XX-modulus_md5"] = str(exc)
        elif _cert_type == openssl_crypto.TYPE_EC:
            rval["key_technology"] = "EC"

        rval["spki_sha256"] = parse_key__spki_sha256(
            key_pem="",
            key_pem_filepath=None,
            cryptography_publickey=_cryptography_publickey,
            as_b64=False,
        )
        return rval

    log.debug(".parse_key > openssl fallback")
    tmpfile_pem = None
    try:
        if not key_pem_filepath:
            tmpfile_pem = new_pem_tempfile(key_pem)
            key_pem_filepath = tmpfile_pem.name
        try:
            rval["key_technology"] = _key_technology = parse_key__technology(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
        except OpenSslError_VersionTooLow as exc2:  # noqa: F841
            # TODO: make this conditional
            # i doubt many people have old versions but who knows?
            raise
        try:
            rval["check"] = key_single_op__pem_filepath(
                _key_technology, key_pem_filepath, "-check"
            )
        except Exception as exc1:
            rval["XX-check"] = str(exc1)
        rval["text"] = key_single_op__pem_filepath(
            _key_technology, key_pem_filepath, "-text"
        )
        if _key_technology in ("RSA", "EC"):
            # rval["spki_sha256"] = _openssl_spki_hash_pkey(key_technology=_key_technology, key_pem_filepath=key_pem_filepath, as_b64=False)
            rval["spki_sha256"] = parse_key__spki_sha256(
                key_pem=key_pem,
                key_pem_filepath=key_pem_filepath,
                key_technology=_key_technology,
                as_b64=False,
            )

        if _key_technology == "RSA":
            _modulus = key_single_op__pem_filepath(
                _key_technology, key_pem_filepath, "-modulus"
            )
            _modulus = _cleanup_openssl_modulus(_modulus)
            _modulus_bytes = _modulus.encode()
            rval["modulus_md5"] = hashlib.md5(_modulus_bytes).hexdigest()
        return rval
    except Exception as exc:  # noqa: F841
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def new_account_key(
    key_technology_id: int = KeyTechnology.RSA,
    rsa_bits: int = 2048,
) -> str:
    """
    :param int key_technology_id: Key Technology type. Default: KeyTechnology.RSA
    :param int rsa_bits: number of bits. default 2048
    :returns: AccountKey in PEM format
    :rtype: str
    """
    if rsa_bits not in ALLOWED_BITS_RSA:
        raise ValueError(
            "LetsEncrypt only supports RSA keys with bits: %s" % ALLOWED_BITS_RSA
        )
    if key_technology_id != KeyTechnology.RSA:
        raise ValueError("invalid `key_technology_id`")
    return new_key_rsa(bits=rsa_bits)


def new_private_key(
    key_technology_id: int,
    rsa_bits: Optional[int] = None,
    ec_bits: Optional[int] = None,
) -> str:
    """
    :param int key_technology_id: Key Technology type. Default: None
    :param int rsa_bits: number of bits. default None
    :param int ec_bits: number of bits. default None
    :returns: PrivateKey in PEM format
    :rtype: str
    """
    if key_technology_id == KeyTechnology.RSA:
        kwargs = {"bits": rsa_bits} if rsa_bits else {}
        return new_key_rsa(**kwargs)
    elif key_technology_id == KeyTechnology.EC:
        kwargs = {"bits": ec_bits} if ec_bits else {}
        return new_key_ec(**kwargs)
    else:
        raise ValueError("invalid `key_technology_id`")


def new_key_ec(bits: int = 384) -> str:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param int bits: number of bits. default 384
    :returns: ECDSA Key in PEM format
    :rtype: str
    """
    log.info("new_key_ec >")
    log.debug(".new_key_ec > bits = %s", bits)
    if bits not in ALLOWED_BITS_ECDSA:
        raise ValueError(
            "LetsEncrypt only supports ECDSA keys with bits: %s; not %s"
            % (ALLOWED_BITS_ECDSA, bits)
        )

    if crypto_ec and crypto_serialization and (crypto_default_backend is not None):
        # see https://github.com/pyca/pyopenssl/issues/291
        if 256 == bits:
            key = crypto_ec.generate_private_key(
                crypto_ec.SECP256R1(), crypto_default_backend()
            )
        elif 384 == bits:
            key = crypto_ec.generate_private_key(
                crypto_ec.SECP384R1(), crypto_default_backend()
            )
        key_pem = key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        )
        # load it: openssl_crypto.load_privatekey(openssl_crypto.FILETYPE_PEM, key_pem)
        key_pem_str = key_pem.decode("utf8")
        key_pem_str = cleanup_pem_text(key_pem_str)
        return key_pem_str

    log.debug(".new_key_ec > openssl fallback")
    # openssl ecparam -list_curves
    curve = None
    if 256 == bits:
        curve = "secp256k1"
    elif 384 == bits:
        curve = "secp384r1"
    # openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
    # -noout will suppress printing the EC Param (see https://security.stackexchange.com/questions/29778/why-does-openssl-writes-ec-parameters-when-generating-private-key)
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, "ecparam", "-name", curve, "-genkey", "-noout"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data_bytes, err = proc.communicate()
        if not data_bytes:
            raise OpenSslError_InvalidKey(err)
        key_pem_str = data_bytes.decode("utf8")
        key_pem_str = cleanup_pem_text(key_pem_str)
        try:
            # we need a tmpfile to validate it
            tmpfile_pem = new_pem_tempfile(key_pem_str)
            # this will raise an error on fails
            key_technology = validate_key(  # noqa: F841
                key_pem=key_pem_str, key_pem_filepath=tmpfile_pem.name
            )
        finally:
            tmpfile_pem.close()
    return key_pem_str


def new_key_rsa(bits: int = 4096) -> str:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param int bits: number of bits. default 4096
    :returns: RSA Key in PEM format
    :rtype: str
    """
    log.info("new_key_rsa >")
    log.debug(".new_key_rsa > bits = %s", bits)
    if bits not in ALLOWED_BITS_RSA:
        raise ValueError(
            "LetsEncrypt only supports RSA keys with bits: %s; not %s"
            % (str(ALLOWED_BITS_RSA), bits)
        )
    if certbot_crypto_util:
        key_pem = certbot_crypto_util.make_key(bits)
        key_pem_str = key_pem.decode("utf8")
        key_pem_str = cleanup_pem_text(key_pem_str)
        return key_pem_str
    log.debug(".new_key_rsa > openssl fallback")
    # openssl genrsa 4096 > domain.key
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, "genrsa", str(bits)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        data_bytes, err = proc.communicate()
        if not data_bytes:
            raise OpenSslError_InvalidKey(err)
        key_pem_str = data_bytes.decode("utf8")
        key_pem_str = cleanup_pem_text(key_pem_str)
        try:
            # we need a tmpfile to validate it
            tmpfile_pem = new_pem_tempfile(key_pem_str)
            # this will raise an error on fails
            key_technology = validate_key(  # noqa: F841
                key_pem=key_pem_str, key_pem_filepath=tmpfile_pem.name
            )
        finally:
            tmpfile_pem.close()
    return key_pem_str


def convert_jwk_to_ans1(pkey_jsons: str) -> str:
    """
    input is a json string

    adapted from https://github.com/JonLundy
    who shared this gist under the MIT license:
        https://gist.github.com/JonLundy/f25c99ee0770e19dc595

    :param pkey_jsons: JWK Key
    :type pkey_jsons: str
    :returns: Key in ANS1 Format
    :rtype: str
    """
    pkey = json.loads(pkey_jsons)

    def enc(data_bytes: bytes) -> str:
        missing_padding = 4 - len(data_bytes) % 4
        if missing_padding:
            data_bytes += b"=" * missing_padding
        data_bytes = binascii.hexlify(base64.b64decode(data_bytes, b"-_")).upper()
        data_str = data_bytes.decode("utf8")
        return "0x" + data_str

    for k, v in list(pkey.items()):
        if k == "kty":
            continue
        pkey[k] = enc(v.encode())

    converted = []
    converted.append("asn1=SEQUENCE:private_key\n[private_key]\nversion=INTEGER:0")
    converted.append("n=INTEGER:{}".format(pkey["n"]))
    converted.append("e=INTEGER:{}".format(pkey["e"]))
    converted.append("d=INTEGER:{}".format(pkey["d"]))
    converted.append("p=INTEGER:{}".format(pkey["p"]))
    converted.append("q=INTEGER:{}".format(pkey["q"]))
    converted.append("dp=INTEGER:{}".format(pkey["dp"]))
    converted.append("dq=INTEGER:{}".format(pkey["dq"]))
    converted.append("qi=INTEGER:{}".format(pkey["qi"]))
    converted.append("")  # trailing newline
    converted_ = "\n".join(converted)
    return converted_


def convert_lejson_to_pem(pkey_jsons: str) -> str:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    input is a json string

    adapted from https://github.com/JonLundy
    who shared this gist under the MIT license:
        https://gist.github.com/JonLundy/f25c99ee0770e19dc595

    openssl asn1parse -noout -out private_key.der -genconf <(python conv.py private_key.json)
    openssl rsa -in private_key.der -inform der > private_key.pem
    openssl rsa -in private_key.pem

    :param pkey_jsons: LetsEncrypt JSON formatted Key
    :type pkey_jsons: str
    :returns: Key in PEM Encoding
    :rtype: str
    """
    log.info("convert_lejson_to_pem >")

    if crypto_serialization and josepy:
        pkey = josepy.JWKRSA.json_loads(pkey_jsons)
        as_pem = pkey.key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        )
        as_pem = as_pem.decode("utf8")
        as_pem = cleanup_pem_text(as_pem)

        # note: we don't need to provide key_pem_filepath because we already rely on openssl
        key_technology = validate_key(key_pem=as_pem)
        return as_pem

    log.debug(".convert_lejson_to_pem > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    pkey_ans1 = convert_jwk_to_ans1(pkey_jsons)
    as_pem = None
    tmpfiles = []
    try:
        tmpfile_ans1 = new_pem_tempfile(pkey_ans1)
        tmpfiles.append(tmpfile_ans1)

        tmpfile_der = new_pem_tempfile("")
        tmpfiles.append(tmpfile_der)

        with psutil.Popen(
            [
                openssl_path,
                "asn1parse",
                "-noout",
                "-out",
                tmpfile_der.name,
                "-genconf",
                tmpfile_ans1.name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            generated, err = proc.communicate()
            if err:
                raise ValueError(err)
        # convert to pem
        as_pem = convert_der_to_pem__rsakey(tmpfile_der.read())

        # we need a tmpfile to validate it
        tmpfile_pem = new_pem_tempfile(as_pem)
        tmpfiles.append(tmpfile_pem)

        # validate it
        key_technology = validate_key(  # noqa: F841
            key_pem=as_pem, key_pem_filepath=tmpfile_pem.name
        )
        return as_pem

    except Exception as exc:  # noqa: F841
        raise
    finally:
        for t in tmpfiles:
            t.close()


def cert_and_chain_from_fullchain(
    fullchain_pem: str,
) -> Tuple[str, str]:
    """
    Split `fullchain_pem` into `cert_pem` and `chain_pem`

    :param str fullchain_pem: concatenated Certificate + Chain
    :returns: tuple of two PEM encoded Certificates in the format of
        (LeafCertificate, ChainedIntermediates)
    :rtype: tuple

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    Portions of this are a reimplentation of certbot's code
    Certbot's code is Apache2 licensed
    https://raw.githubusercontent.com/certbot/certbot/master/LICENSE.txt
    """
    log.info("cert_and_chain_from_fullchain >")
    if certbot_crypto_util:
        try:
            return certbot_crypto_util.cert_and_chain_from_fullchain(fullchain_pem)
        except Exception as exc:
            raise OpenSslError(exc)

    log.debug(".cert_and_chain_from_fullchain > openssl fallback")
    # First pass: find the boundary of each certificate in the chain.
    # TODO: This will silently skip over any "explanatory text" in between boundaries,
    # which is prohibited by RFC8555.
    certs = split_pem_chain(fullchain_pem)
    if len(certs) < 2:
        raise OpenSslError(
            "failed to parse fullchain into cert and chain: "
            + "less than 2 certificates in chain"
        )
    # Second pass: for each certificate found, parse it using OpenSSL and re-encode it,
    # with the effect of normalizing any encoding variations (e.g. CRLF, whitespace).
    certs_normalized = []
    for _cert_pem in certs:
        _cert_pem = _openssl_cert__normalize_pem(_cert_pem)
        _cert_pem = cleanup_pem_text(_cert_pem)
        certs_normalized.append(_cert_pem)

    # Since each normalized cert has a newline suffix, no extra newlines are required.
    return (certs_normalized[0], "".join(certs_normalized[1:]))


def decompose_chain(fullchain_pem: str) -> List[str]:
    """
    Split `fullchain_pem` into multiple PEM encoded certs

    :param str fullchain_pem: concatenated Certificate + Chain
    :returns: list of all PEM Encoded Certificates discovered in the fullchain
    :rtype: list
    """
    log.info("decompose_chain >")
    # First pass: find the boundary of each certificate in the chain.
    # TODO: This will silently skip over any "explanatory text" in between boundaries,
    # which is prohibited by RFC8555.
    certs = split_pem_chain(fullchain_pem)
    if len(certs) < 2:
        raise OpenSslError(
            "failed to parse fullchain into cert and chain: "
            + "less than 2 certificates in chain"
        )
    # Second pass: for each certificate found, parse it using OpenSSL and re-encode it,
    # with the effect of normalizing any encoding variations (e.g. CRLF, whitespace).
    if openssl_crypto:
        certs_normalized = [
            openssl_crypto.dump_certificate(
                openssl_crypto.FILETYPE_PEM,
                openssl_crypto.load_certificate(
                    openssl_crypto.FILETYPE_PEM, cert.encode()
                ),
            ).decode("utf8")
            for cert in certs
        ]
        return certs_normalized
    log.debug(".decompose_chain > openssl fallback")
    certs_normalized = []
    for _cert_pem in certs:
        _cert_pem = _openssl_cert__normalize_pem(_cert_pem)
        _cert_pem = cleanup_pem_text(_cert_pem)
        certs_normalized.append(_cert_pem)
    return certs_normalized


def ensure_chain(
    root_pem: str,
    fullchain_pem: Optional[str] = None,
    cert_pem: Optional[str] = None,
    chain_pem: Optional[str] = None,
    root_pems_other: Optional[List[str]] = None,
) -> bool:
    """
    validates from a root down to a chain
    if chain is a fullchain (with endentity), cert_pem can be None

    THIS WILL RAISE ERRORS, NOT RETURN VALUES

    submit EITHER fullchain_pem or chain_pem+cert_pem

    :param root_pem: The PEM Encoded Root Certificate. Required.
    :type root_pem: str
    :param fullchain_pem: A full Certificate chain in PEM encoding, which
        consists of a Leaf Certificate, and optionally multiple upstream certs in
        a single string.
        If provided:
            * `:param:cert_pem` MUST NOT be provided
            * `:param:chain_pem` MUST NOT be provided.
    :type fullchain_pem: str
    :param cert_pem: the EndEntity or Leaf Certificate.
        If provided:
            * `:param:chain_pem` MUST be provided
            * `:param:fullchain_pem` MUST NOT be provided.
    :type cert_pem: str
    :param chain_pem: A Certificate chain in PEM format, which is multiple
        upstream certs in a single string.
        If provided:
            * `:param:cert_pem` MUST be provided
            * `:param:fullchain_pem` MUST NOT be provided.
    :param root_pems_other: an iterable list of trusted roots certificates, in
       PEM encoding; currently unused.
    :returns: True
    :rtype: bool


    The OpenSSL Equivalent / Fallback is::

    Modern versions of openssl accept multiple `-untrusted` arguments::

        openssl verify -purpose sslserver -CAfile root.pem [[-untrusted intermediate.pem],[-untrusted intermediate.pem],] cert.pem

    However older ones only want to see a single `-untrusted`::

        openssl verify -purpose sslserver -CAfile root.pem -untrusted intermediate.pem cert.pem

    To get around this, put all the intermediates into a single file.

    This is a stopgap solution and needs to be refactored.

    NOTE:
        openssl does not care about the order of intermediates, so this should
        be iteratively built up like the pure-python example
    """
    log.debug(".ensure_chain >")
    if fullchain_pem:
        if chain_pem or cert_pem:
            raise ValueError(
                "If `ensure_chain` is invoked with `fullchain_pem`, do not pass in `chain_pem` or `cert_pem`."
            )
    else:
        if not chain_pem or not cert_pem:
            raise ValueError(
                "If `ensure_chain` is not invoked with `fullchain_pem`, you must pass in `chain_pem` and `cert_pem`."
            )

    if fullchain_pem:
        intermediates = split_pem_chain(fullchain_pem)
        cert_pem = intermediates.pop(0)
    else:
        assert cert_pem
        assert chain_pem
        intermediates = split_pem_chain(chain_pem)
        cert_pem = cert_pem.strip()  # needed to match regex results in above situation

    # sometimes people submit things they should not
    if intermediates[-1] == cert_pem:
        intermediates = intermediates[:-1]

    if openssl_crypto:
        # build a root storage
        store = openssl_crypto.X509Store()
        root_parsed = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, root_pem.encode()
        )
        store.add_cert(root_parsed)

        for _intermediate_pem in reversed(intermediates):
            _intermediate_parsed = openssl_crypto.load_certificate(
                openssl_crypto.FILETYPE_PEM, _intermediate_pem.encode()
            )
            # Check the chain certificate before adding it to the store.
            _store_ctx = openssl_crypto.X509StoreContext(store, _intermediate_parsed)
            _store_ctx.verify_certificate()
            store.add_cert(_intermediate_parsed)

        cert_parsed = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, cert_pem.encode()
        )
        _store_ctx = openssl_crypto.X509StoreContext(store, cert_parsed)
        _store_ctx.verify_certificate()
        return True

    log.debug(".ensure_chain > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    _tempfiles = []
    try:
        _tmpfile_root = new_pem_tempfile(root_pem)
        _tempfiles.append(_tmpfile_root)

        intermediates_unified = "\n".join(intermediates)
        _tempfile_intermediate = new_pem_tempfile(intermediates_unified)
        _tempfiles.append(_tempfile_intermediate)

        _tmpfile_cert = new_pem_tempfile(cert_pem)
        _tempfiles.append(_tmpfile_cert)

        expected_success = "%s: OK\n" % _tmpfile_cert.name
        with psutil.Popen(
            [
                openssl_path,
                "verify",
                "-purpose",
                "sslserver",
                "-CAfile",
                _tmpfile_root.name,
                "-untrusted",
                _tempfile_intermediate.name,
                _tmpfile_cert.name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data, err = proc.communicate()
            if err:
                raise OpenSslError("could not verify: 1")
            data = data.decode("utf8")
            if data != expected_success:
                raise OpenSslError("could not verify: 2")
        return True
    finally:
        for _tmp in _tempfiles:
            _tmp.close()


def ensure_chain_order(
    chain_certs: List[str],
    cert_pem: Optional[str] = None,
) -> bool:
    """
    :param chain_certs: A list of PEM encoded Certificates. Required.
    :type chain_certs: list
    :param cert_pem: A PEM Encoded Certificate to test against the `chain_certs`.
        Optional
    :type cert_pem: str
    :returns: bool
    :rtype: None

    The OpenSSL Equivalent / Fallback is::

        /usr/local/bin/openssl verify -purpose sslserver -partial_chain -trusted {ROOT.pem} {CHAINREVERSED.pem}
    """
    log.debug(".ensure_chain_order >")
    if cert_pem:
        chain_certs.append(cert_pem)
    if len(chain_certs) < 2:
        raise ValueError("must submit 2 or more chain certificates")
    # reverse the cert list
    # we're going to pretend the last item is a root
    r_chain_certs = chain_certs[::-1]
    if openssl_crypto:
        # TODO: openssl crypto does not seem to support partial chains yet
        # as a stopgap, just look to ensure the issuer/subject match
        """
        # build a root storage
        # pretend the first item is a root
        store = openssl_crypto.X509Store()
        root_pem = r_chain_certs.pop(0)
        root_parsed = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, root_pem)
        store.add_cert(root_parsed)

        for (idx, cert_pem) in enumerate(r_chain_certs):
            # Check the chain certificate before adding it to the store.
            try:
                cert_parsed = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, cert_pem)
                _store_ctx = openssl_crypto.X509StoreContext(store, cert_parsed)
                _store_ctx.verify_certificate()
                store.add_cert(cert_parsed)
            except openssl_crypto.X509StoreContextError as exc:
                raise OpenSslError("could not verify: crypto")
        """
        # stash our data in here
        parsed_certs = {}

        # loop the certs
        for idx, cert_pem in enumerate(r_chain_certs):
            # everyone generates data
            cert = openssl_crypto.load_certificate(
                openssl_crypto.FILETYPE_PEM, cert_pem.encode()
            )
            parsed_certs[idx] = cert
            if idx == 0:
                continue
            # only after the first cert do we need to check the last cert
            upchain = parsed_certs[idx - 1]
            if upchain.get_subject() != cert.get_issuer():
                raise OpenSslError("could not verify: upchain does not match issuer")
        return True
    log.debug(".ensure_chain_order > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    _tempfiles = {}
    _last_idx = len(r_chain_certs) - 1
    try:
        # make a bunch of tempfiles
        for _idx, cert_pem in enumerate(r_chain_certs):
            _tmpfile_cert = new_pem_tempfile(cert_pem)
            _tempfiles[_idx] = _tmpfile_cert

        for idx, cert_pem in enumerate(r_chain_certs):
            if idx == _last_idx:
                break
            file_a = _tempfiles[idx]
            file_b = _tempfiles[idx + 1]

            expected_success = "%s: OK\n" % file_b.name
            with psutil.Popen(
                [
                    openssl_path,
                    "verify",
                    "-purpose",
                    "sslserver",
                    "-partial_chain",
                    "-trusted",
                    file_a.name,
                    file_b.name,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                data, err = proc.communicate()
                if err:
                    raise OpenSslError("could not verify: 1")
                data = data.decode("utf8")
                if data != expected_success:
                    raise OpenSslError("could not verify: 2")
        return True
    finally:
        for _idx in _tempfiles:
            _tmp = _tempfiles[_idx]
            _tmp.close()


# ------------------------------------------------------------------------------


def jose_b64(b: bytes) -> str:
    # helper function base64 encode for jose spec
    return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")


class AccountKeyData(object):
    """
    An object encapsulating Account Key data
    """

    key_pem = None
    key_pem_filepath = None  # if used
    jwk = None
    thumbprint = None
    alg = None

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

        (_jwk, _thumbprint, _alg) = account_key__parse(
            key_pem=key_pem,
            key_pem_filepath=key_pem_filepath,
        )
        self.jwk = _jwk
        self.thumbprint = _thumbprint
        self.alg = _alg


def account_key__parse(
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
) -> Tuple[Dict, str, str]:
    """
    :param key_pem: (required) the RSA Key in PEM format
    :param key_pem_filepath: Optional filepath to a PEM encoded RSA account key file.
                             Only used for commandline OpenSSL fallback operations.
    :returns: jwk, thumbprint, alg
    :rtype: list

    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    This includes code from acme-tiny [https://github.com/diafygi/acme-tiny]
    acme-tiny is released under the MIT license and Copyright (c) 2015 Daniel Roesler
    """
    log.info("account_key__parse >")
    alg = "RS256"
    if josepy:
        _jwk = josepy.JWKRSA.load(key_pem.encode("utf8"))
        jwk = _jwk.public_key().fields_to_partial_json()
        jwk["kty"] = "RSA"
        thumbprint = jose_b64(_jwk.thumbprint())
        return jwk, thumbprint, alg
    log.debug(".account_key__parse > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    _tmpfile = None
    try:
        if key_pem_filepath is None:
            _tmpfile = new_pem_tempfile(key_pem)
            key_pem_filepath = _tmpfile.name
        with psutil.Popen(
            [
                openssl_path,
                "rsa",
                "-in",
                key_pem_filepath,
                "-noout",
                "-text",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            data_bytes, err = proc.communicate()
            data_str = data_bytes.decode("utf8")
            assert data_str
        pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
        _matched = re.search(pub_pattern, data_str, re.MULTILINE | re.DOTALL)
        assert _matched
        pub_hex, pub_exp = _matched.groups()
        pub_exp = "{0:x}".format(int(pub_exp))
        pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
        jwk = {
            "e": jose_b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": jose_b64(
                binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))
            ),
        }
        _accountkey_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
        thumbprint = jose_b64(hashlib.sha256(_accountkey_json.encode("utf8")).digest())
        return jwk, thumbprint, alg
    finally:
        if _tmpfile:
            _tmpfile.close()


def account_key__sign(
    data,
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
) -> bytes:
    """
    This routine will use crypto/certbot if available.
    If not, openssl is used via subprocesses

    :param key_pem: (required) the RSA Key in PEM format
    :param key_pem_filepath: Optional filepath to a PEM encoded RSA account key file.
                             Only used for commandline OpenSSL fallback operations.
    :returns: signature
    :rtype: bytes
    """
    log.info("account_key__sign >")
    if not isinstance(data, bytes):
        data = data.encode()
    # cryptography *should* be installed as a dependency of openssl, but who knows!
    if openssl_crypto and crypto_rsa and cryptography:
        pkey: "PKey" = openssl_crypto.load_privatekey(
            openssl_crypto.FILETYPE_PEM, key_pem
        )
        # possible loads are "Union[DSAPrivateKey, DSAPublicKey, RSAPrivateKey, RSAPublicKey]"
        # but only RSAPublicKey is used or will work
        # TODO: check to ensure key type is RSAPublicKey
        signature = pkey.to_cryptography_key().sign(  # type: ignore[union-attr, call-arg]
            data,
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),  # type: ignore[arg-type]
            cryptography.hazmat.primitives.hashes.SHA256(),
        )
        return signature
    log.debug(".account_key__sign > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    _tmpfile = None
    try:
        if key_pem_filepath is None:
            _tmpfile = new_pem_tempfile(key_pem)
            key_pem_filepath = _tmpfile.name
        with psutil.Popen(
            [openssl_path, "dgst", "-sha256", "-sign", key_pem_filepath],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            signature, err = proc.communicate(data)
            if proc.returncode != 0:
                raise IOError("account_key__sign\n{0}".format(err))
            return signature
    finally:
        if _tmpfile:
            _tmpfile.close()


# ------------------------------------------------------------------------------
