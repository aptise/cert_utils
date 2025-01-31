# stdlib
import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

# pypi
from dateutil import parser as dateutil_parser
import psutil
from typing_extensions import Literal

# localapp
from . import conditionals
from .compat.cryptography import _cryptography__cert_or_req__all_names
from .compat.cryptography import _cryptography__public_key_spki_sha256
from .compat.cryptography import _cryptography__public_key_technology
from .compat.cryptography import _format_cryptography_components
from .compat.cryptography import cryptography__cert_and_chain_from_fullchain
from .compat.openssl import _cert_pubkey_technology__text
from .compat.openssl import _cleanup_openssl_modulus
from .compat.openssl import _csr_pubkey_technology__text
from .compat.openssl import _format_openssl_components
from .compat.openssl import _openssl_cert__normalize_pem
from .compat.openssl import _openssl_cert_single_op__pem_filepath
from .compat.openssl import _openssl_spki_hash_cert
from .compat.openssl import _openssl_spki_hash_csr
from .compat.openssl import _openssl_spki_hash_pkey
from .compat.openssl import authority_key_identifier_from_text
from .compat.openssl import cert_ext__pem_filepath
from .compat.openssl import csr_single_op__pem_filepath
from .compat.openssl import issuer_uri_from_text
from .compat.openssl import key_single_op__pem_filepath
from .compat.openssl import RE_openssl_x509_subject
from .compat.openssl import san_domains_from_text
from .compat.openssl import serial_from_text
from .errors import CryptographyError
from .errors import FallbackError_FilepathRequired
from .errors import OpenSslError
from .errors import OpenSslError_CsrGeneration
from .errors import OpenSslError_InvalidCertificate
from .errors import OpenSslError_InvalidCSR
from .errors import OpenSslError_InvalidKey
from .errors import OpenSslError_VersionTooLow
from .model import ALLOWED_BITS_RSA
from .model import ALLOWED_CURVES_ECDSA
from .model import KeyTechnology
from .model import KeyTechnologyEnum
from .utils import cleanup_pem_text
from .utils import convert_binary_to_hex
from .utils import curve_to_nist
from .utils import jose_b64
from .utils import new_pem_tempfile
from .utils import split_pem_chain
from .utils import TECHNOLOGY_RETURN_VALUES

# from .utils import new_der_tempfile

# ==============================================================================

if TYPE_CHECKING:
    import datetime
    from cryptography.x509 import Certificate
    from cryptography.x509 import CertificateSigningRequest
    from cryptography.hazmat.primitives.hashes import HashAlgorithm
    from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

    _TYPES_CRYPTOGRAPHY_KEYS = Union[
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
        RSAPrivateKey,
        RSAPublicKey,
    ]
    _TYPES_CRYPTOGRAPHY_PRIVATEKEY = Union[
        EllipticCurvePrivateKey,
        RSAPrivateKey,
    ]
    _TYPES_CRYPTOGRAPHY_PUBLICKEY = Union[
        EllipticCurvePublicKey,
        RSAPublicKey,
    ]
    _TYPES_CRYPTOGRAPHY_PUBLICKEY_EXTENDED = Union[
        DSAPublicKey,
        EllipticCurvePublicKey,
        Ed25519PublicKey,
        Ed448PublicKey,
        RSAPublicKey,
        X25519PublicKey,
        X448PublicKey,
    ]


# ------------------------------------------------------------------------------

NEEDS_TEMPFILES = True
if conditionals.cryptography and conditionals.josepy:
    NEEDS_TEMPFILES = False

# ==============================================================================

log = logging.getLogger("cert_utils")
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
openssl_version: Optional[List[int]] = None
_RE_openssl_version = re.compile(r"OpenSSL ((\d+\.\d+\.\d+)\w*) ", re.I)
_openssl_behavior: Optional[str] = None  # 'a' or 'b'


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


# ==============================================================================


def make_csr(
    domain_names: Optional[List[str]] = None,
    key_pem: Optional[str] = None,
    key_pem_filepath: Optional[str] = None,
    ipaddrs: Optional[List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]] = None,
    must_staple: bool = False,
    max_domains: int = MAX_DOMAINS_PER_CERTIFICATE,
) -> str:
    """
    This routine will use cryptography if available.
    If not, openssl is used via subprocesses

    :param domain_names: a list of fully qualified domain names
    :type domain_names: list of strings
    :param key_pem: a PEM encoded PrivateKey
    :type key_pem: str
    :param key_pem_filepath: Optional filepath to the PEM encoded PrivateKey.
                             Only used for commandline OpenSSL fallback operations.
    :type key_pem_filepath: str
    :param ipaddrs: a list of ip addresses
    :type ipaddrs: list of strings
    :param bool must_staple: Whether to include the TLS Feature extension (aka
        OCSP Must Staple: https://tools.ietf.org/html/rfc7633).

    :param int max_domains: the max domains to put on a certificate;
        defaults to package max

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

    if domain_names is None:
        domain_names = []
    if ipaddrs is None:
        ipaddrs = []
    if len(domain_names) + len(ipaddrs) == 0:
        raise OpenSslError_CsrGeneration(
            "At least one of domains or ipaddrs parameter need to be not empty"
        )
    elif len(domain_names) + len(ipaddrs) > max_domains:
        raise OpenSslError_CsrGeneration(
            "LetsEncrypt can only allow `%s` domains per certificate"
        )

    # first try with python
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_dsa is not None
            assert conditionals.crypto_ec is not None
            assert conditionals.crypto_ed25519 is not None
            assert conditionals.crypto_ed448 is not None
            assert conditionals.crypto_hashes is not None
            assert conditionals.crypto_rsa is not None
            assert conditionals.crypto_serialization is not None

        if not key_pem:
            raise ValueError("Must submit `key_pem`")

        private_key = conditionals.crypto_serialization.load_pem_private_key(
            key_pem.encode(), password=None
        )

        if not isinstance(
            private_key,
            (
                conditionals.crypto_dsa.DSAPrivateKey,
                conditionals.crypto_ec.EllipticCurvePrivateKey,
                conditionals.crypto_ed25519.Ed25519PrivateKey,
                conditionals.crypto_ed448.Ed448PrivateKey,
                conditionals.crypto_rsa.RSAPrivateKey,
            ),
        ):
            raise ValueError(f"Invalid private key type: {type(private_key)}")

        builder = (
            conditionals.cryptography.x509.CertificateSigningRequestBuilder()
            .subject_name(conditionals.cryptography.x509.Name([]))
            .add_extension(
                conditionals.cryptography.x509.SubjectAlternativeName(
                    [conditionals.cryptography.x509.DNSName(d) for d in domain_names]
                    + [conditionals.cryptography.x509.IPAddress(i) for i in ipaddrs]
                ),
                critical=False,
            )
        )
        if must_staple:
            builder = builder.add_extension(
                conditionals.cryptography.x509.TLSFeature(
                    [conditionals.cryptography.x509.TLSFeatureType.status_request]
                ),
                critical=False,
            )

        csr = builder.sign(private_key, conditionals.crypto_hashes.SHA256())
        pem_bytes = csr.public_bytes(conditionals.crypto_serialization.Encoding.PEM)
        return pem_bytes.decode()

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

    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        cert = conditionals.cryptography.x509.load_pem_x509_certificate(
            cert_pem.encode()
        )
        return _cryptography__cert_or_req__all_names(cert)

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

    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        csr = conditionals.cryptography.x509.load_pem_x509_csr(csr_pem.encode())
        found_domains = _cryptography__cert_or_req__all_names(csr)
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
) -> Optional[TECHNOLOGY_RETURN_VALUES]:
    """
    raises an Exception if invalid
    returns the key_technology if valid

    This routine will use cryptography if available.
    If not, openssl is used via subprocesses

    This may have issues on older openssl systems

    :param key_pem: a PEM encoded PrivateKey
    :type key_pem: str
    :param key_pem_filepath: Optional filepath to the PEM encoded PrivateKey.
                             Only used for commandline OpenSSL fallback operations.
    :type key_pem_filepath: str
    :returns: If the key is valid, it will return a Tuple wherein
        - The first element is the Key's technology (EC, RSA)
        - The second element is a Tuple with the key's type.
            (RSA, (bits, ))
            (EC, (curve_name, ))

      If the key is not valid, an exception will be raised.
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        openssl EC -in {FILEPATH}
        openssl RSA -in {FILEPATH}

    CHANGED
        prior to v1.0.0, this only returned the key's technology (EC, RSA)

    """
    log.info("validate_key >")
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_serialization is not None
            assert conditionals.crypto_rsa is not None
            assert conditionals.crypto_ec is not None
        try:
            key = conditionals.crypto_serialization.load_pem_private_key(
                key_pem.encode(), None
            )
            if isinstance(key, conditionals.crypto_rsa.RSAPrivateKey):
                return ("RSA", (key.key_size,))
            elif isinstance(key, conditionals.crypto_ec.EllipticCurvePrivateKey):
                curve_name = curve_to_nist(key.curve.name)
                return ("EC", (curve_name,))
            return None
        except Exception as exc:
            raise OpenSslError_InvalidKey(exc)
    log.debug(".validate_key > openssl fallback")
    if not key_pem_filepath:
        # TODO: generate a tempfile if needed?
        raise FallbackError_FilepathRequired("Must submit `key_pem_filepath`.")
    if openssl_version is None:
        check_openssl_version()

    def _check_fallback(_technology: Literal["rsa", "ec"]):
        log.debug(".validate_key > openssl fallback: _check_fallback[%s]", _technology)
        # openssl rsa -in {KEY} -check
        try:
            with psutil.Popen(
                [openssl_path, _technology, "-in", key_pem_filepath, "-noout", "-text"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                data_bytes, err = proc.communicate()
                if not data_bytes:
                    raise OpenSslError_InvalidKey(err)
                data_str = data_bytes.decode("utf8")

                if _technology == "rsa":
                    _rsa_pattern = r"Private-Key:\s+\((\d+) bit, 2 primes\)\s"
                    _matched = re.search(
                        _rsa_pattern, data_str, re.MULTILINE | re.DOTALL
                    )
                    if _matched:
                        _bits = int(_matched.groups()[0])
                        return _bits
                    raise OpenSslError_InvalidKey("trouble parsing")
                elif _technology == "ec":
                    _ec_pattern_a = r"ANS1 OID:\s+([\w]+)\s"
                    _matched = re.search(
                        _ec_pattern_a, data_str, re.MULTILINE | re.DOTALL
                    )
                    if _matched:
                        _curve = _matched.groups()[0]
                        return _curve
                    _ec_pattern_b = r"NIST CURVE:\s+(P\-[\d]+)\s"
                    _matched = re.search(
                        _ec_pattern_b, data_str, re.MULTILINE | re.DOTALL
                    )
                    if _matched:
                        _curve = _matched.groups()[0]
                        return _curve
                    raise OpenSslError_InvalidKey("trouble parsing")

        except OpenSslError_InvalidKey as exc:  # noqa: F841
            return None

    _rsa_bits = _check_fallback("rsa")
    if _rsa_bits:
        return ("RSA", (_rsa_bits,))
    _ec_curve = _check_fallback("ec")
    if _ec_curve:
        return ("EC", (_ec_curve,))

    raise OpenSslError_InvalidKey()


def validate_csr(
    csr_pem: str,
    csr_pem_filepath: Optional[str] = None,
) -> bool:
    """
    raises an error if invalid

    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        csr = conditionals.cryptography.x509.load_pem_x509_csr(csr_pem.encode())
        return csr.is_signature_valid

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

    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        try:
            cert = conditionals.cryptography.x509.load_pem_x509_certificate(
                cert_pem.encode()
            )
        except Exception as exc:
            raise OpenSslError_InvalidCertificate(exc)
        if not cert:
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

    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_hashes is not None
        try:
            cert = conditionals.cryptography.x509.load_pem_x509_certificate(
                cert_pem.encode()
            )
        except Exception as exc:
            raise OpenSslError_InvalidCertificate(exc)
        if not cert:
            raise OpenSslError_InvalidCertificate()
        _hash: "HashAlgorithm"
        if algorithm == "sha1":
            _hash = conditionals.crypto_hashes.SHA1()
        elif algorithm == "sha256":
            _hash = conditionals.crypto_hashes.SHA256()
        elif algorithm == "md5":
            _hash = conditionals.crypto_hashes.MD5()
        _fingerprint_bytes = cert.fingerprint(_hash)
        fingerprint = _fingerprint_bytes.hex().upper()
        return fingerprint

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


def modulus_md5_key(
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
) -> Optional[str]:
    """
    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_rsa is not None
            assert conditionals.crypto_serialization is not None
        privkey = conditionals.crypto_serialization.load_pem_private_key(
            key_pem.encode(), password=None
        )
        if isinstance(privkey, conditionals.crypto_rsa.RSAPrivateKey):
            modn = privkey.public_key().public_numbers().n  # type: ignore[union-attr]
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
    This routine will use cryptography if available.
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
    # TODO: Support EC Key Modulus Variant - https://github.com/aptise/cert_utils/issues/15
    # ???: Should this raise an Exception instead of returning `None`?
    log.info("modulus_md5_csr >")
    if conditionals.cryptography:
        csr = conditionals.cryptography.x509.load_pem_x509_csr(csr_pem.encode())
        _pubkey = csr.public_key()
        _keytype = _cryptography__public_key_technology(_pubkey)
        assert _keytype
        _keytype_basic = _keytype[0]
        if _keytype_basic == "RSA":
            modn = _pubkey.public_numbers().n  # type: ignore[union-attr]
            data_str = "{:X}".format(modn)
        elif _keytype_basic == "EC":
            return None
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
    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        cert = conditionals.cryptography.x509.load_pem_x509_certificate(
            cert_pem.encode()
        )
        _pubkey = cert.public_key()
        _keytype = _cryptography__public_key_technology(_pubkey)
        assert _keytype
        _keytype_basic = _keytype[0]
        if _keytype_basic == "RSA":
            modn = _pubkey.public_numbers().n  # type: ignore[union-attr]
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


def parse_cert__enddate(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> "datetime.datetime":
    """
    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        cert = conditionals.cryptography.x509.load_pem_x509_certificate(
            cert_pem.encode()
        )
        date = cert.not_valid_after_utc
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
        # date = date.replace(tzinfo=None)
    return date


def parse_cert__startdate(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> "datetime.datetime":
    """
    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        cert = conditionals.cryptography.x509.load_pem_x509_certificate(
            cert_pem.encode()
        )
        date = cert.not_valid_before_utc
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
        # date = date.replace(tzinfo=None)
    return date


def parse_cert__spki_sha256(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
    cryptography_cert: Optional["Certificate"] = None,
    key_technology_basic: Optional[str] = None,
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param str cert_pem: PEM encoded Certificate
    :param str cert_pem_filepath: Optional filepath to PEM encoded Certificate.
                                  Only used for commandline OpenSSL fallback operations.
    :param cryptography_cert: optional hint to aid in crypto commands
    :type cryptography_cert: `OpenSSL.crypto.load_certificate(...).to_cryptography()``
    :param str key_technology_basic: optional hint to aid in openssl fallback
    :param bool as_b64: encode with b64?
    :returns: spki sha256
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        :function :_openssl_spki_hash_cert
    """
    log.info("parse_cert__spki_sha256 >")
    if conditionals.cryptography:
        if not cryptography_cert:
            cryptography_cert = (
                conditionals.cryptography.x509.load_pem_x509_certificate(
                    cert_pem.encode()
                )
            )
        assert cryptography_cert is not None  # nest under `if TYPE_CHECKING` not needed
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
        if key_technology_basic is None:
            key_technology = parse_cert__key_technology(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            if not key_technology:
                raise ValueError("Could not parse key_technology for backup")
            key_technology_basic = key_technology[0]
        spki_sha256 = _openssl_spki_hash_cert(
            key_technology_basic=key_technology_basic,
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
) -> Optional[TECHNOLOGY_RETURN_VALUES]:
    """
    :param cert_pem: PEM encoded Certificate
    :type cert_pem: str
    :param cert_pem_filepath: Optional filepath to PEM encoded Certificate.
                              Only used for commandline OpenSSL fallback operations.
    :type cert_pem_filepath: str
    :returns: key technology type
    :rtype: TECHNOLOGY_RETURN_VALUES

    The OpenSSL Equivalent / Fallback is::
    Regex the output of::

        openssl x509 -in {FILEPATH} -noout -text
    """
    log.info("parse_cert__key_technology >")
    if conditionals.cryptography:
        cert = conditionals.cryptography.x509.load_pem_x509_certificate(
            cert_pem.encode()
        )
        publickey = cert.public_key()
        return _cryptography__public_key_technology(publickey)
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
    This routine will use cryptography if available.
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
    rval: Dict[
        str,
        Union[None, str, int, "datetime.datetime", List[str], TECHNOLOGY_RETURN_VALUES],
    ] = {
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
        "serial": None,
    }

    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_hashes is not None
        cert = conditionals.cryptography.x509.load_pem_x509_certificate(
            cert_pem.encode()
        )
        publickey = cert.public_key()
        rval["issuer"] = _format_cryptography_components(cert.issuer)
        rval["subject"] = _format_cryptography_components(cert.subject)
        rval["enddate"] = cert.not_valid_after_utc
        rval["startdate"] = cert.not_valid_before_utc
        rval["key_technology"] = _cryptography__public_key_technology(publickey)
        _fingerprint_bytes = cert.fingerprint(conditionals.crypto_hashes.SHA1())
        rval["fingerprint_sha1"] = _fingerprint_bytes.hex().upper()
        rval["spki_sha256"] = parse_cert__spki_sha256(
            cert_pem=cert_pem,
            cert_pem_filepath=cert_pem_filepath,
            cryptography_cert=cert,
            as_b64=False,
        )
        rval["serial"] = cert.serial_number
        try:
            ext = cert.extensions.get_extension_for_oid(
                conditionals.cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            if ext:
                _names: List[str] = ext.value.get_values_for_type(conditionals.cryptography.x509.DNSName)  # type: ignore[attr-defined]
                rval["SubjectAlternativeName"] = sorted(_names)
        except conditionals.cryptography.x509.ExtensionNotFound as exc:  # noqa: F841
            pass
        try:
            ext = cert.extensions.get_extension_for_oid(
                conditionals.cryptography.x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            )
            if ext:
                # this comes out as binary, so we need to convert it to the
                # openssl version, which is an list of uppercase hex pairs
                _as_binary = ext.value.key_identifier  # type: ignore[attr-defined]
                rval["authority_key_identifier"] = convert_binary_to_hex(_as_binary)
        except conditionals.cryptography.x509.ExtensionNotFound as exc:  # noqa: F841
            pass
        try:
            ext = cert.extensions.get_extension_for_oid(
                conditionals.cryptography.x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            )
            if ext:
                # this comes out as binary, so we need to convert it to the
                # openssl version, which is an list of uppercase hex pairs
                _as_binary = ext.value.key_identifier  # type: ignore[attr-defined]
                rval["authority_key_identifier"] = convert_binary_to_hex(_as_binary)
        except conditionals.cryptography.x509.ExtensionNotFound as exc:  # noqa: F841
            pass
        try:
            ext = cert.extensions.get_extension_for_oid(
                conditionals.cryptography.x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            if ext:
                for _item in ext.value:  # type: ignore[attr-defined]
                    if not isinstance(
                        _item,
                        conditionals.cryptography.x509.extensions.AccessDescription,
                    ):
                        continue
                    # _item.access_method is either:
                    # * cryptography.x509.oid.AuthorityInformationAccessOID.OCSP
                    # * cryptography.x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
                    # we only care about CA_ISSUERS
                    if (
                        _item.access_method
                        == conditionals.cryptography.x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
                    ):
                        if isinstance(
                            _item.access_location,
                            conditionals.cryptography.x509.UniformResourceIdentifier,
                        ):
                            rval["issuer_uri"] = _item.access_location.value
        except conditionals.cryptography.x509.ExtensionNotFound as exc:  # noqa: F841
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
        if _key_technology:
            rval["spki_sha256"] = parse_cert__spki_sha256(
                cert_pem=cert_pem,
                cert_pem_filepath=cert_pem_filepath,
                key_technology_basic=_key_technology[0],
                as_b64=False,
            )
        try:
            _text = cert_ext__pem_filepath(cert_pem_filepath, "serial")
            serial_no = serial_from_text(_text)
            rval["serial"] = serial_no
        except Exception as exc:  # noqa: F841
            pass

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
    csr: Optional["CertificateSigningRequest"] = None,
) -> Optional[TECHNOLOGY_RETURN_VALUES]:
    """
    :param csr_pem: PEM encoded CSR
    :type csr_pem: str
    :param csr_pem_filepath: Optional filepath to PEM encoded CSR.
                             Only used for commandline OpenSSL fallback operations.
    :type csr_pem_filepath: str
    :param _csr: cryptography CSR object
    :type csr: `cryptography.x509.CertificateSigningRequest`
    :returns: key technology type
    :rtype: str or None

    The OpenSSL Equivalent / Fallback is::
    Regex the output of::

        openssl req -in {FILEPATH} -noout -text
    """
    log.info("parse_csr__key_technology >")
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.EllipticCurvePublicKey is not None
            assert conditionals.RSAPublicKey is not None
        if not csr:
            csr = conditionals.cryptography.x509.load_pem_x509_csr(csr_pem.encode())
        assert csr is not None  # nest under `if TYPE_CHECKING` not needed
        csr_pubkey = csr.public_key()
        assert isinstance(
            csr_pubkey, conditionals.EllipticCurvePublicKey
        ) or isinstance(csr_pubkey, conditionals.RSAPublicKey)
        return _cryptography__public_key_technology(csr_pubkey)
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
    csr: Optional["CertificateSigningRequest"] = None,
    key_technology_basic: Optional[str] = None,
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param str csr_pem: CSR in PEM encoding
    :param str csr_pem_filepath: Optional filepath to PEM encoded CSR.
                                 Only used for commandline OpenSSL fallback operations.
    :param object csr: optional hint to aid in crypto commands
    :param str key_technology_basic: optional hint to aid in openssl fallback
    :param bool as_b64: encode with b64?
    :returns: spki sha256
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        :_see:_openssl_spki_hash_csr
    """
    log.info("parse_csr__spki_sha256 >")
    if conditionals.cryptography:
        if not csr:
            csr = conditionals.cryptography.x509.load_pem_x509_csr(csr_pem.encode())
        assert csr is not None  # nest under `if TYPE_CHECKING` not needed
        publickey = csr.public_key()
        spki_sha256 = _cryptography__public_key_spki_sha256(publickey, as_b64=as_b64)
        return spki_sha256
    log.debug(".parse_csr__spki_sha256 > openssl fallback")
    if not csr_pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `csr_pem_filepath`.")
    tmpfile_pem = None
    try:
        if key_technology_basic is None:
            _key_technology = parse_csr__key_technology(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            if not _key_technology:
                raise ValueError("Could not parse key_technology for backup")
            key_technology_basic = _key_technology[0]
        spki_sha256 = _openssl_spki_hash_csr(
            key_technology_basic=key_technology_basic,
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
    This routine will use cryptography if available.
    If not, openssl is used via subprocesses

    :param str csr_pem: CSR in PEM encoding
    :param str csr_pem_filepath: Optional filepath to PEM encoded CSR.
                                 Only used for commandline OpenSSL fallback operations.
    :returns: dict of select CSR data
    :rtype: dict
    """
    log.info("parse_csr >")
    rval: Dict[str, Union[None, List, str, TECHNOLOGY_RETURN_VALUES]] = {
        "key_technology": None,
        "spki_sha256": None,
        "SubjectAlternativeName": [],
        "subject": None,
    }

    if conditionals.cryptography:
        csr = conditionals.cryptography.x509.load_pem_x509_csr(csr_pem.encode())
        # _subject = csr.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)
        # _subject[0].value
        rval["subject"] = csr.subject.rfc4514_string() if csr.subject else ""
        try:
            ext = csr.extensions.get_extension_for_oid(
                conditionals.cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            if ext:
                _names = ext.value.get_values_for_type(conditionals.cryptography.x509.DNSName)  # type: ignore[attr-defined]
                rval["SubjectAlternativeName"] = sorted(_names)
        except Exception as exc:  # noqa: F841
            pass
        rval["key_technology"] = _cryptography__public_key_technology(csr.public_key())
        rval["spki_sha256"] = parse_csr__spki_sha256(
            csr_pem=csr_pem,
            csr_pem_filepath=csr_pem_filepath,
            csr=csr,
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
        if _key_technology:
            rval["spki_sha256"] = parse_csr__spki_sha256(
                csr_pem=csr_pem,
                csr_pem_filepath=csr_pem_filepath,
                key_technology_basic=_key_technology[0],
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
    publickey: Optional["_TYPES_CRYPTOGRAPHY_KEYS"] = None,
    key_technology_basic: Optional[str] = None,
    as_b64: Optional[bool] = None,
) -> str:
    """
    :param str key_pem: Key in PEM form
    :param str key_pem_filepath: Optional filepath to PEM.
                                 Only used for commandline OpenSSL fallback operations.
    :param cryptography_publickey: optional hint to aid in crypto commands
    :type cryptography_publickey: cryptography.hazmat.backends.openssl.rsa._RSAPublicKey
        openssl_crypto.load_privatekey(...).to_cryptography_key().public_key()
    :param str key_technology_basic: optional hint to aid in openssl fallback
    :param bool as_b64: encode with b64?
    :returns: spki sha256
    :rtype: str

    The OpenSSL Equivalent / Fallback is::

        :_see:_openssl_spki_hash_pkey
    """
    log.info("parse_key__spki_sha256 >")
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_serialization is not None
        if not publickey:
            privkey = conditionals.crypto_serialization.load_pem_private_key(
                key_pem.encode(), password=None
            )
            publickey = privkey.public_key()  # type: ignore[union-attr]
        assert publickey is not None  # nest under `if TYPE_CHECKING` not needed
        spki_sha256 = _cryptography__public_key_spki_sha256(publickey, as_b64=as_b64)
        return spki_sha256
    log.debug(".parse_key__spki_sha256 > openssl fallback")
    if not key_pem_filepath:
        raise FallbackError_FilepathRequired("Must submit `key_pem_filepath`.")
    tmpfile_pem = None
    try:
        if key_technology_basic is None:
            key_technology_basic = parse_key__technology_basic(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
        spki_sha256 = _openssl_spki_hash_pkey(
            key_technology_basic=key_technology_basic,
            key_pem_filepath=key_pem_filepath,
            as_b64=as_b64,
        )
        return spki_sha256
    except Exception as exc:  # noqa: F841
        raise
    finally:
        if tmpfile_pem:
            tmpfile_pem.close()


def parse_key__technology_basic(
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
    privatekey: Optional["_TYPES_CRYPTOGRAPHY_PRIVATEKEY"] = None,
) -> Literal["EC", "RSA"]:
    """
    :param str key_pem: Key in PEM form
    :param str key_pem_filepath: Optional filepath to PEM.
                                 Only used for commandline OpenSSL fallback operations.
    :param object privatekey: optional private key
    :returns: key technology
    :rtype: str
    """
    log.info("parse_key__technology_basic >")
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_ec is not None
            assert conditionals.crypto_rsa is not None
            assert conditionals.crypto_serialization is not None
        if not privatekey:
            privatekey = conditionals.crypto_serialization.load_pem_private_key(
                key_pem.encode(), None
            )
        assert privatekey is not None  # nest under `if TYPE_CHECKING` not needed
        if isinstance(privatekey, conditionals.crypto_rsa.RSAPrivateKey):
            # return ("RSA", (privatekey.key_size,))
            return "RSA"
        elif isinstance(privatekey, conditionals.crypto_ec.EllipticCurvePrivateKey):
            # curve_name = curve_to_nist(privatekey.curve.name)
            # return ("EC", (curve_name,))
            return "EC"
        raise OpenSslError_InvalidKey("I don't know what kind of key this is")
    log.debug(".parse_key__technology_basic > openssl fallback")
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
                # TODO - parse curve
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

    This routine will use cryptography if available.
    If not, openssl is used via subprocesses

    :param str key_pem: Key in PEM encoding
    :param str key_pem_filepath: Optional filepath to PEM encoded Key.
                                 Only used for commandline OpenSSL fallback operations.
    :returns: dict of select CSR data
    :rtype: dict
    """
    log.info("parse_key >")
    rval: Dict[str, Union[None, str, Tuple]] = {
        "key_technology": None,
        "text": None,
        "modulus_md5": None,
        "key_technology_basic": None,
        "spki_sha256": None,
    }
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_ec is not None
            assert conditionals.crypto_rsa is not None
            assert conditionals.crypto_serialization is not None
        try:
            # note: we don't need to provide key_pem_filepath because we already rely on openssl
            rval["key_technology"] = validate_key(key_pem=key_pem)
        except Exception as exc:
            rval["key_technology"] = str(exc)
        privkey = conditionals.crypto_serialization.load_pem_private_key(
            key_pem.encode(), password=None
        )
        publickey = privkey.public_key()  # type: ignore[union-attr]
        if isinstance(privkey, conditionals.crypto_rsa.RSAPrivateKey):
            rval["key_technology_basic"] = "RSA"
            try:
                modn = publickey.public_numbers().n  # type: ignore[union-attr]
                modn = "{:X}".format(modn)
                modn = modn.encode()
                rval["modulus_md5"] = hashlib.md5(modn).hexdigest()
            except Exception as exc:
                rval["XX-modulus_md5"] = str(exc)
        elif isinstance(privkey, conditionals.crypto_ec.EllipticCurvePrivateKey):
            rval["key_technology_basic"] = "EC"
            # TODO: Support EC Key Modulus Variant - https://github.com/aptise/cert_utils/issues/15
            # legacy ONLY works on RSA keys
            # might just rely on spki_sha256
            # related certbot/pyopenssl ticket:
            # see https://github.com/pyca/pyopenssl/issues/291

        rval["spki_sha256"] = parse_key__spki_sha256(
            key_pem="",
            key_pem_filepath=None,
            publickey=publickey,
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
            rval["key_technology_basic"] = _key_technology_basic = (
                parse_key__technology_basic(
                    key_pem=key_pem, key_pem_filepath=key_pem_filepath
                )
            )
        except OpenSslError_VersionTooLow as exc2:  # noqa: F841
            # TODO: make this conditional
            # i doubt many people have old versions but who knows?
            raise
        try:
            # rval["check"] = key_single_op__pem_filepath(
            #    _key_technology_basic, key_pem_filepath, "-check"
            # )
            rval["key_technology"] = validate_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
        except Exception as exc1:
            rval["XX-check"] = str(exc1)
        rval["text"] = key_single_op__pem_filepath(
            _key_technology_basic, key_pem_filepath, "-text"
        )
        if _key_technology_basic in ("RSA", "EC"):
            # rval["spki_sha256"] = _openssl_spki_hash_pkey(key_technology=_key_technology, key_pem_filepath=key_pem_filepath, as_b64=False)
            rval["spki_sha256"] = parse_key__spki_sha256(
                key_pem=key_pem,
                key_pem_filepath=key_pem_filepath,
                key_technology_basic=_key_technology_basic,
                as_b64=False,
            )

        if _key_technology_basic == "RSA":
            _modulus = key_single_op__pem_filepath(
                _key_technology_basic, key_pem_filepath, "-modulus"
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
    key_technology_id: Literal[
        KeyTechnologyEnum.RSA, KeyTechnologyEnum.EC
    ] = KeyTechnologyEnum.RSA,
    rsa_bits: Optional[Literal[2048, 3072, 4096]] = 2048,
    ec_curve: Optional[Literal["P-256", "P-384"]] = "P-256",
) -> str:
    """
    :param int key_technology_id: Key Technology type. Default: KeyTechnology.RSA
    :param int rsa_bits: number of bits. default 2048
    :param istrnt ec_curve: default "P-256"
    :returns: AccountKey in PEM format
    :rtype: str
    """
    if key_technology_id in (KeyTechnologyEnum.RSA, KeyTechnology.RSA):
        if rsa_bits not in ALLOWED_BITS_RSA:
            raise ValueError(
                "LetsEncrypt only supports RSA keys with bits: %s" % ALLOWED_BITS_RSA
            )
        return new_key_rsa(bits=rsa_bits)
    elif key_technology_id in (KeyTechnologyEnum.EC, KeyTechnology.EC):
        if ec_curve not in ALLOWED_CURVES_ECDSA:
            raise ValueError(
                "LetsEncrypt only supports EC with curves: %s" % ALLOWED_CURVES_ECDSA
            )
        return new_key_ec(curve=ec_curve)
    else:
        raise ValueError("invalid `key_technology_id`")


def new_private_key(
    key_technology_id: Literal[KeyTechnologyEnum.RSA, KeyTechnologyEnum.EC],
    rsa_bits: Optional[Union[Literal[2048], Literal[3072], Literal[4096]]] = 2048,
    ec_curve: Optional[Union[Literal["P-256"], Literal["P-384"]]] = "P-384",
) -> str:
    """
    :param int key_technology_id: Key Technology type. Default: None
    :param int rsa_bits: number of bits. default None
    :param str ec_curve: ec curve. default P-256
    :returns: PrivateKey in PEM format
    :rtype: str
    """
    if key_technology_id in (KeyTechnologyEnum.RSA, KeyTechnology.RSA):
        kwargs_rsa = {"bits": rsa_bits} if rsa_bits else {}
        return new_key_rsa(**kwargs_rsa)
    elif key_technology_id in (KeyTechnologyEnum.EC, KeyTechnology.EC):
        kwargs_ec = {"curve": ec_curve} if ec_curve else {}
        return new_key_ec(**kwargs_ec)
    else:
        raise ValueError("invalid `key_technology_id`")


def new_key_ec(
    curve: Union[Literal["P-256"], Literal["P-384"]] = "P-256",
) -> str:
    """
    This routine will use cryptography if available.
    If not, openssl is used via subprocesses

    :param str curve: Which EC curve to use
    :returns: ECDSA Key in PEM format
    :rtype: str
    """
    log.info("new_key_ec >")
    log.debug(".new_key_ec > curve = %s", curve)
    if curve not in ALLOWED_CURVES_ECDSA:
        raise ValueError(
            "LetsEncrypt only supports ECDSA keys with curves: %s; not %s"
            % (ALLOWED_CURVES_ECDSA, curve)
        )

    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_ec is not None
            assert conditionals.crypto_serialization is not None
        # see https://github.com/pyca/pyopenssl/issues/291
        if curve == "P-256":
            key = conditionals.crypto_ec.generate_private_key(
                conditionals.crypto_ec.SECP256R1()
            )
        elif curve == "P-384":
            key = conditionals.crypto_ec.generate_private_key(
                conditionals.crypto_ec.SECP384R1()
            )
        key_pem = key.private_bytes(
            encoding=conditionals.crypto_serialization.Encoding.PEM,
            format=conditionals.crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=conditionals.crypto_serialization.NoEncryption(),
        )
        # load it: openssl_crypto.load_privatekey(openssl_crypto.FILETYPE_PEM, key_pem)
        key_pem_str = key_pem.decode("utf8")
        key_pem_str = cleanup_pem_text(key_pem_str)
        return key_pem_str

    log.debug(".new_key_ec > openssl fallback")
    # openssl ecparam -list_curves
    _openssl_curve: str
    if curve == "P-256":
        _openssl_curve = "secp256r1"
    elif curve == "P-384":
        _openssl_curve = "secp384r1"
    else:
        raise ValueError("invalid curve")
    # openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
    # -noout will suppress printing the EC Param (see https://security.stackexchange.com/questions/29778/why-does-openssl-writes-ec-parameters-when-generating-private-key)
    if openssl_version is None:
        check_openssl_version()

    with psutil.Popen(
        [openssl_path, "ecparam", "-name", _openssl_curve, "-genkey", "-noout"],
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


def new_key_rsa(
    bits: Union[Literal[2048], Literal[3072], Literal[4096]] = 4096,
) -> str:
    """
    This routine will use cryptography if available.
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
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_rsa is not None
            assert conditionals.crypto_serialization is not None
        key_rsa = conditionals.crypto_rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
        )
        key_pem = key_rsa.private_bytes(
            encoding=conditionals.crypto_serialization.Encoding.PEM,
            format=conditionals.crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=conditionals.crypto_serialization.NoEncryption(),
        )
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


def cert_and_chain_from_fullchain(
    fullchain_pem: str,
) -> Tuple[str, str]:
    """
    Split `fullchain_pem` into `cert_pem` and `chain_pem`

    :param str fullchain_pem: concatenated Certificate + Chain
    :returns: tuple of two PEM encoded Certificates in the format of
        (LeafCertificate, ChainedIntermediates)
    :rtype: tuple

    This routine will use cryptography if available.
    If not, openssl is used via subprocesses

    Portions of this are a reimplentation of certbot's code
    Certbot's code is Apache2 licensed
    https://raw.githubusercontent.com/certbot/certbot/master/LICENSE.txt
    """
    log.info("cert_and_chain_from_fullchain >")
    if conditionals.cryptography:
        try:
            return cryptography__cert_and_chain_from_fullchain(fullchain_pem)
        except Exception as exc:
            raise
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
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_serialization is not None
        certs_normalized = []
        for cert_pem in certs:
            cert = conditionals.cryptography.x509.load_pem_x509_certificate(
                cert_pem.encode()
            )
            cert_pem = cert.public_bytes(
                conditionals.crypto_serialization.Encoding.PEM
            ).decode()
            certs_normalized.append(cert_pem)
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
    log.info("ensure_chain >")
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

    if conditionals.cryptography:
        # build a root storage
        root_cert = conditionals.cryptography.x509.load_pem_x509_certificate(
            root_pem.encode()
        )
        store = conditionals.cryptography.x509.verification.Store(
            certs=[
                root_cert,
            ]
        )

        intermediate_certs = []
        for _intermediate_pem in reversed(intermediates):
            _intermediate_cert = (
                conditionals.cryptography.x509.load_pem_x509_certificate(
                    _intermediate_pem.encode()
                )
            )
            intermediate_certs.append(_intermediate_cert)

        cert_cert = conditionals.cryptography.x509.load_pem_x509_certificate(
            cert_pem.encode()
        )
        builder = conditionals.cryptography.x509.verification.PolicyBuilder().store(
            store
        )

        try:
            builder.build_client_verifier().verify(cert_cert, intermediate_certs)
        except Exception as exc:  # noqa: F841
            raise
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
    log.debug("ensure_chain_order >")
    if cert_pem:
        chain_certs.append(cert_pem)
    if len(chain_certs) < 2:
        raise ValueError("must submit 2 or more chain certificates")
    # reverse the cert list
    # we're going to pretend the last item is a root
    r_chain_certs = chain_certs[::-1]
    if conditionals.cryptography:
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
            cert = conditionals.cryptography.x509.load_pem_x509_certificate(
                cert_pem.encode()
            )
            parsed_certs[idx] = cert
            if idx == 0:
                continue
            # only after the first cert do we need to check the last cert
            upchain = parsed_certs[idx - 1]
            if upchain.subject != cert.issuer:
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

    This routine will use cryptography if available.
    If not, openssl is used via subprocesses

    This includes code from acme-tiny [https://github.com/diafygi/acme-tiny]
    acme-tiny is released under the MIT license and Copyright (c) 2015 Daniel Roesler
    """
    log.info("account_key__parse >")
    _key_technology_basic = parse_key__technology_basic(
        key_pem=key_pem, key_pem_filepath=key_pem_filepath
    )
    if _key_technology_basic == "RSA":
        alg = "RS256"
    elif _key_technology_basic == "EC":
        alg = "ES256"
    else:
        raise ValueError("invalid key_technology")
    if conditionals.josepy:
        if _key_technology_basic == "RSA":
            _jwk = conditionals.josepy.JWKRSA.load(key_pem.encode("utf8"))
            jwk = _jwk.public_key().fields_to_partial_json()
            jwk["kty"] = "RSA"
        elif _key_technology_basic == "EC":
            _jwk = conditionals.josepy.JWKEC.load(key_pem.encode("utf8"))
            jwk = _jwk.public_key().fields_to_partial_json()
            jwk["kty"] = "EC"
            """
            jwk will be something like:
                {'crv': 'P-256',
                 'x': '...',
                 'y': '...'}
            # is this needed?
            if jwk["crv"] == "P-256":
                alg = "ES256"
            elif jwk["crv"] == "P-384":
                alg = "ES384"
            else:
                raise ValueError("unknown curve")
            """

        thumbprint = jose_b64(_jwk.thumbprint())
        return jwk, thumbprint, alg
    log.debug(".account_key__parse > openssl fallback")
    if openssl_version is None:
        check_openssl_version()

    _tmpfile = None
    try:
        if _key_technology_basic == "RSA":
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
        elif _key_technology_basic == "EC":
            if key_pem_filepath is None:
                _tmpfile = new_pem_tempfile(key_pem)
                key_pem_filepath = _tmpfile.name
            with psutil.Popen(
                [
                    openssl_path,
                    "ec",
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
            # keys generated by account_key__new don't have the NIST embedded?
            pub_pattern = r"pub:[\s]+?([a-f0-9\:\s]+?)\nASN1 OID:[\s]+([\w\-]+)\n(?:NIST CURVE:[\s]+([\w\-]+)\n)?"
            _matched = re.search(pub_pattern, data_str, re.MULTILINE | re.DOTALL)
            assert _matched
            pub_hex, ans1, nist = _matched.groups()
            pub_hex = "".join([i.strip() for i in pub_hex.split("\n")])
            if nist is None:
                if ans1.lower() == "secp256r1":
                    nist = "P-256"
                elif ans1.lower() == "secp384r1":
                    nist = "P-384"
            if nist == "P-256":
                alg = "EC256"
            elif nist == "P-384":
                alg = "EC384"
            else:
                raise ValueError("unknown curve")
            _pub_hex = pub_hex.replace(":", "")
            # this is a compressed key and we should never see it in this context
            assert len(_pub_hex) > 66
            # Uncompressed key
            x = int(_pub_hex[:64], 16)
            y = int(_pub_hex[64:], 16)
            jwk = {
                "kty": "EC",
                "crv": nist,
                "x": x,
                "y": y,
            }
            _accountkey_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
        else:
            raise ValueError("invalid key_technology")
        thumbprint = jose_b64(hashlib.sha256(_accountkey_json.encode("utf8")).digest())
        return jwk, thumbprint, alg
    finally:
        if _tmpfile:
            _tmpfile.close()


def account_key__sign(
    data,
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
    standardize_signature: Optional[bool] = True,
) -> bytes:
    """
    This routine will use cryptography if available.
    If not, openssl is used via subprocesses

    :param key_pem: (required) the RSA Key in PEM format
    :param key_pem_filepath: Optional filepath to a PEM encoded RSA account key file.
                             Only used for commandline OpenSSL fallback operations.
    :standardize_signature: Bool. Default `True`.  Will reformat signatures if needed
    :returns: signature
    :rtype: bytes
    """
    log.info("account_key__sign >")
    if not isinstance(data, bytes):
        data = data.encode()
    if conditionals.cryptography and conditionals.josepy:
        if TYPE_CHECKING:
            assert conditionals.crypto_ec is not None
            assert conditionals.crypto_hashes is not None
            assert conditionals.crypto_rsa is not None
            assert conditionals.crypto_serialization is not None
            assert conditionals.crypto_utils is not None
        pkey = conditionals.crypto_serialization.load_pem_private_key(
            key_pem.encode(), None
        )
        # possible loads are "Union[DSAPrivateKey, DSAPublicKey, RSAPrivateKey, RSAPublicKey]"
        # but only RSAPublicKey is used or will work
        # TODO: check to ensure key type is RSAPublicKey

        if isinstance(pkey, conditionals.crypto_ec.EllipticCurvePrivateKey):
            signature = pkey.sign(  # type: ignore[union-attr, call-arg]
                data,
                conditionals.crypto_ec.ECDSA(conditionals.crypto_hashes.SHA256()),
            )
            if standardize_signature:
                # https://community.letsencrypt.org/t/debugging-pebble-ec-account-keys/231109/3
                dr, ds = conditionals.crypto_utils.decode_dss_signature(signature)
                length = conditionals.josepy.jwk.JWKEC.expected_length_for_curve(
                    pkey.curve
                )
                signature = dr.to_bytes(length=length, byteorder="big") + ds.to_bytes(
                    length=length, byteorder="big"
                )
        elif isinstance(pkey, conditionals.crypto_rsa.RSAPrivateKey):
            signature = pkey.sign(  # type: ignore[union-attr, call-arg]
                data,
                conditionals.cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),  # type: ignore[arg-type]
                conditionals.crypto_hashes.SHA256(),
            )
        else:
            raise ValueError("unsupported private key type")
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


def account_key__verify(
    signature,
    data,
    key_pem: str,
    key_pem_filepath: Optional[str] = None,
    standardize_signature: Optional[bool] = True,
) -> bytes:
    """
    This routine will use cryptography if available.
    If not, openssl is used via subprocesses

    :param key_pem: (required) the RSA Key in PEM format
    :param key_pem_filepath: Optional filepath to a PEM encoded RSA account key file.
                             Only used for commandline OpenSSL fallback operations.
    :param standardize_signature: bool. Default `True`. Was the signature standardized?
    :returns: result
    :rtype: bool
    """
    log.info("account_key__verify >")
    if not isinstance(signature, bytes):
        signature = signature.encode()
    if not isinstance(data, bytes):
        data = data.encode()
    if conditionals.cryptography and conditionals.josepy:
        if TYPE_CHECKING:
            assert conditionals.crypto_ec is not None
            assert conditionals.crypto_hashes is not None
            assert conditionals.crypto_rsa is not None
            assert conditionals.crypto_serialization is not None
            assert conditionals.crypto_utils is not None
        pkey = conditionals.crypto_serialization.load_pem_private_key(
            key_pem.encode(), None
        )
        if isinstance(pkey, conditionals.crypto_ec.EllipticCurvePrivateKey):
            if standardize_signature:
                # https://community.letsencrypt.org/t/debugging-pebble-ec-account-keys/231109/3
                # https://github.com/certbot/josepy/blob/2731969a8460a3ae0dcbcdc65be772385eb4a89e/src/josepy/jwa.py#L168
                rlen = conditionals.josepy.jwk.JWKEC.expected_length_for_curve(
                    pkey.curve
                )
                if len(signature) != 2 * rlen:
                    # Format error - rfc7518 - 3.4 | MUST NOT be shortened to omit any leading zero octets
                    raise ValueError("invalid signature")
                asn1sig = conditionals.crypto_utils.encode_dss_signature(
                    int.from_bytes(signature[0:rlen], byteorder="big"),
                    int.from_bytes(signature[rlen:], byteorder="big"),
                )
                signature = asn1sig
            result = pkey.public_key().verify(
                signature,
                data,
                conditionals.crypto_ec.ECDSA(conditionals.crypto_hashes.SHA256()),
            )
        elif isinstance(pkey, conditionals.crypto_rsa.RSAPrivateKey):
            result = pkey.public_key().verify(
                signature,
                data,
                conditionals.cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),  # type: ignore[arg-type]
                conditionals.crypto_hashes.SHA256(),
            )
        else:
            raise ValueError("unsupported private key type")
        return result
    log.debug(".account_key__verify > openssl fallback")
    raise ValueError("not supported yet")


def ari__encode_serial_no(serial_no: int) -> str:
    # we need one more byte when aligend due to sign padding
    _serial_url = serial_no.to_bytes((serial_no.bit_length() + 8) // 8, "big")
    serial_url = base64.urlsafe_b64encode(_serial_url).decode("ascii").replace("=", "")
    return serial_url


def ari_construct_identifier(
    cert_pem: str,
    cert_pem_filepath: Optional[str] = None,
) -> str:
    """
    construct an ARI key identifier

    This is quite a PAIN.

    All the relevant info is in the Certificate itself, but requires extended
    parsing as Python libraries overparse or underparse the relevant data
    structures.

    In a first ARI client draft to Certbot, a LetsEncrypt engineer constructs
    an OSCP request to make this data more acessible:
    https://github.com/certbot/certbot/pull/9102/files

    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import ocsp
    import josepy as jose

     def get_renewal_info(self, cert: jose.ComparableX509, issuer: jose.ComparableX509) -> messages.RenewalInfoResource:
            '''Fetch ACME Renewal Information for certificate.
            :param .ComparableX509 cert: The cert whose renewal info should be fetched.
            :param .ComparableX509 issuer: The intermediate which issued the above cert,
                which will be used to uniquely identify the cert in the ARI request.
            '''
            # Rather than compute the serial, issuer key hash, and issuer name hash
            # ourselves, we instead build an OCSP Request and extract those fields.
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer, hashes.SHA1())
            ocspRequest = builder.build()

            # Construct the ARI path from the OCSP CertID sequence.
            key_hash = ocspRequest.issuer_key_hash.hex()
            name_hash = ocspRequest.issuer_name_hash.hex()
            serial = hex(ocspRequest.serial_number)[2:]
            path = f"{key_hash}/{name_hash}/{serial}"

            return self.net.get(self.directory['renewalInfo'].rstrip('/') + '/' + path)
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    I want to avoid the OCSP generation in this routine, because that requires
    having the Intermediate - and that is really out-of-scope for the purposes
    of this function.

    I came up with the same approach as @orangepizza in this Certbot PR:
        https://github.com/certbot/certbot/pull/9945

    Originally I had parsed the data out using `asn1`, but I didn't want to have
    that dependency, so I implemented @orangepizza's idea of discarding the first
    4 bytes, as they are guaranteed to be the tag.

    LetsEncrypt engineer @aarongable doesn't think that is safe enough, and
    believes the data should be fully parsed.

    As a temporary compromise until I weighed options better, I implemented a
    PREFERNCE to utilize asn1 decoding if the package is installed, with a
    FALLBACK to just discarding the first 4 bits if it is not available.

    After implementing that, I realized the underlying issue was using the
    openssl certificate object - which is quite kludgy.  I migrated the function
    to use the cryptography package's Certificate object, which offers a much
    cleaner and more reliable way to extract this data.
    """
    log.info("ari_construct_identifier >")

    if conditionals.cryptography:
        try:
            cert = conditionals.cryptography.x509.load_pem_x509_certificate(
                cert_pem.encode()
            )
        except Exception as exc:
            raise CryptographyError(exc)

        akid = None
        try:
            ext = cert.extensions.get_extension_for_oid(
                conditionals.cryptography.x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            )
            akid = ext.value.key_identifier
        except Exception as exc:
            log.debug("Exception", exc)
        if not akid:
            raise ValueError("akid: not found")

        akid_url = base64.urlsafe_b64encode(akid).decode("ascii").replace("=", "")

        serial_no = cert.serial_number
        if not isinstance(serial_no, int):
            raise ValueError("serial: expected integer")
        serial_url = ari__encode_serial_no(serial_no)

        return f"{akid_url}.{serial_url}"

    log.debug(".ari_construct_identifier > openssl fallback")

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

            data_str = data_bytes.decode()
            akid = authority_key_identifier_from_text(data_str)
            if not akid:
                raise ValueError("akid: not found")
            serial_no = serial_from_text(data_str)
            if not serial_no:
                raise ValueError("serial: not found")

            akid_url = (
                base64.urlsafe_b64encode(bytes.fromhex(akid))
                .decode("ascii")
                .replace("=", "")
            )

            serial_url = ari__encode_serial_no(serial_no)

            return f"{akid_url}.{serial_url}"

    finally:
        if _tmpfile_cert:
            _tmpfile_cert.close()


# ------------------------------------------------------------------------------
