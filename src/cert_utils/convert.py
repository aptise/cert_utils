# stdlib
import base64
import binascii
import json
import logging
import subprocess
import textwrap
from typing import List
from typing import TYPE_CHECKING

# pypi
import psutil

# locals
from . import conditionals
from .core import check_openssl_version
from .core import openssl_path
from .core import openssl_version
from .core import validate_key
from .errors import OpenSslError_InvalidCertificate
from .utils import cleanup_pem_text
from .utils import new_der_tempfile
from .utils import new_pem_tempfile
from .utils import split_pem_chain


# ==============================================================================

log = logging.getLogger("cert_utils")
log.setLevel(logging.INFO)

# ------------------------------------------------------------------------------


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
    if conditionals.cryptography:
        if TYPE_CHECKING:
            assert conditionals.crypto_pkcs7 is not None
            assert conditionals.crypto_serialization is not None
        certs_loaded = conditionals.crypto_pkcs7.load_der_pkcs7_certificates(pkcs7_data)
        certs_bytes = [
            cert.public_bytes(conditionals.crypto_serialization.Encoding.PEM)
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

    if conditionals.cryptography and conditionals.josepy:
        if TYPE_CHECKING:
            assert conditionals.crypto_serialization is not None
        pkey = conditionals.josepy.JWKRSA.json_loads(pkey_jsons)
        as_pem = pkey.key.private_bytes(
            encoding=conditionals.crypto_serialization.Encoding.PEM,
            format=conditionals.crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=conditionals.crypto_serialization.NoEncryption(),
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
