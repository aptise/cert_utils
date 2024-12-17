# stdlib
import binascii
import subprocess
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

# pypi
import psutil

# local
from .. import core
from ..errors import FallbackError_FilepathRequired
from ..errors import OpenSslError
from ..errors import OpenSslError_InvalidCertificate
from ..errors import OpenSslError_InvalidCSR
from ..errors import OpenSslError_InvalidKey
from ..errors import OpenSslError_VersionTooLow
from ..utils import new_pem_tempfile

# ==============================================================================


def _cleanup_openssl_modulus(data: str) -> str:
    data = data.strip()
    if data[:8] == "Modulus=":
        data = data[8:]
    return data


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
    # print(core.openssl_version, data)
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
    if core.openssl_version is None:
        core.check_openssl_version()

    _tmpfile_pem = new_pem_tempfile(cert_pem)
    try:
        cert_pem_filepath = _tmpfile_pem.name
        with psutil.Popen(
            [core.openssl_path, "x509", "-in", cert_pem_filepath],
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
    if core.openssl_version is None:
        core.check_openssl_version()

    spki_hash = None
    # convert to DER
    p1 = p2 = p3 = proc4 = None
    try:
        # extract the key
        p1 = psutil.Popen(
            [
                core.openssl_path,
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
                core.openssl_path,
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
                core.openssl_path,
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
                    core.openssl_path,
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
    if core.openssl_version is None:
        core.check_openssl_version()

    spki_hash = None
    # convert to DER
    p1 = p2 = p3 = proc4 = None
    try:
        # extract the key
        p1 = psutil.Popen(
            [
                core.openssl_path,
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
                core.openssl_path,
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
                core.openssl_path,
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
                    core.openssl_path,
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
    if core.openssl_version is None:
        core.check_openssl_version()

    spki_hash = None
    # convert to DER
    p1 = p2 = proc3 = None
    try:
        # convert to DER
        p1 = psutil.Popen(
            [
                core.openssl_path,
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
                core.openssl_path,
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
                    core.openssl_path,
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
    if core.openssl_version is None:
        core.check_openssl_version()

    with psutil.Popen(
        [core.openssl_path, "x509", "-noout", single_op, "-in", pem_filepath],
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
    if core.openssl_version is None:
        core.check_openssl_version()

    with psutil.Popen(
        [core.openssl_path, "x509", "-noout", "-ext", ext, "-in", pem_filepath],
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
    if core.openssl_version is None:
        core.check_openssl_version()

    with psutil.Popen(
        [core.openssl_path, "req", "-noout", single_op, "-in", pem_filepath],
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
    if core.openssl_version is None:
        core.check_openssl_version()

    with psutil.Popen(
        [core.openssl_path, keytype.lower(), "-noout", single_op, "-in", pem_filepath],
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
