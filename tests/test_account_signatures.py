"""Cross-backend signature tests: OpenSSL calls always use psutil.Popen."""

from contextlib import contextmanager
from pathlib import Path
from typing import Union
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils
import pytest

from cert_utils import core
from cert_utils.compat.signatures import der_to_raw
from cert_utils.compat.signatures import raw_to_der
from cert_utils.errors import OpenSslError_InvalidKey
from cert_utils.errors import OpenSslError_InvalidSignature


@pytest.fixture(scope="module", params=["rsa", "p256", "p384", "p521"])
def account_key(request):
    key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    if request.param == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        width = None
    else:
        curves = {
            "p256": ec.SECP256R1(),
            "p384": ec.SECP384R1(),
            "p521": ec.SECP521R1(),
        }
        key = ec.generate_private_key(curves[request.param])
        width = (key.key_size + 7) // 8
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return pem, width


@contextmanager
def backend(name):
    if name == "native":
        yield
    elif name == "no_josepy":
        with patch.object(core.conditionals, "josepy", None):
            yield
    else:
        with patch.object(core.conditionals, "cryptography", None):
            with patch.object(core.conditionals, "josepy", None):
                yield


@pytest.mark.parametrize("standardized", [False, True])
@pytest.mark.parametrize("signer", ["native", "openssl", "no_josepy"])
def test_cross_backend_signatures(account_key, standardized, signer, tmp_path):
    pem, width = account_key
    keyfile = tmp_path / "key with spaces.pem"
    keyfile.write_text(pem)
    with backend(signer):
        signature = core.account_key__sign("message", pem, str(keyfile), standardized)
    if width is not None:
        if standardized:
            assert len(signature) == width * 2
        else:
            utils.decode_dss_signature(signature)
    for verifier in ("native", "openssl", "no_josepy"):
        with backend(verifier):
            core.account_key__verify(
                signature, b"message", pem, standardize_signature=standardized
            )
            error = (
                InvalidSignature
                if verifier == "native"
                else OpenSslError_InvalidSignature
            )
            with pytest.raises(error):
                core.account_key__verify(
                    signature, b"changed", pem, str(keyfile), standardized
                )
            if width is not None:
                # Explicit formats are never auto-detected. Wrong raw size is
                # rejected before verification; malformed DER fails in OpenSSL.
                with pytest.raises((ValueError, error)):
                    core.account_key__verify(
                        signature, b"message", pem, str(keyfile), not standardized
                    )


@pytest.mark.parametrize("width", [32, 48, 66])
def test_ec_encoding_zero_padding_and_der_sign_bits(width):
    for r, s in [(1, 128), (128, 1), (0, 0), ((1 << (width * 8 - 1)), 255)]:
        der = utils.encode_dss_signature(r, s)
        raw = r.to_bytes(width, "big") + s.to_bytes(width, "big")
        assert raw_to_der(raw, width) == der
        assert der_to_raw(der, width) == raw
    with pytest.raises(ValueError):
        raw_to_der(b"short", width)
    with pytest.raises(ValueError):
        der_to_raw(der + b"extra", width)


@pytest.mark.parametrize(
    "malformed",
    [
        b"",
        b"\x30\x80\x00\x00",
        b"\x30\x81\x06\x02\x01\x01\x02\x01\x01",
        b"\x30\x06\x02\x01\x80\x02\x01\x01",
        b"\x30\x07\x02\x02\x00\x01\x02\x01\x01",
        b"\x30\x05\x02\x00\x02\x01\x01",
        b"\x30\x06\x02\x01\x01\x02\x02\x01",
    ],
)
def test_malformed_der_rejected(malformed):
    with pytest.raises(ValueError):
        der_to_raw(malformed, 32)


def test_verification_tempfiles_cleanup(account_key):
    pem, _ = account_key
    with backend("openssl"):
        signature = core.account_key__sign(b"message", pem)
        real_popen = core.psutil.Popen
        paths = []

        def tracked(args, **kwargs):
            for flag in ("-in", "-prverify", "-signature"):
                if flag in args:
                    paths.append(Path(args[args.index(flag) + 1]))
            return real_popen(args, **kwargs)

        with patch.object(core.psutil, "Popen", side_effect=tracked):
            core.account_key__verify(signature, b"message", pem)
            with pytest.raises(OpenSslError_InvalidSignature):
                core.account_key__verify(signature, b"wrong", pem)
            with pytest.raises(OpenSslError_InvalidKey):
                core.account_key__verify(signature, b"message", "invalid PEM")
        assert paths
        assert all(not path.exists() for path in paths)


def test_wrong_key_is_rejected(account_key):
    pem, width = account_key
    if width is None:
        wrong_pem = (
            Path(__file__).parent / "test_data/unit_tests/cert_001/privkey.pem"
        ).read_text()
    else:
        curve = {32: ec.SECP256R1(), 48: ec.SECP384R1(), 66: ec.SECP521R1()}[width]
        wrong = ec.generate_private_key(curve)
        wrong_pem = wrong.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
    signature = core.account_key__sign(b"message", pem)
    for name, error in [
        ("native", InvalidSignature),
        ("openssl", OpenSslError_InvalidSignature),
    ]:
        with backend(name):
            with pytest.raises(error):
                core.account_key__verify(signature, b"message", wrong_pem)
