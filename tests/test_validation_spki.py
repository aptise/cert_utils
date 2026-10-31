"""Offline malformed-payload and cross-technology SPKI relationship coverage."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

import cert_utils
from cert_utils import conditionals
from cert_utils.errors import OpenSslError_InvalidCertificate, OpenSslError_InvalidCSR


@pytest.fixture(scope="module")
def objects() -> Dict[str, Dict[str, str]]:
    """Issue small local certificates from existing RSA and EC fixture keys."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    base = Path(__file__).parent / "test_data"
    result: Dict[str, Dict[str, str]] = {}
    for technology, key_file, other_file in (
        (
            "RSA",
            "key_technology-rsa/selfsigned_1-server.key",
            "key_technology-rsa/selfsigned_2-server.key",
        ),
        (
            "EC",
            "key_technology-ec/ec384-1-key.pem",
            "key_technology-ec/ec384-2-key.pem",
        ),
    ):
        pem = (base / key_file).read_text()
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        assert isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey))
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.example")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(name)
            .sign(key, hashes.SHA256())
        )
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(123)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        result[technology] = {
            "key": pem,
            "other": (base / other_file).read_text(),
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
        }
    return result


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("technology", ["RSA", "EC"])
def test_spki_relationships(
    objects: Dict[str, Dict[str, str]],
    technology: str,
    fallback: bool,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """Key, CSR and issued certificate agree; unrelated keys differ on both backends."""
    if fallback:
        monkeypatch.setattr(conditionals, "cryptography", False)
    data = objects[technology]
    digests: Dict[str, str] = {}
    for kind in ("key", "csr", "cert", "other"):
        path = tmp_path / (kind + ".pem")
        path.write_text(data[kind])
        function = getattr(
            cert_utils,
            "parse_" + ("key" if kind == "other" else kind) + "__spki_sha256",
        )
        digests[kind] = function(data[kind], str(path), as_b64=False)
    assert digests["key"] == digests["csr"] == digests["cert"]
    assert digests["other"] != digests["key"]
    parsed = cert_utils.parse_key(data["key"])
    assert parsed["spki_sha256"] == digests["key"]
    if technology == "RSA":
        assert parsed["modulus_md5"] is not None
    else:
        assert parsed["modulus_md5"] is None
    # Compare each backend with the native implementation as well.
    monkeypatch.undo()
    assert digests["key"] == cert_utils.parse_key__spki_sha256(
        data["key"], as_b64=False
    )


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("kind", ["cert", "csr"])
@pytest.mark.parametrize(
    "payload_kind",
    ["empty", "garbage", "invalid-base64", "truncated", "wrong-object", "private-key"],
)
def test_bad_payloads(
    objects: Dict[str, Dict[str, str]],
    fallback: bool,
    kind: str,
    payload_kind: str,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """Malformed and wrong-object PEM inputs must fail rather than validate."""
    if fallback:
        monkeypatch.setattr(conditionals, "cryptography", False)
    data = objects["RSA"]
    label = "CERTIFICATE" if kind == "cert" else "CERTIFICATE REQUEST"
    payload = {
        "empty": "",
        "garbage": "not a PEM object",
        "invalid-base64": "-----BEGIN %s-----\n!invalid!\n-----END %s-----\n"
        % (label, label),
        "truncated": data[kind][: len(data[kind]) // 2],
        "wrong-object": data["csr" if kind == "cert" else "cert"],
        "private-key": data["key"],
    }[payload_kind]
    path = tmp_path / "bad.pem"
    path.write_text(payload)
    error = (
        OpenSslError_InvalidCertificate if kind == "cert" else OpenSslError_InvalidCSR
    )
    with pytest.raises((error, ValueError)):
        getattr(cert_utils, "validate_" + kind)(payload, str(path))


@pytest.mark.parametrize("fallback", [False, True])
def test_invalid_csr_signature(
    objects: Dict[str, Dict[str, str]], fallback: bool, tmp_path: Path, monkeypatch: Any
) -> None:
    """A parseable CSR with an altered signature must fail signature validation."""
    import base64

    pem = objects["RSA"]["csr"]
    der = bytearray(base64.b64decode("".join(pem.splitlines()[1:-1])))
    der[-1] ^= 1
    payload = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + base64.encodebytes(bytes(der)).decode()
        + "-----END CERTIFICATE REQUEST-----\n"
    )
    path = tmp_path / "bad-signature.pem"
    path.write_text(payload)
    if fallback:
        monkeypatch.setattr(conditionals, "cryptography", False)
    with pytest.raises(OpenSslError_InvalidCSR):
        cert_utils.validate_csr(payload, str(path))
