"""Offline integrity checks for the bundled public CA archive."""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from cert_utils.letsencrypt_info import certificates as info

BUNDLE = Path(info.__file__).parents[1] / "letsencrypt-certs"
ALL = dict(info.CERT_CAS_DEPRECATED, **info.CERT_CAS_DATA)


def certificate(key):
    folder = "deprecated" if key in info.CERT_CAS_DEPRECATED else ""
    return x509.load_pem_x509_certificate(
        (BUNDLE / folder / ALL[key]["url_pem"].split("/")[-1]).read_bytes()
    )


@pytest.mark.parametrize("key", list(ALL))
def test_certificate_metadata_and_issuer_signature(key):
    data = ALL[key]
    cert = certificate(key)
    issuer = certificate(data["signed_by"])
    if key == "trustid_root_x3":
        # The high-level verifier rejects legacy SHA-1 signatures on newer
        # Cryptography, but the archived root's signature can still be checked.
        public = issuer.public_key()
        assert isinstance(public, rsa.RSAPublicKey)
        public.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    else:
        cert.verify_directly_issued_by(issuer)
    assert data["is_self_signed"] == (cert.subject == cert.issuer)
    expected = (
        "RSA" if isinstance(cert.public_key(), rsa.RSAPublicKey) else "EC"
    )
    assert data["key_technology"] == expected
    assert data[".enddate"] == cert.not_valid_after_utc.timetuple()[:6]
    fingerprints = data["cert.fingerprints"]
    assert fingerprints is not None
    for name, algorithm in [
        ("sha1", hashes.SHA1()),
        ("sha256", hashes.SHA256()),
    ]:
        assert fingerprints[name] == cert.fingerprint(algorithm).hex().upper()
    alternate = data.get("alternate_of")
    if alternate:
        other = certificate(alternate)
        assert cert.subject == other.subject
        assert cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == other.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert key in (ALL[alternate].get("alternates") or [])


def test_orders_preferences_and_file_inventory():
    assert set(info._CERT_CAS_ORDER) == set(info.CERT_CAS_DATA)
    assert len(info._CERT_CAS_ORDER) == len(info.CERT_CAS_DATA)
    assert set(info._CERT_CAS_DEPRECATED_ORDER) == set(
        info.CERT_CAS_DEPRECATED
    )
    assert len(info._CERT_CAS_DEPRECATED_ORDER) == len(
        info.CERT_CAS_DEPRECATED
    )
    assert not set(info.CERT_CAS_DATA) & set(info.CERT_CAS_DEPRECATED)
    for folder, data in [
        (BUNDLE, info.CERT_CAS_DATA),
        (BUNDLE / "deprecated", info.CERT_CAS_DEPRECATED),
    ]:
        assert {p.name for p in folder.glob("*.pem")} == {
            item["url_pem"].split("/")[-1] for item in data.values()
        }
    assert info.DEFAULT_CA_PREFERENCES == [
        "isrg_root_x2",
        "isrg_root_x1",
        "isrg_root_ye",
        "isrg_root_yr",
    ]
    for key in info.DEFAULT_CA_PREFERENCES:
        assert info.CERT_CAS_DATA[key]["is_self_signed"]
    for key in ("isrg_root_ye", "isrg_root_yr"):
        assert not info.CERT_CAS_DATA[key]["is_trusted_root"]
        assert info.CERT_CAS_DATA[key]["is_untrusted_root"]


def test_current_and_backup_intermediates():
    assert info.CA_LE_INTERMEDIATES == [
        "ye1",
        "ye2",
        "yr1",
        "yr2",
        "ye3",
        "yr3",
    ]
    assert info.CA_LE_INTERMEDIATES_CROSSED == []
    for key in info.CA_LE_INTERMEDIATES:
        data = info.CERT_CAS_DATA[key]
        assert data["is_active"] == (key not in ("ye3", "yr3"))
        assert bool(data.get("is_backup")) == (key in ("ye3", "yr3"))
        assert certificate(key).not_valid_after_utc > datetime.datetime(
            2026, 10, 28, tzinfo=datetime.timezone.utc
        )
    for data in info.CERT_CAS_DEPRECATED.values():
        assert not data["is_active"]
        assert data["is_retired"]


def test_cross_sign_renewal_preserves_old_certificate():
    old = certificate("isrg_root_x2_cross")
    renewed = certificate("isrg_root_x2_cross_2025")
    assert old.fingerprint(hashes.SHA256()) != renewed.fingerprint(
        hashes.SHA256()
    )
    assert old.not_valid_after_utc < renewed.not_valid_after_utc


def test_official_archive_fingerprint_manifest():
    import json

    manifest = json.loads(
        (
            Path(__file__).parent
            / "test_data"
            / "letsencrypt_bundle_manifest.json"
        ).read_text()
    )
    assert set(manifest) == set(ALL)
    for key, expected in manifest.items():
        assert (
            ALL[key]["url_pem"]
            == "https://letsencrypt.org/certs/" + expected["source"]
        )
        assert (
            certificate(key).fingerprint(hashes.SHA256()).hex().upper()
            == expected["sha256"]
        )
