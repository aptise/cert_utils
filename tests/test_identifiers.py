"""Typed SAN extraction agrees across native and OpenSSL backends."""

import datetime
import ipaddress
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from cert_utils import conditionals
from cert_utils.identifiers import parse_cert_identifiers
from cert_utils.identifiers import parse_csr_identifiers


@pytest.fixture
def mixed_pems() -> Tuple[str, str]:
    """Create public test material with private, public-documentation and IPv6 SANs."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ignored.example.com")]
    )
    sans = x509.SubjectAlternativeName(
        [
            x509.DNSName("EXAMPLE.com"),
            x509.IPAddress(ipaddress.ip_address("10.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("2001:db8::1")),
        ]
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(sans, False)
        .sign(key, hashes.SHA256())
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(sans, False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        csr.public_bytes(serialization.Encoding.PEM).decode(),
    )


@pytest.mark.parametrize("fallback", [False, True])
def test_typed_sans_preserve_ip_kind_and_ignore_non_san_cn(
    mixed_pems: Tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
    fallback: bool,
) -> None:
    if fallback:
        monkeypatch.setattr(conditionals, "cryptography", None)
    expected = [
        {"type": "dns", "value": "example.com"},
        {"type": "ip", "value": "10.0.0.1"},
        {"type": "ip", "value": "2001:db8::1"},
    ]
    assert parse_cert_identifiers(mixed_pems[0]) == expected
    assert parse_csr_identifiers(mixed_pems[1]) == expected


@pytest.mark.parametrize("fallback", [False, True])
def test_ip_looking_dns_san_is_not_reclassified(
    monkeypatch: pytest.MonkeyPatch,
    fallback: bool,
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("192.0.2.1")]), False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    if fallback:
        monkeypatch.setattr(conditionals, "cryptography", None)
    assert parse_csr_identifiers(csr) == [{"type": "dns", "value": "192.0.2.1"}]


@pytest.mark.parametrize("fallback", [False, True])
def test_legacy_cn_fallback_only_when_san_is_absent(
    monkeypatch: pytest.MonkeyPatch, fallback: bool
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.example.com")])
        )
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    if fallback:
        monkeypatch.setattr(conditionals, "cryptography", None)
    assert parse_csr_identifiers(csr) == [
        {"type": "dns", "value": "legacy.example.com"}
    ]


@pytest.mark.parametrize("fallback", [False, True])
def test_non_cn_subject_fields_cannot_supply_a_dns_identity(
    monkeypatch: pytest.MonkeyPatch, fallback: bool
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, "CN=not-a-common-name.example.com"
                    )
                ]
            )
        )
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    if fallback:
        monkeypatch.setattr(conditionals, "cryptography", None)
    assert parse_csr_identifiers(csr) == []
