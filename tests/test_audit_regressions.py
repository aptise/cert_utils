from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.x509.verification import VerificationError
import pytest

from cert_utils import core
from cert_utils.errors import OpenSslError
from cert_utils.errors import OpenSslError_InvalidCSR


def test_verification_success_and_bad_signature():
    key = Path(__file__).parent / "test_data/unit_tests/cert_001/privkey.pem"
    pem = key.read_text()
    signature = core.account_key__sign(b"original", pem)
    core.account_key__verify(signature, b"original", pem)
    with pytest.raises(InvalidSignature):
        core.account_key__verify(signature, b"changed", pem)


def test_invalid_csr_signature_raises():
    class CSR:
        is_signature_valid = False

    assert core.conditionals.cryptography is not None
    with patch.object(
        core.conditionals.cryptography.x509,
        "load_pem_x509_csr",
        return_value=CSR(),
    ):
        with pytest.raises(OpenSslError_InvalidCSR):
            core.validate_csr("unused")


def test_invalid_chain_purpose():
    with pytest.raises(ValueError, match="purpose"):
        core.ensure_chain("unused", purpose="bogus")  # type: ignore[arg-type]


@pytest.mark.parametrize("fallback", [False, True])
def test_chain_rejects_expired_and_wrong_hostname(fallback):
    import datetime

    base = Path(__file__).parent / "test_data/long_chains/TestA"
    root = (base / "root_0.pem").read_text()
    cert = (base / "cert.pem").read_text()
    chain = (base / "chain_0.pem").read_text()
    backend = None if fallback else core.conditionals.cryptography
    expected = OpenSslError if fallback else VerificationError
    with patch.object(core.conditionals, "cryptography", backend):
        with pytest.raises(expected):
            core.ensure_chain(
                root,
                cert_pem=cert,
                chain_pem=chain,
                validation_time=datetime.datetime(
                    2030, 1, 1, tzinfo=datetime.timezone.utc
                ),
            )
        with pytest.raises(expected):
            core.ensure_chain(
                root,
                cert_pem=cert,
                chain_pem=chain,
                validation_time=datetime.datetime(
                    2024, 1, 1, tzinfo=datetime.timezone.utc
                ),
                server_hostname="wrong.example.com",
            )


@pytest.mark.parametrize("fallback", [False, True])
def test_client_purpose_does_not_check_server_hostname(fallback):
    import datetime

    base = Path(__file__).parent / "test_data/long_chains/TestA"
    backend = None if fallback else core.conditionals.cryptography
    with patch.object(core.conditionals, "cryptography", backend):
        assert core.ensure_chain(
            (base / "root_0.pem").read_text(),
            cert_pem=(base / "cert.pem").read_text(),
            chain_pem=(base / "chain_0.pem").read_text(),
            validation_time=datetime.datetime(
                2024, 1, 1, tzinfo=datetime.timezone.utc
            ),
            purpose="sslclient",
            server_hostname="wrong.example.com",
        )
