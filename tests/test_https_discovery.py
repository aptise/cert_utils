"""Exercise HTTPS-to-local discovery without making network requests."""

from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from cert_utils.scripts import cert_info
from cert_utils import utils_discovery


@pytest.mark.parametrize("mode", ["exact", "overlap", "all"])
def test_https_discovery(tmp_path: Path, capsys: Any, mode: str) -> None:
    """Match the actual fetched PEM to a lineage and print usable PEM lines."""
    root = tmp_path / "le"
    (root / "renewal").mkdir(parents=True)
    archive = root / "archive" / "example"
    archive.mkdir(parents=True)
    source = (
        Path(__file__).parent / "test_data/key_technology-rsa/selfsigned_1-server.crt"
    )
    pem = cert_utils_pem(source)
    certificate = archive / "cert1.pem"
    certificate.write_text(pem)
    (root / "renewal/example.conf").write_text(
        "cert = %s\narchive_dir = %s\n[renewalparams]\naccount = account-live\n"
        % (certificate, archive)
    )
    session = Mock()
    session.get.return_value._sock_data = {"cert_pem": pem, "cert_dict": {}}
    with patch.object(cert_info, "new_session", return_value=session), patch.object(
        cert_info, "ari_query"
    ) as ari:
        cert_info.main(
            [
                "cert_info",
                "https://example.com",
                "--discover-certbot=" + mode,
                "--certbot-config-directory",
                str(root),
                "--no-cache",
            ]
        )
    output = capsys.readouterr().out
    assert pem in output
    assert "ALERT: byte-identical certificate" in output
    assert "account-live" in output
    assert str(certificate) in output
    ari.assert_not_called()
    session.get.assert_called_once_with("https://example.com")
    session.close.assert_called_once_with()


def cert_utils_pem(path: Path) -> str:
    """Normalize fixture bytes like the HTTPS peer conversion."""
    import ssl
    import cert_utils

    return cert_utils.convert_der_to_pem(ssl.PEM_cert_to_DER_cert(path.read_text()))


def test_missing_peer_fails_discovery() -> None:
    """Unavailable peer data cannot silently produce an empty discovery result."""
    session = Mock()
    session.get.return_value._sock_data = None
    with patch.object(cert_info, "new_session", return_value=session), patch.object(
        utils_discovery, "discover"
    ) as discover:
        with pytest.raises(ValueError, match="peer certificate unavailable"):
            cert_info.main(
                [
                    "cert_info",
                    "https://example.com",
                    "--discover-certbot",
                    "--no-cache",
                ]
            )
    discover.assert_not_called()
    session.close.assert_called_once_with()
