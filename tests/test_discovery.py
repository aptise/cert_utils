"""Exercise discovery evidence and filesystem cache invalidation offline."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from cert_utils import utils_discovery
from cert_utils.scripts import cert_info


def lineage(tmp_path: Path) -> Path:
    """Create an isolated Certbot layout with a real certificate fixture."""
    root = tmp_path / "le"
    (root / "renewal").mkdir(parents=True)
    archive = root / "archive" / "example"
    archive.mkdir(parents=True)
    fixture = (
        Path(__file__).parent / "test_data/key_technology-rsa/selfsigned_1-server.crt"
    )
    (archive / "cert1.pem").write_bytes(fixture.read_bytes())
    (root / "renewal/example.conf").write_text(
        "cert = %s\narchive_dir = %s\n[renewalparams]\naccount = account-1\n"
        % (archive / "cert1.pem", archive)
    )
    return root


def test_local_default_does_not_query_ari(tmp_path: Path) -> None:
    """Default inspection never contacts the remote ARI service."""
    root = lineage(tmp_path)
    with patch.object(cert_info, "ari_query") as query:
        cert_info.process_filepath(str(root / "archive/example/cert1.pem"))
    query.assert_not_called()


def test_cache_and_identical_copy(tmp_path: Path, monkeypatch: Any) -> None:
    """Cache hits skip certificate parsing; refresh and changes regenerate data."""
    monkeypatch.setenv("HOME", str(tmp_path))
    root = lineage(tmp_path)
    target = tmp_path / "copy.pem"
    target.write_bytes((root / "archive/example/cert1.pem").read_bytes())
    result = utils_discovery.discover(str(target), root, "exact", 300, False, False)
    assert result[0]["account"] == "account-1"
    assert result[0]["identical_certificate_paths"]
    with patch.object(utils_discovery, "domains", side_effect=AssertionError("cache miss")):
        assert utils_discovery.lineage_index(root, 300, False, False)
    with patch.object(utils_discovery, "domains", wraps=utils_discovery.domains) as parse:
        utils_discovery.lineage_index(root, 300, True, False)
        assert parse.call_count == 1
    cache = next((tmp_path / ".cert_utils").glob("*.json"))
    assert cache.stat().st_mode & 0o777 == 0o600
    configuration = root / "renewal/example.conf"
    configuration.write_text(
        configuration.read_text().replace("account-1", "account-2")
    )
    index = utils_discovery.lineage_index(root, 0, False, False)
    assert index[str(configuration)]["account"] == "account-2"
    certificate = root / "archive/example/cert1.pem"
    certificate.write_bytes(certificate.read_bytes() + b"\n")
    with patch.object(utils_discovery, "domains", wraps=utils_discovery.domains) as parse:
        utils_discovery.lineage_index(root, 0, False, False)
        assert parse.call_count == 1
    configuration.unlink()
    assert utils_discovery.lineage_index(root, 0, False, False) == {}


def test_no_cache_and_context(tmp_path: Path, monkeypatch: Any) -> None:
    """Context alone is inert and bypass mode creates no persistent cache."""
    monkeypatch.setenv("HOME", str(tmp_path))
    root = lineage(tmp_path)
    utils_discovery.lineage_index(root, 300, True, True)
    assert not (tmp_path / ".cert_utils").exists()
    assert (
        utils_discovery.installation_root(
            str(root / "archive/example/cert1.pem"), True, str(root)
        )
        == root
    )
    with pytest.raises(ValueError, match="conflict"):
        utils_discovery.installation_root(
            str(root / "archive/example/cert1.pem"), True, str(tmp_path)
        )


@pytest.mark.parametrize("mode", ["exact", "overlap", "all"])
def test_additive_modes(tmp_path: Path, mode: str) -> None:
    """Every discovery mode preserves exact domain matches."""
    root = lineage(tmp_path)
    results = utils_discovery.discover(
        str(root / "archive/example/cert1.pem"), root, mode, 0, False, True
    )
    assert results[0]["evidence"] == "identical domain set"


def test_overlap_and_key_correlation(tmp_path: Path) -> None:
    """Broader modes add partial-domain and public-key evidence."""
    root = lineage(tmp_path)
    target = root / "archive/example/cert1.pem"
    entry = {"domains": ["another.example", "shared.example"], "account": "account-1"}
    with patch.object(
        utils_discovery,
        "lineage_index",
        return_value={str(root / "renewal/example.conf"): entry},
    ):
        with patch.object(utils_discovery, "domains", return_value=["shared.example"]):
            assert utils_discovery.discover(str(target), root, "exact", 0, False, True) == []
            result = utils_discovery.discover(str(target), root, "overlap", 0, False, True)
            assert result[0]["matching_domains"] == ["shared.example"]
        with patch.object(utils_discovery, "domains", return_value=["unrelated.example"]):
            assert (
                utils_discovery.discover(str(target), root, "overlap", 0, False, True) == []
            )
            assert utils_discovery.discover(str(target), root, "all", 0, False, True)[0][
                "same_public_key"
            ]


def test_cli_cache_precedence(monkeypatch: Any) -> None:
    """Explicit cache arguments override corresponding environment values."""
    monkeypatch.setenv("CERT_INFO_CACHE_TTL", "invalid")
    monkeypatch.setenv("CERT_INFO_REFRESH_CACHE", "invalid")
    monkeypatch.setenv("CERT_INFO_NO_CACHE", "invalid")
    with patch.object(cert_info, "process_filepath"), patch.object(
        utils_discovery, "discover", return_value=[]
    ) as discover:
        cert_info.main(
            [
                "cert_info",
                "cert.pem",
                "--discover-letsencrypt=exact",
                "--cache-ttl=2",
                "--refresh-cache",
                "--no-cache",
            ]
        )
    assert discover.call_args.args[3:] == (2, True, True)
