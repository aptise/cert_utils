"""The policy snapshot is typed, serializable, and independent of CA bundles."""

import datetime
import json
from pathlib import Path
import subprocess
import sys

from cert_utils.letsencrypt_info.profiles import PROFILES


def test_snapshot_units_and_provenance() -> None:
    assert json.loads(json.dumps(PROFILES)) == PROFILES
    assert PROFILES["profiles"]["shortlived"]["validity_seconds"] == 576000
    assert PROFILES["profiles"]["tlsserver"]["validity_seconds"] == 3888000
    assert PROFILES["profiles"]["shortlived"]["identifier_types"] == ["dns", "ip"]
    assert PROFILES["retired_profiles"]["tlsclient"] == "2026-07-08"
    assert [
        (change["effective_on"], change["validity_seconds"] // 86400)
        for change in PROFILES["announced_validity_changes"]
    ] == [
        ("2027-02-10", 64),
        ("2028-02-16", 45),
    ]
    for source in (PROFILES["source"], PROFILES["validity_changes_source"]):
        datetime.date.fromisoformat(source["document_last_modified"])
        datetime.date.fromisoformat(source["checked_on"])
        assert source["url"].startswith("https://letsencrypt.org/")


def test_lightweight_import_without_certificate_bundle() -> None:
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import cert_utils.letsencrypt_info.profiles; "
            "assert 'cert_utils.letsencrypt_info.certificates' not in sys.modules",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )


def test_source_announcements_match_local_checkout() -> None:
    source = Path(__file__).resolve().parents[2] / "letsencrypt-website"
    if not source.exists():
        return  # A published package does not include the website checkout.
    text = (source / PROFILES["validity_changes_source"]["path"]).read_text()
    assert "February 10, 2027" in text
    assert "February 16, 2028" in text
