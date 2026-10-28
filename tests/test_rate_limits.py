import json
import subprocess
import sys

import pytest

from cert_utils.letsencrypt_info.rate_limits import LIMITS
from cert_utils.letsencrypt_info.rate_limits import RATE_LIMITS


def test_serialization_and_lightweight_import():
    assert json.loads(json.dumps(RATE_LIMITS)) == RATE_LIMITS
    assert LIMITS is RATE_LIMITS
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import cert_utils.letsencrypt_info.rate_limits; "
            "assert 'cert_utils.letsencrypt_info.certificates' "
            "not in sys.modules",
        ],
        check=True,
        capture_output=True,
    )
    assert result.returncode == 0
    from cert_utils.letsencrypt_info.rate_limits import LIMITS as old_location

    assert old_location is RATE_LIMITS
    assert RATE_LIMITS["schema_version"] == 2
    assert RATE_LIMITS["policy_environment"] == "production"


@pytest.mark.parametrize(
    "key,capacity,interval",
    [
        ("registrations_per_ip", 10, 1080),
        ("registrations_per_ipv6_range", 500, 22),
        ("orders_per_account", 300, 36),
        ("certificates_per_registered_domain", 50, 12120),
        ("certificates_per_exact_identifier_set", 5, 122400),
        ("authorization_failures_per_identifier_account", 5, 720),
        ("consecutive_authorization_failures", 1152, 86400),
    ],
)
def test_documented_capacities_and_refills(key, capacity, interval):
    limit = RATE_LIMITS["limits"][key]
    assert limit["capacity"] == capacity
    assert limit["refill"]["period_seconds"] == interval
    assert limit["refill"]["tokens"] == 1
    assert limit["source_url"].startswith(RATE_LIMITS["source"]["url"])


def test_rounded_refills_are_not_relabelled_as_exact():
    for limit in RATE_LIMITS["limits"].values():
        if limit["refill"]["precision"] == "published_rounded":
            window = limit["nominal_window_seconds"]
            assert window is not None
            assert (
                limit["refill"]["period_seconds"] * limit["capacity"] >= window
            )
    domain = RATE_LIMITS["limits"]["certificates_per_registered_domain"]
    assert domain["scope"]["dimensions"] == ["registered_domain_or_ip_range"]
    assert domain["scope"]["key_rules"]["ipv6"] == "/64 network"
    registrations = RATE_LIMITS["limits"]["registrations_per_ipv6_range"]
    assert registrations["scope"]["dimensions"] == ["source_ipv6_48"]


def test_renewals_and_failure_guard_are_distinct_policies():
    exempt = {
        key
        for key, value in RATE_LIMITS["limits"].items()
        if value["renewal_exemptions"]["same_identifier_set"] == "exempt"
    }
    assert exempt == {
        "orders_per_account",
        "certificates_per_registered_domain",
    }
    assert (
        set(RATE_LIMITS["renewals"]["same_identifier_set"]["exempt_limit_ids"])
        == exempt
    )
    guard = RATE_LIMITS["limits"]["consecutive_authorization_failures"]
    assert guard["kind"] == "consecutive_failure_guard"
    assert guard["reset_on"] == "authorization_succeeded"
    assert guard["nominal_window_seconds"] is None
    assert guard["exhaustion_action"] == "identifier_issuance_paused"
    assert "renewal_exemption" in RATE_LIMITS["endpoint_matching"]


@pytest.mark.parametrize(
    "path,rate,burst",
    [
        ("/acme/new-nonce", 20, 10),
        ("/acme/new-account", 5, 15),
        ("/acme/new-order", 300, 200),
        ("/acme/revoke-cert", 10, 100),
        ("/acme/renewal-info", 1000, 100),
        ("/acme/*", 250, 125),
        ("/directory", 40, 40),
    ],
)
def test_endpoint_rates_and_bursts(path, rate, burst):
    record = RATE_LIMITS["endpoints"][path]
    assert record["capacity"] == burst
    assert record["refill"]["tokens"] == rate
    assert record["refill"]["period_seconds"] == 1
    assert record["exhaustion_http_status"] == 503
    assert record["retry_after_header"]


def test_size_constraints_are_not_rate_limits():
    assert "pending_authorizations/account" not in LIMITS
    assert "names/certificate" not in LIMITS
    constraint = RATE_LIMITS["constraints"]["identifiers_per_certificate"]
    assert constraint["maximum_by_profile"] == {
        "classic": 100,
        "tlsserver": 25,
        "shortlived": 25,
    }


def test_namespace_does_not_eagerly_load_datasets():
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import cert_utils.letsencrypt_info; "
            "assert 'cert_utils.letsencrypt_info.certificates' "
            "not in sys.modules; "
            "assert 'cert_utils.letsencrypt_info.rate_limits' "
            "not in sys.modules",
        ],
        check=True,
        capture_output=True,
    )
