"""Versioned public production policy snapshot, not a live quota counter.

Values are JSON-compatible. See docs/rate-limits.md for modelling decisions,
rounded refill figures, exemption boundaries and migration from schema 1.
Importing this module does not load the bundled CA certificates.
"""

# local
from .types import Catalogue

RATE_LIMITS: Catalogue = {
    "schema_version": 2,
    "policy_environment": "production",
    "source": {
        "url": "https://letsencrypt.org/docs/rate-limits/",
        "document_last_modified": "2026-08-05",
        "checked_on": "2026-10-28",
        "checkout": "bb7e7238",
        "path": "content/en/docs/rate-limits.md",
    },
    "limits": {
        "registrations_per_ip": {
            "kind": "token_bucket",
            "title": "New Registrations per IP Address",
            "capacity": 10,
            "unit": "account",
            "scope": {
                "dimensions": ["source_ip"],
                "key_rules": {"source_ip": "exact IPv4 " "or IPv6 " "address"},
            },
            "nominal_window_seconds": 10800,
            "refill": {
                "tokens": 1,
                "period_seconds": 1080,
                "precision": "published",
            },
            "cost_per_event": 1,
            "counted_event": "account_created",
            "enforced_on": "new_account",
            "renewal_exemptions": {
                "ari_replacement": "not_applicable",
                "same_identifier_set": "not_applicable",
            },
            "override_scopes": [],
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#new-regi"
                "strations-per-ip-address"
            ),
        },
        "registrations_per_ipv6_range": {
            "kind": "token_bucket",
            "title": "New Registrations per IPv6 " "Range",
            "capacity": 500,
            "unit": "account",
            "scope": {
                "dimensions": ["source_ipv6_48"],
                "key_rules": {
                    "source_ipv6_48": "IPv6 "
                    "address "
                    "masked "
                    "to "
                    "/48; "
                    "additional "
                    "to "
                    "per-IP "
                    "quota"
                },
            },
            "nominal_window_seconds": 10800,
            "refill": {
                "tokens": 1,
                "period_seconds": 22,
                "precision": "published_rounded",
            },
            "cost_per_event": 1,
            "counted_event": "account_created",
            "enforced_on": "new_account",
            "renewal_exemptions": {
                "ari_replacement": "not_applicable",
                "same_identifier_set": "not_applicable",
            },
            "override_scopes": [],
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#new-regi"
                "strations-per-ipv6-range"
            ),
        },
        "orders_per_account": {
            "kind": "token_bucket",
            "title": "New Orders per Account",
            "capacity": 300,
            "unit": "order",
            "scope": {"dimensions": ["account"], "key_rules": {}},
            "nominal_window_seconds": 10800,
            "refill": {
                "tokens": 1,
                "period_seconds": 36,
                "precision": "published",
            },
            "cost_per_event": 1,
            "counted_event": "order_created",
            "enforced_on": "new_order",
            "renewal_exemptions": {
                "ari_replacement": "documented_exempt",
                "same_identifier_set": "exempt",
            },
            "override_scopes": ["account"],
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#new-orde"
                "rs-per-account"
            ),
        },
        "certificates_per_registered_domain": {
            "kind": "token_bucket",
            "title": "New Certificates per " "Registered Domain",
            "capacity": 50,
            "unit": "certificate",
            "scope": {
                "dimensions": ["registered_domain_or_ip_range"],
                "key_rules": {
                    "dns": "Public "
                    "Suffix "
                    "List "
                    "registered "
                    "domain; "
                    "not "
                    "simply "
                    "the "
                    "last "
                    "two "
                    "labels",
                    "ipv4": "exact " "address",
                    "ipv6": "/64 " "network",
                    "sharing": "global " "across " "accounts",
                    "multi_identifier": "evaluate "
                    "each "
                    "distinct "
                    "registered-domain/IP-range "
                    "bucket",
                },
            },
            "nominal_window_seconds": 604800,
            "refill": {
                "tokens": 1,
                "period_seconds": 12120,
                "precision": "published_rounded",
            },
            "cost_per_event": 1,
            "counted_event": "certificate_issued",
            "enforced_on": "new_order",
            "renewal_exemptions": {
                "ari_replacement": "documented_exempt",
                "same_identifier_set": "exempt",
            },
            "override_scopes": ["registered_domain", "account"],
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#new-cert"
                "ificates-per-registered-domain"
            ),
        },
        "certificates_per_exact_identifier_set": {
            "kind": "token_bucket",
            "title": "New Certificates per " "Exact Set of " "Identifiers",
            "capacity": 5,
            "unit": "certificate",
            "scope": {
                "dimensions": ["identifier_set"],
                "key_rules": {
                    "normalization": "case-insensitive "
                    "and "
                    "order-independent "
                    "identifiers",
                    "sharing": "global " "across " "accounts",
                    "ip_canonicalization": "not "
                    "specified "
                    "by "
                    "this "
                    "source; "
                    "do "
                    "not "
                    "infer "
                    "string "
                    "equivalence "
                    "rules",
                },
            },
            "nominal_window_seconds": 604800,
            "refill": {
                "tokens": 1,
                "period_seconds": 122400,
                "precision": "published_rounded",
            },
            "cost_per_event": 1,
            "counted_event": "certificate_issued",
            "enforced_on": "new_order",
            "renewal_exemptions": {
                "ari_replacement": "documented_exempt",
                "same_identifier_set": "not_exempt",
            },
            "override_scopes": [],
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#new-cert"
                "ificates-per-exact-set-of-identifiers"
            ),
        },
        "authorization_failures_per_identifier_account": {
            "kind": "token_bucket",
            "title": "Authorization "
            "Failures per "
            "Identifier per "
            "Account",
            "capacity": 5,
            "unit": "failure",
            "scope": {
                "dimensions": ["account", "identifier"],
                "key_rules": {
                    "identifier": "DNS " "name " "or " "IP " "address"
                },
            },
            "nominal_window_seconds": 3600,
            "refill": {
                "tokens": 1,
                "period_seconds": 720,
                "precision": "published",
            },
            "cost_per_event": 1,
            "counted_event": "authorization_failed",
            "enforced_on": "new_order",
            "renewal_exemptions": {
                "ari_replacement": "documented_exempt",
                "same_identifier_set": "not_exempt",
            },
            "override_scopes": [],
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#authoriz"
                "ation-failures-per-identifier-per-account"
            ),
        },
        "consecutive_authorization_failures": {
            "kind": "consecutive_failure_guard",
            "title": "Consecutive Authorization "
            "Failures per Identifier "
            "per Account",
            "capacity": 1152,
            "unit": "failure",
            "scope": {
                "dimensions": ["account", "identifier"],
                "key_rules": {
                    "identifier": "DNS " "name " "or " "IP " "address"
                },
            },
            "nominal_window_seconds": None,
            "refill": {
                "tokens": 1,
                "period_seconds": 86400,
                "precision": "published",
            },
            "cost_per_event": 1,
            "counted_event": "consecutive_authorization_failed",
            "enforced_on": "new_order",
            "renewal_exemptions": {
                "ari_replacement": "documented_exempt",
                "same_identifier_set": "not_exempt",
            },
            "override_scopes": [],
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#consecut"
                "ive-authorization-failures-per-identifier-per-acco"
                "unt"
            ),
            "reset_on": "authorization_succeeded",
            "exhaustion_action": "identifier_issuance_paused",
            "recovery": "self_service_unpause_link; "
            "automatic unpause "
            "semantics not "
            "specified",
        },
    },
    "endpoints": {
        "/acme/new-nonce": {
            "kind": "endpoint_bucket",
            "unit": "request",
            "cost_per_event": 1,
            "scope": ["source_ip"],
            "refill": {
                "tokens": 20,
                "period_seconds": 1,
                "precision": "published",
            },
            "capacity": 10,
            "exhaustion_http_status": 503,
            "retry_after_header": True,
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#overall-"
                "requests-limit"
            ),
        },
        "/acme/new-account": {
            "kind": "endpoint_bucket",
            "unit": "request",
            "cost_per_event": 1,
            "scope": ["source_ip"],
            "refill": {
                "tokens": 5,
                "period_seconds": 1,
                "precision": "published",
            },
            "capacity": 15,
            "exhaustion_http_status": 503,
            "retry_after_header": True,
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#overall-"
                "requests-limit"
            ),
        },
        "/acme/new-order": {
            "kind": "endpoint_bucket",
            "unit": "request",
            "cost_per_event": 1,
            "scope": ["source_ip"],
            "refill": {
                "tokens": 300,
                "period_seconds": 1,
                "precision": "published",
            },
            "capacity": 200,
            "exhaustion_http_status": 503,
            "retry_after_header": True,
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#overall-"
                "requests-limit"
            ),
        },
        "/acme/revoke-cert": {
            "kind": "endpoint_bucket",
            "unit": "request",
            "cost_per_event": 1,
            "scope": ["source_ip"],
            "refill": {
                "tokens": 10,
                "period_seconds": 1,
                "precision": "published",
            },
            "capacity": 100,
            "exhaustion_http_status": 503,
            "retry_after_header": True,
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#overall-"
                "requests-limit"
            ),
        },
        "/acme/renewal-info": {
            "kind": "endpoint_bucket",
            "unit": "request",
            "cost_per_event": 1,
            "scope": ["source_ip"],
            "refill": {
                "tokens": 1000,
                "period_seconds": 1,
                "precision": "published",
            },
            "capacity": 100,
            "exhaustion_http_status": 503,
            "retry_after_header": True,
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#overall-"
                "requests-limit"
            ),
        },
        "/acme/*": {
            "kind": "endpoint_bucket",
            "unit": "request",
            "cost_per_event": 1,
            "scope": ["source_ip"],
            "refill": {
                "tokens": 250,
                "period_seconds": 1,
                "precision": "published",
            },
            "capacity": 125,
            "exhaustion_http_status": 503,
            "retry_after_header": True,
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#overall-"
                "requests-limit"
            ),
        },
        "/directory": {
            "kind": "endpoint_bucket",
            "unit": "request",
            "cost_per_event": 1,
            "scope": ["source_ip"],
            "refill": {
                "tokens": 40,
                "period_seconds": 1,
                "precision": "published",
            },
            "capacity": 40,
            "exhaustion_http_status": 503,
            "retry_after_header": True,
            "source_url": (
                "https://letsencrypt.org/docs/rate-limits/#overall-"
                "requests-limit"
            ),
        },
    },
    "endpoint_matching": {
        "patterns": "literal paths and /acme/* prefix pattern",
        "overlap_policy": "not specified by source; do not assume "
        "precedence or additive buckets",
        "renewal_exemption": "transport/load-balancer applicability not "
        "specified; do not disable request pacing "
        "for ARI",
    },
    "constraints": {
        "identifiers_per_certificate": {
            "kind": "profile_constraint",
            "unit": "identifier",
            "scope": ["certificate", "profile"],
            "maximum_by_profile": {
                "classic": 100,
                "tlsserver": 25,
                "shortlived": 25,
            },
            "source_url": "https://letsencrypt.org/docs/profiles/",
            "checked_on": "2026-10-28",
        }
    },
    "renewals": {
        "ari_replacement": {
            "conditions": [
                "order explicitly replaces an "
                "existing certificate using ARI",
                "at least one identifier overlaps the " "replaced certificate",
                "certificate has not already been " "replaced using ARI",
            ],
            "exempt_from": "documented certificate-issuance rate "
            "limits; not an arbitrary ARI-capable "
            "request",
            "server_decides_eligibility": True,
        },
        "same_identifier_set": {
            "normalization": "ignore capitalization and "
            "identifier ordering",
            "exempt_limit_ids": [
                "orders_per_account",
                "certificates_per_registered_domain",
            ],
            "other_limits": "still apply unless the server "
            "grants an exemption",
        },
    },
    "retry_policy": {
        "honor_retry_after": True,
        "multiple_exhausted_limits": "wait until the latest applicable retry "
        "time",
        "revocation_resets_quota": False,
        "quota_is_shared": "local estimates cannot observe other clients or "
        "account-specific overrides",
    },
}

# Public historical name, now explicitly schema version 2.
LIMITS = RATE_LIMITS
