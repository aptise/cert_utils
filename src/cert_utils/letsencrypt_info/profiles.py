"""Versioned advisory profile metadata, never an allowlist for ACME clients.

The server directory determines availability. Values describe the published
production policy at the source revision, not guarantees about future issuance.
Certificate validity and ACME expires/ARI responses remain authoritative.
"""

from typing import Dict
from typing import List

from typing_extensions import TypedDict

from .types import Source


class Profile(TypedDict):
    """Published validation and certificate properties, with durations in seconds."""

    validity_seconds: int
    pending_authorization_seconds: int
    authorization_reuse_seconds: int
    order_seconds: int
    max_identifiers: int
    identifier_types: List[str]
    includes_common_name: bool


class ValidityChange(TypedDict):
    """An announced future policy change; clients must not use it as a timer."""

    profile: str
    effective_on: str
    validity_seconds: int
    authorization_reuse_seconds: int


class ProfileCatalogue(TypedDict):
    """JSON-compatible snapshot with independent profile and announcement sources."""

    schema_version: int
    source: Source
    validity_changes_source: Source
    profiles: Dict[str, Profile]
    retired_profiles: Dict[str, str]
    announced_validity_changes: List[ValidityChange]


PROFILES: ProfileCatalogue = {
    "schema_version": 1,
    "source": {
        "url": "https://letsencrypt.org/docs/profiles/",
        "document_last_modified": "2026-10-04",
        "checked_on": "2026-10-30",
        "checkout": "bb7e7238",
        "path": "content/en/docs/profiles.md",
    },
    "validity_changes_source": {
        "url": "https://letsencrypt.org/2025/12/02/from-90-to-45/",
        "document_last_modified": "2025-12-02",
        "checked_on": "2026-10-30",
        "checkout": "bb7e7238",
        "path": "content/en/post/2025-12-02-from-90-to-45.md",
    },
    "profiles": {
        "classic": {
            "validity_seconds": 90 * 86400,
            "pending_authorization_seconds": 7 * 86400,
            "authorization_reuse_seconds": 30 * 86400,
            "order_seconds": 7 * 86400,
            "max_identifiers": 100,
            "identifier_types": ["dns"],
            "includes_common_name": True,
        },
        "tlsserver": {
            "validity_seconds": 45 * 86400,
            "pending_authorization_seconds": 3600,
            "authorization_reuse_seconds": 7 * 3600,
            "order_seconds": 8 * 3600,
            "max_identifiers": 25,
            "identifier_types": ["dns"],
            "includes_common_name": False,
        },
        "shortlived": {
            "validity_seconds": 160 * 3600,
            "pending_authorization_seconds": 3600,
            "authorization_reuse_seconds": 7 * 3600,
            "order_seconds": 8 * 3600,
            "max_identifiers": 25,
            "identifier_types": ["dns", "ip"],
            "includes_common_name": False,
        },
    },
    "retired_profiles": {"tlsclient": "2026-07-08"},
    "announced_validity_changes": [
        {
            "profile": "classic",
            "effective_on": "2027-02-10",
            "validity_seconds": 64 * 86400,
            "authorization_reuse_seconds": 10 * 86400,
        },
        {
            "profile": "classic",
            "effective_on": "2028-02-16",
            "validity_seconds": 45 * 86400,
            "authorization_reuse_seconds": 7 * 3600,
        },
    ],
}
