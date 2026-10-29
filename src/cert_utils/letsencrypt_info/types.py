"""Shared TypedDict definitions for certificate and rate-limit metadata."""

from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

from typing_extensions import Literal
from typing_extensions import Required
from typing_extensions import TypedDict


class Source(TypedDict):
    url: str
    document_last_modified: str
    checked_on: str
    checkout: str
    path: str


class Refill(TypedDict):
    tokens: int
    period_seconds: int
    precision: str


class Scope(TypedDict):
    dimensions: List[str]
    key_rules: Dict[str, str]


class Limit(TypedDict, total=False):
    kind: Required[Literal["token_bucket", "consecutive_failure_guard"]]
    title: Required[str]
    capacity: Required[int]
    unit: Required[str]
    scope: Required[Scope]
    nominal_window_seconds: Required[Optional[int]]
    refill: Required[Refill]
    counted_event: Required[str]
    cost_per_event: Required[int]
    enforced_on: Required[str]
    renewal_exemptions: Required[Dict[str, str]]
    override_scopes: Required[List[str]]
    source_url: Required[str]
    reset_on: str
    exhaustion_action: str
    recovery: str


class Endpoint(TypedDict):
    kind: str
    unit: str
    cost_per_event: int
    scope: List[str]
    refill: Refill
    capacity: int
    exhaustion_http_status: int
    retry_after_header: bool
    source_url: str


class Constraint(TypedDict):
    kind: str
    unit: str
    scope: List[str]
    maximum_by_profile: Dict[str, int]
    source_url: str
    checked_on: str


class Renewal(TypedDict, total=False):
    conditions: List[str]
    exempt_from: str
    server_decides_eligibility: bool
    normalization: str
    exempt_limit_ids: List[str]
    other_limits: str


class Catalogue(TypedDict):
    schema_version: int
    policy_environment: str
    source: Source
    limits: Dict[str, Limit]
    endpoints: Dict[str, Endpoint]
    endpoint_matching: Dict[str, str]
    constraints: Dict[str, Constraint]
    renewals: Dict[str, Renewal]
    retry_policy: Dict[str, Union[str, bool]]


CERT_CA_PAYLOAD = TypedDict(
    "CERT_CA_PAYLOAD",
    {
        "display_name": Required[str],
        "url_pem": Required[str],
        "is_trusted_root": Optional[bool],
        "is_untrusted_root": Optional[bool],
        "is_self_signed": Optional[bool],
        "signed_by": Required[str],
        "is_active": Required[bool],
        "is_retired": Optional[bool],
        "is_backup": Optional[bool],
        "key_technology": Required[str],
        "cert.fingerprints": Optional[Dict[str, str]],
        ".enddate": Optional[Tuple[int, ...]],
        "compatibility": Optional[
            Dict[str, Tuple[str, Optional[str], Optional[str]]]
        ],  # platform: (min, max, note)
        "alternates": Optional[List[str]],
        "alternate_of": Optional[str],
        "letsencrypt_serial": Optional[str],
        # loaded via deprecated processors
        "cert_pem": Optional[str],
        "cert_pem_md5": Optional[str],
    },
    total=False,
)
