"""Opt-in Certbot lineage discovery and private filesystem metadata caching."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List, Optional, Set

import cert_utils
from .identifiers import parse_cert_identifiers

CACHE_VERSION = str(cert_utils.__VERSION__) + ":1"
DEFAULT_TTL = 300


def domains(path: Path) -> List[str]:
    """Read canonical DNS identities from a lineage's current certificate."""
    return sorted(
        {
            i["value"].rstrip(".")
            for i in parse_cert_identifiers(path.read_text())
            if i["type"] == "dns"
        }
    )


def metadata(path: Path) -> List[int]:
    """Track replacement, modification, and target changes without reading content."""
    info = path.stat()
    return [info.st_mtime_ns, info.st_size, info.st_ino, info.st_ctime_ns]


def installation_root(certificate: str, managed: bool, explicit: Optional[str]) -> Path:
    """Resolve managed live/archive paths and reject conflicting context roots."""
    derived: Optional[Path] = None
    if managed:
        for candidate in (
            Path(os.path.abspath(certificate)),
            Path(certificate).resolve(),
        ):
            if candidate.parent.parent.name in ("live", "archive"):
                derived = candidate.parent.parent.parent.resolve()
                break
        if derived is None:
            raise ValueError("certificate is not in a managed live/archive lineage")
    root = (
        Path(explicit).expanduser().resolve()
        if explicit
        else derived or Path("/etc/letsencrypt")
    )
    if derived is not None and root != derived:
        raise ValueError("Let's Encrypt installation roots conflict")
    return root


def _save(path: Path, data: Dict[str, Any]) -> None:
    """Atomically persist only public lineage metadata with private permissions."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(str(path.parent), 0o700)
    descriptor, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".cache-")
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(data, stream)
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def lineage_index(
    root: Path, ttl: float, refresh: bool, no_cache: bool
) -> Dict[str, Any]:
    """Revalidate both renewal files and certificates after the bounded TTL."""
    cache_dir = Path.home() / ".cert_utils"
    cache_path = cache_dir / (
        "renewal-" + hashlib.sha256(str(root).encode()).hexdigest() + ".json"
    )
    now = time.time()
    cached: Dict[str, Any] = {}
    if not no_cache:
        for old in cache_dir.glob("renewal-*.json"):
            try:
                content = json.loads(old.read_text())
                if content.get("version_id") != CACHE_VERSION or now - content.get(
                    "checked", 0
                ) > max(ttl, 86400):
                    old.unlink()
                elif old == cache_path:
                    cached = content
            except (OSError, ValueError, TypeError, AttributeError):
                try:
                    old.unlink()
                except OSError:
                    pass
        if not refresh and 0 <= now - cached.get("checked", 0) < ttl:
            return cached.get("entries", {})
    entries: Dict[str, Any] = {}
    # Certbot uses renewal/; accept renewals/ installations as well.
    configurations = sorted(
        set(root.glob("renewal/*.conf")) | set(root.glob("renewals/*.conf"))
    )
    for configuration in configurations:
        try:
            parser = configparser.ConfigParser(interpolation=None, strict=False)
            parser.read_string("[lineage]\n" + configuration.read_text())
            section = parser["lineage"]
            certificate = Path(section["cert"])
            if not certificate.is_absolute():
                certificate = root / certificate
            stamps = [metadata(configuration), metadata(certificate)]
            previous = cached.get("entries", {}).get(str(configuration), {})
            if not refresh and previous.get("metadata") == stamps:
                entries[str(configuration)] = previous
            else:
                entries[str(configuration)] = {
                    "metadata": stamps,
                    "domains": domains(certificate),
                    "account": parser.get("renewalparams", "account", fallback=None),
                }
        except (OSError, ValueError, KeyError, configparser.Error) as error:
            print(
                "Warning: unable to inspect renewal configuration %s: %s"
                % (configuration, error)
            )
    if not no_cache:
        try:
            _save(
                cache_path,
                {"version_id": CACHE_VERSION, "checked": now, "entries": entries},
            )
        except OSError as error:
            print("Warning: unable to save discovery cache: %s" % error)
    return entries


def discover(
    certificate: str, root: Path, mode: str, ttl: float, refresh: bool, no_cache: bool
) -> List[Dict[str, Any]]:
    """Report additive domain, byte identity, path, and public key evidence."""
    target = Path(certificate)
    target_domains = set(domains(target))
    target_bytes = target.read_bytes()
    results: List[Dict[str, Any]] = []
    for filename, entry in lineage_index(root, ttl, refresh, no_cache).items():
        names: Set[str] = set(entry["domains"])
        exact = bool(names) and names == target_domains
        overlap = sorted(names & target_domains)
        if not exact and not (mode != "exact" and overlap) and mode != "all":
            continue
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string("[lineage]\n" + Path(filename).read_text())
            configured = Path(parser["lineage"]["cert"])
            if not configured.is_absolute():
                configured = root / configured
            candidates = [configured]
            archive = parser["lineage"].get("archive_dir")
            if exact and archive:
                archive_path = Path(archive)
                if not archive_path.is_absolute():
                    archive_path = root / archive_path
                candidates.extend(sorted(archive_path.glob("cert*.pem")))
            identical: List[str] = []
            same_path = False
            same_key = False
            for candidate in candidates:
                try:
                    same_path = same_path or candidate.resolve() == target.resolve()
                    raw = candidate.read_bytes()
                    if raw == target_bytes and os.path.abspath(
                        str(candidate)
                    ) != os.path.abspath(str(target)):
                        identical.append(str(candidate))
                    if mode == "all":
                        same_key = same_key or (
                            cert_utils.parse_cert(raw.decode())["spki_sha256"]
                            == cert_utils.parse_cert(target_bytes.decode())[
                                "spki_sha256"
                            ]
                        )
                except (OSError, ValueError, ImportError):
                    continue
            if exact or overlap or same_path or same_key or identical:
                results.append(
                    {
                        "renewal": filename,
                        "account": entry["account"],
                        "evidence": (
                            "identical domain set"
                            if exact
                            else (
                                "partial domain overlap"
                                if overlap
                                else "inferred correlation"
                            )
                        ),
                        "matching_domains": overlap,
                        "identical_certificate_paths": sorted(set(identical)),
                        "same_managed_path": same_path,
                        "same_public_key": same_key,
                    }
                )
        except (OSError, KeyError, configparser.Error) as error:
            print("Warning: unable to correlate %s: %s" % (filename, error))
    return results
