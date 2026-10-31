"""Typed certificate identities; SAN kind is never inferred from its text."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import subprocess
import tempfile
from typing import List
from typing import Optional
from typing import TYPE_CHECKING
from typing import Union

from typing_extensions import Literal
from typing_extensions import TypedDict

from . import conditionals

if TYPE_CHECKING:
    from cryptography.x509 import Certificate
    from cryptography.x509 import CertificateSigningRequest


class Identifier(TypedDict):
    """An explicit DNS SAN or IP SAN with its canonical string value."""

    type: Literal["dns", "ip"]
    value: str


def _native(loaded: Union[Certificate, CertificateSigningRequest]) -> List[Identifier]:
    """Use SANs authoritatively; retain DNS CN fallback only when SAN is absent."""
    from cryptography import x509

    result: List[Identifier] = []
    try:
        extension = loaded.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        for attribute in loaded.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )[:1]:
            value = attribute.value
            result.append(
                {
                    "type": "dns",
                    "value": (
                        value.decode() if isinstance(value, bytes) else value
                    ).lower(),
                }
            )
    else:
        for name in extension.value:
            if isinstance(name, x509.DNSName):
                result.append({"type": "dns", "value": name.value.lower()})
            elif isinstance(name, x509.IPAddress):
                result.append(
                    {"type": "ip", "value": str(ipaddress.ip_address(str(name.value)))}
                )
    return _deduplicate(result)


def _deduplicate(values: List[Identifier]) -> List[Identifier]:
    """Return deterministic identities, retaining DNS/IP distinctions."""
    unique = {(item["type"], item["value"]): item for item in values}
    return [unique[key] for key in sorted(unique)]


def _text_sans(text: str) -> Optional[List[Identifier]]:
    """Read only the OpenSSL SAN block, including folded output lines."""
    result: List[Identifier] = []
    indentation: Optional[int] = None
    for line in text.splitlines():
        if "X509v3 Subject Alternative Name:" in line:
            indentation = len(line) - len(line.lstrip())
            continue
        if indentation is None:
            continue
        if line.strip() and len(line) - len(line.lstrip()) <= indentation:
            break
        for field in line.strip().split(","):
            field = field.strip()
            if field.startswith("DNS:"):
                result.append({"type": "dns", "value": field[4:].lower()})
            elif field.startswith("IP Address:"):
                result.append(
                    {"type": "ip", "value": str(ipaddress.ip_address(field[11:]))}
                )
    return None if indentation is None else _deduplicate(result)


def _openssl_output(kind: Literal["x509", "req"], path: Path, *options: str) -> str:
    """Use bounded subprocesses and omit raw diagnostic payloads from failures."""
    from . import core

    try:
        response = subprocess.run(
            [core.openssl_path, kind, "-in", str(path), "-noout", *options],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("OpenSSL identifier parsing failed") from None
    if response.returncode:
        raise ValueError("OpenSSL could not parse the certificate or CSR")
    return response.stdout.decode("utf-8")


def _parse(
    pem: str, kind: Literal["x509", "req"], filepath: Optional[str]
) -> List[Identifier]:
    """Parse with the selected backend; bound and close the OpenSSL subprocess."""
    if conditionals.cryptography:
        from cryptography import x509

        loaded = (
            x509.load_pem_x509_certificate(pem.encode())
            if kind == "x509"
            else x509.load_pem_x509_csr(pem.encode())
        )
        return _native(loaded)
    with tempfile.TemporaryDirectory(prefix="cert-identifiers-") as directory:
        path = Path(filepath) if filepath else Path(directory) / "public.pem"
        if not filepath:
            with path.open("w", encoding="ascii") as output:
                output.write(pem)
            path.chmod(0o600)
        result = _text_sans(_openssl_output(kind, path, "-text"))
        if result is not None:
            return result
        # Dedicated multiline subject output avoids mistaking "CN=" inside an
        # organization or issuer value for the actual subject common name.
        subject = _openssl_output(
            kind, path, "-subject", "-nameopt", "sep_multiline,utf8,esc_ctrl,esc_msb"
        )
        common_name = re.search(r"(?m)^\s*CN\s*=\s*([^\n]+)$", subject)
        return (
            [{"type": "dns", "value": common_name.group(1).strip().lower()}]
            if common_name
            else []
        )


def parse_cert_identifiers(
    cert_pem: str, cert_pem_filepath: Optional[str] = None
) -> List[Identifier]:
    """Return typed certificate SANs, without flattening IP SANs into DNS names."""
    return _parse(cert_pem, "x509", cert_pem_filepath)


def parse_csr_identifiers(
    csr_pem: str, csr_pem_filepath: Optional[str] = None
) -> List[Identifier]:
    """Return typed CSR SANs using the same identity rules as certificates."""
    return _parse(csr_pem, "req", csr_pem_filepath)
