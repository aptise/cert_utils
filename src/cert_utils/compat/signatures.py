"""Small DER codecs for account signatures and OpenSSL public-key metadata.

No Cryptography/josepy dependency. This is not a general ASN.1 implementation.
"""

import subprocess
from typing import Optional
from typing import Tuple

import psutil

from ..errors import OpenSslError_InvalidKey


def _read(data: bytes, offset: int, tag: int) -> Tuple[bytes, int]:
    if offset + 2 > len(data) or data[offset] != tag:
        raise ValueError("invalid DER tag or truncated value")
    length = data[offset + 1]
    offset += 2
    if length & 128:
        count = length & 127
        if count == 0 or count > 2 or offset + count > len(data):
            raise ValueError("invalid DER length")
        length_end = offset + count
        encoded = data[offset:length_end]
        length = int.from_bytes(encoded, "big")
        if encoded[0] == 0 or length < 128:
            raise ValueError("non-minimal DER length")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return data[offset:end], end


def _encode(tag: int, value: bytes) -> bytes:
    length = len(value)
    size = (length.bit_length() + 7) // 8
    prefix = (
        bytes([length])
        if length < 128
        else bytes([128 | size]) + length.to_bytes(size, "big")
    )
    return bytes([tag]) + prefix + value


def raw_to_der(signature: bytes, width: int) -> bytes:
    """Encode a fixed-width unsigned r||s signature as canonical DER."""
    if width not in (32, 48, 66) or len(signature) != width * 2:
        raise ValueError("invalid standardized EC signature length")
    integers = []
    for part in (signature[:width], signature[width:]):
        part = part.lstrip(b"\x00") or b"\x00"
        if part[0] & 128:
            part = b"\x00" + part
        integers.append(_encode(2, part))
    return _encode(48, b"".join(integers))


def der_to_raw(signature: bytes, width: int) -> bytes:
    """Decode two canonical nonnegative DER integers, rejecting trailing data."""
    if width not in (32, 48, 66) or len(signature) > 2 * width + 10:
        raise ValueError("invalid EC signature size")
    sequence, end = _read(signature, 0, 48)
    if end != len(signature):
        raise ValueError("trailing DER signature data")
    offset = 0
    parts = []
    for _ in range(2):
        part, offset = _read(sequence, offset, 2)
        if not part or part[0] & 128:
            raise ValueError("invalid DER signature integer")
        if len(part) > 1 and part[0] == 0 and not part[1] & 128:
            raise ValueError("non-minimal DER signature integer")
        number = int.from_bytes(part, "big")
        if number.bit_length() > width * 8:
            raise ValueError("EC signature integer exceeds curve width")
        parts.append(number.to_bytes(width, "big"))
    if offset != len(sequence):
        raise ValueError("extra DER signature components")
    return b"".join(parts)


def openssl_key_width(openssl: str, filepath: str) -> Optional[int]:
    """Return None for RSA or EC component width, using only public metadata."""
    with psutil.Popen(
        [openssl, "pkey", "-in", filepath, "-pubout", "-outform", "DER"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        public, error = proc.communicate()
        if proc.returncode:
            raise OpenSslError_InvalidKey(error.decode("utf8", errors="replace"))
    sequence, end = _read(public, 0, 48)
    if end != len(public):
        raise ValueError("trailing public key data")
    algorithm, _ = _read(sequence, 0, 48)
    oid, offset = _read(algorithm, 0, 6)
    if oid == bytes.fromhex("2a864886f70d010101"):
        return None
    if oid != bytes.fromhex("2a8648ce3d0201"):
        raise ValueError("unsupported private key type")
    curve, end = _read(algorithm, offset, 6)
    if end != len(algorithm):
        raise ValueError("unsupported EC parameters")
    widths = {
        bytes.fromhex("2a8648ce3d030107"): 32,
        bytes.fromhex("2b81040022"): 48,
        bytes.fromhex("2b81040023"): 66,
    }
    if curve not in widths:
        raise ValueError("unsupported EC curve")
    return widths[curve]
