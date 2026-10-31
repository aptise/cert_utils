"""Check legacy modulus warnings and unchanged RSA digest relationships."""

from pathlib import Path
from typing import Any
import warnings

import pytest

import cert_utils
from cert_utils import conditionals


@pytest.mark.parametrize(
    "kind,suffix", [("key", "key"), ("csr", "csr"), ("cert", "crt")]
)
@pytest.mark.parametrize("fallback", [False, True])
def test_modulus_deprecation(
    kind: str, suffix: str, fallback: bool, monkeypatch: Any
) -> None:
    """Every public modulus API warns at the caller and retains its RSA result."""
    if fallback:
        monkeypatch.setattr(conditionals, "cryptography", False)
    path = Path(__file__).parent / (
        "test_data/key_technology-rsa/selfsigned_1-server." + suffix
    )
    pem = path.read_text()
    function = getattr(cert_utils, "modulus_md5_" + kind)
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always", DeprecationWarning)
        result = function(pem, str(path))
    deprecations = [item for item in captured if item.category is DeprecationWarning]
    assert len(deprecations) == 1
    assert "parse_" + kind + "__spki_sha256" in str(deprecations[0].message)
    assert deprecations[0].filename == __file__
    assert result is not None and len(result) == 32
    # All three fixture objects share the same RSA modulus.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        key = path.with_suffix(".key")
        assert result == cert_utils.modulus_md5_key(key.read_text(), str(key))
