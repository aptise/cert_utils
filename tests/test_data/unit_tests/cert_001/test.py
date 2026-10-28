"""Inspect the RSA certificate fixtures; run from this directory."""

import pprint

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

with open("privkey.pem", "rb") as stream:
    key = serialization.load_pem_private_key(stream.read(), password=None)
assert isinstance(key, RSAPrivateKey)
with open("cert.pem", "rb") as stream:
    cert = x509.load_pem_x509_certificate(stream.read())
with open("csr.pem", "rb") as stream:
    csr = x509.load_pem_x509_csr(stream.read())
cert_key = cert.public_key()
csr_key = csr.public_key()
assert isinstance(cert_key, RSAPublicKey)
assert isinstance(csr_key, RSAPublicKey)
pprint.pprint(
    {
        "privkey": key.public_key().public_numbers(),
        "cert": cert_key.public_numbers(),
        "csr": csr_key.public_numbers(),
    }
)
