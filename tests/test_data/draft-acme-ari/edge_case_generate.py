"""
The edge cases generate an AuthorityKeyIdentifer with extraneous params.

The values and contents are designed to mimic the Appendix A cert from the
draft-ari-spec RFC

X509v3 Authority Key Identifier:
    keyid:69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4
    URI:EXAMPLE.COM
    serial:01

vs

X509v3 Authority Key Identifier:
    69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4
"""

# stdlib
from datetime import datetime
from typing import Union

# pypi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing_extensions import Literal


def generate_cert(
    strategy: Union[Literal["key_id"], Literal["issuer+serial"], Literal["all"]]
) -> bytes:
    # pregenerate values
    _key_identifier = bytes.fromhex(
        "69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4".replace(":", "")
    )
    _authority_cert_issuer = [x509.UniformResourceIdentifier("EXAMPLE.COM")]
    _authority_cert_serial_number = 1
    # okgo
    private_key = ec.generate_private_key(curve=ec.SECP256R1)
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com"),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Example CA"),
        ]
    )
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(private_key.public_key())
    cert_builder = cert_builder.serial_number(2271560481)
    cert_builder = cert_builder.not_valid_before(datetime(1950, 1, 1))
    cert_builder = cert_builder.not_valid_after(datetime(1950, 1, 1))
    if strategy == "key_id":
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=_key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
    elif strategy == "issuer+serial":
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=None,
                authority_cert_issuer=_authority_cert_issuer,
                authority_cert_serial_number=_authority_cert_serial_number,
            ),
            critical=False,
        )
    elif strategy == "all":
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=_key_identifier,
                authority_cert_issuer=_authority_cert_issuer,
                authority_cert_serial_number=_authority_cert_serial_number,
            ),
            critical=False,
        )
    certificate = cert_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    return cert_pem


def decode_akid(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    akid: str = ""
    try:
        ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        akid = ext.value.key_identifier
    except Exception as exc:
        print("\t", "\t", exc)
    return akid


def test_strategy(strategy: str, write_cert: bool = False):
    print("testing:", strategy)
    cert = generate_cert(strategy=strategy)
    if write_cert:
        with open("cert--%s.pem" % strategy, "wb") as f:
            f.write(cert)
    try:
        akid = decode_akid(cert)
        print("\t", "akid = ", akid)
    except Exception as exc:
        print("\t", "FAIL")
        print("\t", exc)


if __name__ == "__main__":
    write_cert = True
    test_strategy("key_id", write_cert=write_cert)
    test_strategy("issuer+serial", write_cert=write_cert)
    test_strategy("all", write_cert=write_cert)
