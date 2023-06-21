# stdlib
import pdb
import pprint

# pypi
from certbot import crypto_util
import cryptography
from cryptography.x509 import DNSName
from cryptography.x509.oid import ExtensionOID
from OpenSSL import crypto

# ==============================================================================

pems = {}
pems["privkey"] = open("privkey.pem").read()
pems["cert"] = open("cert.pem").read()
pems["csr"] = open("csr.pem").read()

pubs = {}

privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pems["privkey"])
privkey_cryptography = privkey.to_cryptography_key()
pubs["privkey"] = privkey_cryptography.public_key().public_numbers()

data = crypto_util.valid_privkey(pems["privkey"])


cert = crypto.load_certificate(crypto.FILETYPE_PEM, pems["cert"])
cert_cryptography = cert.to_cryptography()
cert_pub = cert.get_pubkey()
cert_pub_cryptography = cert_pub.to_cryptography_key()
pubs["cert"] = cert_pub_cryptography.public_numbers()


ext = cert_cryptography.extensions.get_extension_for_oid(
    cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
)
ext.value.get_values_for_type(cryptography.x509.DNSName)

pdb.set_trace()

#

ext = cert_cryptography.extensions.get_extension_for_oid(
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
)
ext.value.get_values_for_type(DNSName)


csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, pems["csr"])
csr_pub = csr.get_pubkey()
csr_pub_cryptography = csr_pub.to_cryptography_key()
pubs["csr"] = csr_pub_cryptography.public_numbers()


pdb.set_trace()


pprint.pprint(pubs)
