"""
Please don't use this.

THIS ENTIRE FILE IS DEPRECATED, UNTESTED AND UNSUPPORTED.

This is provided solely for legacy information as these operations are a bit
more esoteric and not well documented elsewhere.

Please use the other interfaces.
"""

import logging
from types import ModuleType
from typing import List
from typing import Optional

# locals
from ..errors import OpenSslError
from ..utils import split_pem_chain

# conditional imports
openssl_crypto: Optional[ModuleType]
try:
    from OpenSSL import crypto as openssl_crypto
except ImportError:
    openssl_crypto = None

# logging
log = logging.getLogger("cert_utils")
log.setLevel(logging.INFO)

# ==============================================================================


def ensure_chain(
    root_pem: str,
    fullchain_pem: Optional[str] = None,
    cert_pem: Optional[str] = None,
    chain_pem: Optional[str] = None,
    root_pems_other: Optional[List[str]] = None,
) -> bool:
    """
    validates from a root down to a chain
    if chain is a fullchain (with endentity), cert_pem can be None

    THIS WILL RAISE ERRORS, NOT RETURN VALUES

    submit EITHER fullchain_pem or chain_pem+cert_pem

    :param root_pem: The PEM Encoded Root Certificate. Required.
    :type root_pem: str
    :param fullchain_pem: A full Certificate chain in PEM encoding, which
        consists of a Leaf Certificate, and optionally multiple upstream certs in
        a single string.
        If provided:
            * `:param:cert_pem` MUST NOT be provided
            * `:param:chain_pem` MUST NOT be provided.
    :type fullchain_pem: str
    :param cert_pem: the EndEntity or Leaf Certificate.
        If provided:
            * `:param:chain_pem` MUST be provided
            * `:param:fullchain_pem` MUST NOT be provided.
    :type cert_pem: str
    :param chain_pem: A Certificate chain in PEM format, which is multiple
        upstream certs in a single string.
        If provided:
            * `:param:cert_pem` MUST be provided
            * `:param:fullchain_pem` MUST NOT be provided.
    :param root_pems_other: an iterable list of trusted roots certificates, in
       PEM encoding; currently unused.
    :returns: True
    :rtype: bool


    The OpenSSL Equivalent / Fallback is::

    Modern versions of openssl accept multiple `-untrusted` arguments::

        openssl verify -purpose sslserver -CAfile root.pem [[-untrusted intermediate.pem],[-untrusted intermediate.pem],] cert.pem

    However older ones only want to see a single `-untrusted`::

        openssl verify -purpose sslserver -CAfile root.pem -untrusted intermediate.pem cert.pem

    To get around this, put all the intermediates into a single file.

    This is a stopgap solution and needs to be refactored.

    NOTE:
        openssl does not care about the order of intermediates, so this should
        be iteratively built up like the pure-python example
    """
    log.debug("ensure_chain >")
    if fullchain_pem:
        if chain_pem or cert_pem:
            raise ValueError(
                "If `ensure_chain` is invoked with `fullchain_pem`, do not pass in `chain_pem` or `cert_pem`."
            )
    else:
        if not chain_pem or not cert_pem:
            raise ValueError(
                "If `ensure_chain` is not invoked with `fullchain_pem`, you must pass in `chain_pem` and `cert_pem`."
            )

    if fullchain_pem:
        intermediates = split_pem_chain(fullchain_pem)
        cert_pem = intermediates.pop(0)
    else:
        assert cert_pem
        assert chain_pem
        intermediates = split_pem_chain(chain_pem)
        cert_pem = cert_pem.strip()  # needed to match regex results in above situation

    # sometimes people submit things they should not
    if intermediates[-1] == cert_pem:
        intermediates = intermediates[:-1]

    if not openssl_crypto:
        raise ValueError("Requires pyopenssl")
    # build a root storage
    store = openssl_crypto.X509Store()
    root_parsed = openssl_crypto.load_certificate(
        openssl_crypto.FILETYPE_PEM, root_pem.encode()
    )
    store.add_cert(root_parsed)

    for _intermediate_pem in reversed(intermediates):
        _intermediate_parsed = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, _intermediate_pem.encode()
        )
        # Check the chain certificate before adding it to the store.
        _store_ctx = openssl_crypto.X509StoreContext(store, _intermediate_parsed)
        _store_ctx.verify_certificate()
        store.add_cert(_intermediate_parsed)

    cert_parsed = openssl_crypto.load_certificate(
        openssl_crypto.FILETYPE_PEM, cert_pem.encode()
    )
    _store_ctx = openssl_crypto.X509StoreContext(store, cert_parsed)
    _store_ctx.verify_certificate()
    return True


def ensure_chain_order(
    chain_certs: List[str],
    cert_pem: Optional[str] = None,
) -> bool:
    """
    :param chain_certs: A list of PEM encoded Certificates. Required.
    :type chain_certs: list
    :param cert_pem: A PEM Encoded Certificate to test against the `chain_certs`.
        Optional
    :type cert_pem: str
    :returns: bool
    :rtype: None

    The OpenSSL Equivalent / Fallback is::

        /usr/local/bin/openssl verify -purpose sslserver -partial_chain -trusted {ROOT.pem} {CHAINREVERSED.pem}
    """
    log.debug("ensure_chain_order >")
    if cert_pem:
        chain_certs.append(cert_pem)
    if len(chain_certs) < 2:
        raise ValueError("must submit 2 or more chain certificates")
    # reverse the cert list
    # we're going to pretend the last item is a root
    r_chain_certs = chain_certs[::-1]
    if not openssl_crypto:
        raise ValueError("Requires pyopenssl")
    # TODO: openssl crypto does not seem to support partial chains yet
    # as a stopgap, just look to ensure the issuer/subject match
    """
    # build a root storage
    # pretend the first item is a root
    store = openssl_crypto.X509Store()
    root_pem = r_chain_certs.pop(0)
    root_parsed = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, root_pem)
    store.add_cert(root_parsed)

    for (idx, cert_pem) in enumerate(r_chain_certs):
        # Check the chain certificate before adding it to the store.
        try:
            cert_parsed = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, cert_pem)
            _store_ctx = openssl_crypto.X509StoreContext(store, cert_parsed)
            _store_ctx.verify_certificate()
            store.add_cert(cert_parsed)
        except openssl_crypto.X509StoreContextError as exc:
            raise OpenSslError("could not verify: crypto")
    """
    # stash our data in here
    parsed_certs = {}

    # loop the certs
    for idx, cert_pem in enumerate(r_chain_certs):
        # everyone generates data
        cert = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, cert_pem.encode()
        )
        parsed_certs[idx] = cert
        if idx == 0:
            continue
        # only after the first cert do we need to check the last cert
        upchain = parsed_certs[idx - 1]
        if upchain.get_subject() != cert.get_issuer():
            raise OpenSslError("could not verify: upchain does not match issuer")
    return True
