"""
pip install cert_utils requests
"""
from __future__ import annotations

# stdlib
import logging
import os
import pprint
import socket  # peername hack, see below
import sys
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import TypedDict

# pypi
import _socket  # noqa: I100,I201  # peername hack, see below
import requests
from requests import Response

# local
import cert_utils

if TYPE_CHECKING:
    from requests.structures import CaseInsensitiveDict

log = logging.getLogger(__name__)

# peername hacks
# only use for these stdlib packages
# eventually will not be needed thanks to upstream changes in `requests`
try:
    _compatible_sockets: Tuple = (
        _socket.socket,
        socket._socketobject,  # type: ignore[attr-defined]
    )
except AttributeError:
    _compatible_sockets: Tuple = (_socket.socket,)  # type: ignore[no-redef]


# ==============================================================================


class PeerData(TypedDict, total=False):
    peername: Tuple[str, int]
    cert_dict: Optional[Dict]
    cert_pem: Optional[str]


class AllowableError(Exception):
    pass


def get_response_data(resp: Response) -> Optional[PeerData]:
    """
    used to get the peername (ip+port) data from the request
    if a socket is found, caches this onto the request object

    IMPORTANT. this must happen BEFORE any content is consumed.

    `response` is really `requests.models.Response`

    This will UPGRADE the response object to have the following attribute:

        * _mp_peername
    """
    if not isinstance(resp, requests.Response):
        # raise AllowableError("Not a HTTPResponse")
        log.debug("Not a supported HTTPResponse | %s", resp)
        log.debug("-> received a type of: %s", type(resp))
        return None

    if hasattr(resp, "_sock_data"):
        return resp._sock_data

    def _get_socket() -> Optional[socket.socket]:
        i = 0
        while True:
            i += 1
            try:
                if i == 1:
                    sock = resp.raw._connection.sock
                elif i == 2:
                    sock = resp.raw._connection.sock.socket
                elif i == 3:
                    sock = resp.raw._fp.fp._sock
                elif i == 4:
                    sock = resp.raw._fp.fp._sock.socket
                elif i == 5:
                    sock = resp.raw._fp.fp.raw._sock
                else:
                    break
                if not isinstance(sock, _compatible_sockets):
                    raise AllowableError()
                return sock
            except Exception:
                pass
        return None

    if TYPE_CHECKING:
        assert hasattr(resp, "_sock_data")

    sock = _get_socket()
    if sock:
        # only cache if we have a sock
        # we may want/need to call again
        resp._sock_data = PeerData()
        resp._sock_data["peername"] = sock.getpeername()
        try:
            resp._sock_data["cert_dict"] = sock.getpeercert()  # type: ignore[attr-defined]
            _cert_raw = sock.getpeercert(binary_form=True)  # type: ignore[attr-defined]
            if _cert_raw:
                resp._sock_data["cert_pem"] = cert_utils.convert_der_to_pem(_cert_raw)
        except AttributeError:  # http connections
            pass
    else:
        resp._sock_data = None
    return resp._sock_data


# ------------------------------------------------------------------------------


def response_initial_hook(resp: Response, *args, **kwargs) -> None:
    get_response_data(resp)
    # do not return anything


def new_session() -> requests.Session:
    """generate a new Session with our hook built in"""
    sess = requests.Session()
    sess.hooks["response"].insert(0, response_initial_hook)
    return sess


def process_ari_url(
    sess: requests.Session,
    url: str,
    _print=True,
) -> Tuple[Optional[Dict], CaseInsensitiveDict]:
    if _print:
        print("=-" * 40)
        print("Requesting ARI")
        print("ari_url:", url)
    r = sess.get(url)
    _data: Optional[Dict] = r.json()
    _headers: CaseInsensitiveDict = r.headers
    if _print:
        pprint.pprint(_headers)
        print("- " * 10)
        pprint.pprint(_data)
    return (_data, _headers)


def issuer_to_endpoint(
    cert_data: Optional[Dict] = None,
    sock_data: Optional[Dict] = None,
) -> Optional[str]:
    if not any((cert_data, sock_data)) or all((cert_data, sock_data)):
        raise ValueError("submit `cert_data` OR `sock_data`")
    if cert_data:
        _issuer = cert_data["issuer"].split("\n")
        if _issuer[1] == "O=Let's Encrypt":
            return "https://acme-v02.api.letsencrypt.org/directory"
        return None
    if TYPE_CHECKING:
        assert sock_data is not None
    if sock_data["issuer"][1][0][1] == "Let's Encrypt":
        return "https://acme-v02.api.letsencrypt.org/directory"
    return None


def ari_query(
    acme_server: str, ari_id: str
) -> Tuple[Optional[Dict], CaseInsensitiveDict]:
    sess = new_session()
    r = sess.get(acme_server)
    _renewal_base = r.json().get("renewalInfo")
    if not _renewal_base:
        raise ValueError("endpoint does not support ARI")
    _renewal_base_url = "%s/%s" % (_renewal_base, ari_id)
    (_d, _h) = process_ari_url(sess, _renewal_base_url, _print=True)
    return (_d, _h)


def process_filepath(filepath: str) -> None:
    print("**" * 40)
    print("**" * 40)
    print("Process Filepath:")
    print("filepath: ", filepath)
    if not os.path.exists(filepath):
        raise ValueError("invalid filepath")

    with open(filepath, "r") as _file:
        cert_pem = _file.read()

    cert_data = cert_utils.parse_cert(cert_pem=cert_pem, cert_pem_filepath=filepath)
    print("=-" * 40)
    print("Cert Data:")
    pprint.pprint(cert_data)
    print("=-" * 40)

    _ari_id = cert_utils.ari_construct_identifier(cert_pem)
    print("ARI ID: %s" % _ari_id)
    _acme_server = issuer_to_endpoint(cert_data=cert_data)
    if _acme_server:
        ari_query(_acme_server, _ari_id)
    else:
        print("No known ARI endpoint")


def process_url(url: str) -> None:
    print("**" * 40)
    print("**" * 40)
    print("Process URL:")
    print("url: ", url)
    sess = new_session()

    r = sess.get(url)
    if TYPE_CHECKING:
        assert hasattr(r, "_sock_data")

    print("=-" * 40)
    print("Connection Data:")
    pprint.pprint(r._sock_data)
    print("=-" * 40)

    _cert_dict = r._sock_data.get("cert_dict")
    _cert_pem = r._sock_data.get("cert_pem")
    if _cert_pem:
        print("=-" * 40)
        print("Cert Data:")
        _ari_id = cert_utils.ari_construct_identifier(_cert_pem)
        print("ARI ID: %s" % _ari_id)

        _acme_server = issuer_to_endpoint(sock_data=_cert_dict)
        if _acme_server:
            ari_query(_acme_server, _ari_id)
        else:
            print("No known ARI endpoint")


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s < url | filepath >\n"
        '  (example: "%s https://example.com")\n'
        '  (example: "%s /path/to/cert.pem")' % (cmd, cmd, cmd)
    )
    sys.exit(1)


def main(argv: List = sys.argv):
    if len(argv) != 2:
        usage(argv)
    target = sys.argv[1]
    if target.startswith("http://"):
        raise ValueError("Can not handle `http`!")
    elif target.startswith("https://"):
        process_url(target)
    else:
        process_filepath(target)


if __name__ == "__main__":
    process_url("https://2xlp.com")
