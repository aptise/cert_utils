"""
pip install cert_utils requests
"""

from __future__ import annotations

# stdlib
import _socket
import argparse
import logging
import math
import os
import pprint
import shutil
import socket  # peername hack, see below
import sys
import tempfile
from typing import Any
from typing import Dict
from typing import List
from typing import Mapping
from typing import NoReturn
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

# pypi
import requests
from requests import Response
from typing_extensions import TypedDict

# local
import cert_utils
from cert_utils.network import get_timeout
from cert_utils.network import parse_timeout
from cert_utils.network import Timeout
import cert_utils.utils_discovery

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

USER_AGENT = "cert_utils/%s" % cert_utils.__VERSION__


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

        * _sock_data
    """
    if not isinstance(resp, requests.Response):
        # raise AllowableError("Not a HTTPResponse")
        log.info("Not a supported HTTPResponse | %s", resp)
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
                    sock = resp.raw._connection.sock  # type: ignore[union-attr]
                elif i == 2:
                    sock = resp.raw._connection.sock.socket  # type: ignore[union-attr]
                elif i == 3:
                    sock = resp.raw._fp.fp._sock  # type: ignore[union-attr]
                elif i == 4:
                    sock = resp.raw._fp.fp._sock.socket  # type: ignore[union-attr]
                elif i == 5:
                    sock = resp.raw._fp.fp.raw._sock  # type: ignore[union-attr]
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


def response_initial_hook(resp: Response, *args: Any, **kwargs: Any) -> None:
    get_response_data(resp)
    # do not return anything


class _TimeoutSession(requests.Session):
    def __init__(self, timeout: Timeout) -> None:
        super().__init__()
        self.timeout = timeout

    def request(
        self,
        method: Union[str, bytes],
        url: Union[str, bytes],
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        # Requests permits timeout as the seventh argument after method/url.
        if len(args) < 7:
            kwargs.setdefault("timeout", self.timeout)
        return super().request(method, url, *args, **kwargs)


def new_session(timeout: Optional[Timeout] = None) -> requests.Session:
    """generate a new Session with our hook built in"""
    sess = _TimeoutSession(get_timeout(timeout))
    sess.hooks["response"].insert(0, response_initial_hook)
    sess.headers.update({"User-Agent": USER_AGENT})
    return sess


def process_ari_url(
    sess: requests.Session,
    url: str,
    _print: bool = True,
    *,
    timeout: Optional[Timeout] = None,
) -> Tuple[Optional[Dict], CaseInsensitiveDict]:
    if _print:
        print("=-" * 40)
        print("Requesting ARI")
        print("ari_url:", url)
    r = sess.get(url, timeout=get_timeout(timeout))
    r.raise_for_status()
    _data: Optional[Dict] = r.json()
    _headers: CaseInsensitiveDict = r.headers
    if _print:
        pprint.pprint(_headers)
        print("- " * 10)
        pprint.pprint(_data)
    return (_data, _headers)


def issuer_to_endpoint(
    cert_data: Optional[Mapping[str, Any]] = None,
    sock_data: Optional[Dict] = None,
) -> Optional[str]:
    if (cert_data is None) == (sock_data is None):
        raise ValueError("submit `cert_data` OR `sock_data`")
    if cert_data is not None:
        issuer = cert_data.get("issuer") or ""
        organizations = [
            part[2:] for part in issuer.splitlines() if part.startswith("O=")
        ]
    else:
        assert sock_data is not None
        organizations = [
            value
            for rdn in sock_data.get("issuer", ())
            for key, value in rdn
            if key == "organizationName"
        ]
    if "Let's Encrypt" in organizations:
        return "https://acme-v02.api.letsencrypt.org/directory"
    return None


def ari_query(
    acme_server: str, ari_id: str, *, timeout: Optional[Timeout] = None
) -> Tuple[Optional[Dict], CaseInsensitiveDict]:
    sess = new_session(timeout=timeout)
    try:
        r = sess.get(acme_server)
        r.raise_for_status()
        _renewal_base = r.json().get("renewalInfo")
        if not _renewal_base:
            raise ValueError("endpoint does not support ARI")
        _renewal_base_url = "%s/%s" % (_renewal_base.rstrip("/"), ari_id)
        _d, _h = process_ari_url(sess, _renewal_base_url, _print=True, timeout=timeout)
        return (_d, _h)
    finally:
        sess.close()


def process_filepath(
    filepath: str, *, timeout: Optional[Timeout] = None, check_ari: bool = False
) -> None:
    """Inspect a local certificate; contact ARI only when explicitly requested."""
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

    if not check_ari:
        return

    _ari_id = cert_utils.ari_construct_identifier(cert_pem)
    print("ARI ID: %s" % _ari_id)
    _acme_server = issuer_to_endpoint(cert_data=cert_data)
    if _acme_server and check_ari:
        ari_query(_acme_server, _ari_id, timeout=timeout)
    elif check_ari:
        print("No known ARI endpoint")


def process_url(
    url: str, *, timeout: Optional[Timeout] = None, check_ari: bool = False
) -> Optional[str]:
    """Inspect HTTPS, print its peer certificate PEM, and return it for discovery."""
    print("**" * 40)
    print("**" * 40)
    print("Process URL:")
    print("url: ", url)
    sess = new_session(timeout=timeout)
    try:

        r = sess.get(url)
        if TYPE_CHECKING:
            assert hasattr(r, "_sock_data")

        print("=-" * 40)
        print("Connection Data:")
        pprint.pprint(getattr(r, "_sock_data", None))
        print("=-" * 40)

        sock_data = getattr(r, "_sock_data", None) or {}
        _cert_dict = sock_data.get("cert_dict")
        _cert_pem = sock_data.get("cert_pem")
        if _cert_pem:
            print("Peer certificate PEM:")
            print(_cert_pem, end="" if _cert_pem.endswith("\n") else "\n")
        if _cert_pem and check_ari:
            print("=-" * 40)
            print("Cert Data:")
            _ari_id = cert_utils.ari_construct_identifier(_cert_pem)
            print("ARI ID: %s" % _ari_id)

            _acme_server = issuer_to_endpoint(sock_data=_cert_dict)
            if _acme_server:
                ari_query(_acme_server, _ari_id, timeout=timeout)
            else:
                print("No known ARI endpoint")
        return _cert_pem
    finally:
        sess.close()


def usage(argv: List[str]) -> NoReturn:
    cmd = os.path.basename(argv[0]) if argv else "cert_info"
    print(
        "usage: %s [--timeout CONNECT,READ] < url | filepath >\n"
        '  (example: "%s https://example.com")\n'
        '  (example: "%s /path/to/cert.pem")' % (cmd, cmd, cmd)
    )
    sys.exit(1)


class _VersionAction(argparse.Action):
    """Print diagnostic versions and the invoked entrypoint path to stderr."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        binary = os.path.realpath(shutil.which(parser.prog) or parser.prog)
        print("cert_info library version: %s" % cert_utils.__VERSION__, file=sys.stderr)
        print("Python version: %s" % sys.version.split()[0], file=sys.stderr)
        print("cert_info binary path: %s" % binary, file=sys.stderr)
        parser.exit()


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv
    from cert_utils.utils_discovery import DEFAULT_TTL, discover, installation_root

    parser = argparse.ArgumentParser(prog=argv[0] if argv else "cert_info")
    parser.add_argument(
        "--version",
        action=_VersionAction,
        nargs=0,
        help="Print library/Python versions and binary path to stderr, then exit.",
    )
    parser.add_argument("target")
    parser.add_argument("--timeout", type=parse_timeout, metavar="CONNECT,READ")
    parser.add_argument("--check-ari", action="store_true")
    parser.add_argument(
        "--discover-certbot",
        nargs="?",
        const="exact",
        choices=("exact", "overlap", "all"),
        help="Discover matching Certbot renewal configurations and accounts.",
    )
    parser.add_argument(
        "--certbot-config-directory",
        help="Certbot configuration root (default: /etc/letsencrypt).",
    )
    parser.add_argument(
        "--certbot-managed",
        action="store_true",
        help="Derive the configuration root from a Certbot-managed certificate path.",
    )
    parser.add_argument("--cache-ttl", type=float)
    parser.add_argument("--refresh-cache", action="store_true", default=None)
    parser.add_argument("--no-cache", action="store_true", default=None)
    if len(argv) < 2 or (
        len(argv) > 2 and not any(arg.startswith("--") for arg in argv[1:])
    ):
        usage(argv)
    options = parser.parse_args(argv[1:])

    def environment_bool(name: str, explicit: Optional[bool]) -> bool:
        """Resolve CLI booleans before consulting environment defaults."""
        if explicit is not None:
            return explicit
        value = os.environ.get(name, "false").lower()
        if value not in ("true", "false", "1", "0", "yes", "no", "on", "off"):
            raise ValueError("invalid boolean for " + name)
        return value in ("true", "1", "yes", "on")

    try:
        ttl = (
            options.cache_ttl
            if options.cache_ttl is not None
            else float(os.environ.get("CERT_INFO_CACHE_TTL", str(DEFAULT_TTL)))
        )
        if not math.isfinite(ttl) or ttl < 0:
            raise ValueError("cache TTL must be finite and nonnegative")
        refresh = environment_bool("CERT_INFO_REFRESH_CACHE", options.refresh_cache)
        no_cache = environment_bool("CERT_INFO_NO_CACHE", options.no_cache)
        root = installation_root(
            options.target, options.certbot_managed, options.certbot_config_directory
        )
    except ValueError as error:
        parser.error(str(error))
    kwargs: Dict[str, Any] = {}
    if options.timeout is not None:
        kwargs["timeout"] = options.timeout

    def report_discovery(target: str) -> None:
        """Use the same discovery and reporting for local and fetched certificates."""
        print("Certbot discovery (potential historical account associations):")
        results = discover(
            target,
            root,
            options.discover_certbot,
            ttl,
            refresh,
            no_cache,
        )
        for result in results:
            if result["identical_certificate_paths"]:
                print(
                    "ALERT: byte-identical certificate at another path; associated account is likely the issuing account."
                )
            pprint.pprint(result)
        if not results:
            print("No matching renewal configurations.")

    if options.check_ari:
        kwargs["check_ari"] = True
    if options.target.startswith("http://"):
        raise ValueError("Can not handle `http`!")
    elif options.target.startswith("https://"):
        pem = process_url(options.target, **kwargs)
        if options.discover_certbot:
            if not pem:
                raise ValueError(
                    "HTTPS peer certificate unavailable; cannot perform discovery"
                )
            # Requests' DER-to-PEM conversion uses Certbot-compatible 64-column PEM.
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".pem") as certificate:
                certificate.write(pem)
                certificate.flush()
                report_discovery(certificate.name)
    else:
        process_filepath(options.target, **kwargs)
        if options.discover_certbot:
            report_discovery(options.target)


if __name__ == "__main__":
    main()
