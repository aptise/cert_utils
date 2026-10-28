import json
import runpy
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock
from unittest.mock import patch

import pytest
import requests

from cert_utils.scripts import cert_info


def test_explicit_argv_selects_target():
    with patch.object(cert_info.sys, "argv", ["cert_info", "wrong.pem"]):
        with patch.object(cert_info, "process_filepath") as process:
            cert_info.main(["cert_info", "chosen.pem"])
    process.assert_called_once_with("chosen.pem")


def test_default_argv_selects_target():
    with patch.object(cert_info.sys, "argv", ["cert_info", "default.pem"]):
        with patch.object(cert_info, "process_filepath") as process:
            cert_info.main()
    process.assert_called_once_with("default.pem")


@pytest.mark.parametrize("args", [[], ["cert_info"], ["cert_info", "a", "b"]])
def test_usage(args, capsys):
    with pytest.raises(SystemExit) as error:
        cert_info.main(args)
    assert error.value.code == 1
    assert "usage:" in capsys.readouterr().out


def test_url_dispatch_and_http_rejection():
    with patch.object(cert_info, "process_url") as process:
        cert_info.main(["cert_info", "https://example.com"])
    process.assert_called_once_with("https://example.com")
    with pytest.raises(ValueError):
        cert_info.main(["cert_info", "http://example.com"])


def test_module_entry_point_uses_arguments():
    with patch.object(
        cert_info.sys, "argv", ["cert_info", "http://example.com"]
    ):
        with pytest.raises(ValueError):
            runpy.run_path(cert_info.__file__, run_name="__main__")


@pytest.mark.parametrize("position", range(1, 6))
@pytest.mark.parametrize("tls", [False, True])
def test_socket_layouts_and_cache(position, tls):
    sock = Mock()
    sock.getpeername.return_value = ("127.0.0.1", 443)
    if tls:
        sock.getpeercert.side_effect = lambda binary_form=False: (
            b"der" if binary_form else {"issuer": ()}
        )
    else:
        sock.getpeercert.side_effect = AttributeError
    paths = {
        1: {"_connection": SimpleNamespace(sock=sock)},
        2: {"_connection": SimpleNamespace(sock=SimpleNamespace(socket=sock))},
        3: {"_fp": SimpleNamespace(fp=SimpleNamespace(_sock=sock))},
        4: {
            "_fp": SimpleNamespace(
                fp=SimpleNamespace(_sock=SimpleNamespace(socket=sock))
            )
        },
        5: {
            "_fp": SimpleNamespace(
                fp=SimpleNamespace(raw=SimpleNamespace(_sock=sock))
            )
        },
    }
    resp: Any = requests.Response()
    resp.raw = SimpleNamespace(**paths[position])
    with patch.object(cert_info, "_compatible_sockets", (type(sock),)):
        with patch.object(
            cert_info.cert_utils, "convert_der_to_pem", return_value="pem"
        ):
            data = cert_info.get_response_data(resp)
    assert data is not None
    assert data["peername"] == ("127.0.0.1", 443)
    assert data.get("cert_pem") == ("pem" if tls else None)
    assert cert_info.get_response_data(resp) is data
    sock.getpeername.assert_called_once()


def test_missing_socket_and_non_response():
    assert cert_info.get_response_data(Mock()) is None
    resp: Any = requests.Response()
    resp.raw = SimpleNamespace()
    assert cert_info.get_response_data(resp) is None
    assert cert_info.get_response_data(resp) is None


def test_session_hook_and_agent():
    with patch.object(cert_info, "get_response_data") as get_data:
        response = requests.Response()
        cert_info.response_initial_hook(response, unused=True)
    get_data.assert_called_once_with(response)

    with cert_info.new_session() as session:
        assert session.headers["User-Agent"] == cert_info.USER_AGENT
        assert session.hooks["response"][0] is cert_info.response_initial_hook


@pytest.mark.parametrize("issuer", [None, "CN=example", "O=Unknown", ""])
def test_unknown_certificate_issuer(issuer):
    assert cert_info.issuer_to_endpoint(cert_data={"issuer": issuer}) is None


@pytest.mark.parametrize("socket_data", [False, True])
def test_issuer_organization_can_appear_anywhere(socket_data):
    if socket_data:
        data = {"issuer": ((("organizationName", "Let's Encrypt"),),)}
        result = cert_info.issuer_to_endpoint(sock_data=data)
    else:
        result = cert_info.issuer_to_endpoint(
            cert_data={"issuer": "O=Let's Encrypt\nCN=issuer"}
        )
    assert result == "https://acme-v02.api.letsencrypt.org/directory"


def test_issuer_argument_validation():
    with pytest.raises(ValueError):
        cert_info.issuer_to_endpoint()
    with pytest.raises(ValueError):
        cert_info.issuer_to_endpoint(cert_data={}, sock_data={})
    assert cert_info.issuer_to_endpoint(sock_data={}) is None


def response_json(data):
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps(data).encode()
    return response


@pytest.mark.parametrize("printing", [False, True])
def test_ari_response(printing, capsys):
    session = Mock()
    response = response_json({"suggestedWindow": {}})
    session.get.return_value = response
    assert cert_info.process_ari_url(session, "https://ari", printing) == (
        {"suggestedWindow": {}},
        response.headers,
    )
    assert bool(capsys.readouterr().out) == printing


def test_ari_directory_and_unsupported_endpoint():
    session = Mock()
    session.get.side_effect = [
        response_json({"renewalInfo": "https://ari/"}),
        response_json({"window": 1}),
    ]
    with patch.object(cert_info, "new_session", return_value=session):
        assert cert_info.ari_query("https://directory", "id")[0] == {
            "window": 1
        }
    assert session.get.call_args_list[-1][0] == ("https://ari/id",)
    session.get.side_effect = None
    session.get.return_value = response_json({})
    with patch.object(cert_info, "new_session", return_value=session):
        with pytest.raises(ValueError, match="does not support"):
            cert_info.ari_query("https://directory", "id")


@pytest.mark.parametrize("endpoint", [None, "https://directory"])
def test_file_processing(tmp_path, endpoint, capsys):
    path = tmp_path / "certificate.pem"
    path.write_text("pem")
    with patch.object(
        cert_info.cert_utils, "parse_cert", return_value={}
    ) as parse:
        with patch.object(
            cert_info.cert_utils, "ari_construct_identifier", return_value="id"
        ):
            with patch.object(
                cert_info, "issuer_to_endpoint", return_value=endpoint
            ):
                with patch.object(cert_info, "ari_query") as query:
                    cert_info.process_filepath(str(path))
    parse.assert_called_once_with(cert_pem="pem", cert_pem_filepath=str(path))
    assert query.call_count == bool(endpoint)
    assert "ARI ID: id" in capsys.readouterr().out
    with pytest.raises(ValueError, match="invalid filepath"):
        cert_info.process_filepath(str(tmp_path / "missing"))


@pytest.mark.parametrize(
    "data", [None, {}, {"cert_pem": "pem", "cert_dict": {}}]
)
@pytest.mark.parametrize("endpoint", [None, "https://directory"])
def test_url_processing_handles_missing_peer(data, endpoint):
    session = Mock()
    session.get.return_value._sock_data = data
    with patch.object(cert_info, "new_session", return_value=session):
        with patch.object(
            cert_info.cert_utils, "ari_construct_identifier", return_value="id"
        ):
            with patch.object(
                cert_info, "issuer_to_endpoint", return_value=endpoint
            ):
                with patch.object(cert_info, "ari_query") as query:
                    cert_info.process_url("https://example.com")
    assert query.call_count == bool(data and endpoint)


def test_empty_der_certificate_is_not_converted():
    sock = Mock()
    sock.getpeername.return_value = ("127.0.0.1", 443)
    sock.getpeercert.side_effect = [{}, None]
    resp: Any = requests.Response()
    resp.raw = SimpleNamespace(_connection=SimpleNamespace(sock=sock))
    with patch.object(cert_info, "_compatible_sockets", (type(sock),)):
        with patch.object(
            cert_info.cert_utils, "convert_der_to_pem"
        ) as convert:
            data = cert_info.get_response_data(resp)
    assert data == {"peername": ("127.0.0.1", 443), "cert_dict": {}}
    convert.assert_not_called()


@pytest.mark.parametrize("directory", [False, True])
def test_ari_http_errors_are_not_treated_as_data(directory):
    session = Mock()
    response = requests.Response()
    response.status_code = 503
    session.get.return_value = response
    with pytest.raises(requests.HTTPError):
        if directory:
            with patch.object(cert_info, "new_session", return_value=session):
                cert_info.ari_query("https://directory", "id")
        else:
            cert_info.process_ari_url(session, "https://ari")


def test_timeout_default_environment_and_explicit_override(monkeypatch):
    monkeypatch.delenv("CERT_UTILS_TIMEOUT", raising=False)
    for override, expected in [(None, (5.0, 30.0)), ((2.0, 4.0), (2.0, 4.0))]:
        with cert_info.new_session(override) as session:
            with patch.object(
                requests.Session, "request", return_value=requests.Response()
            ) as request:
                session.get("https://example.com")
            assert request.call_args[1]["timeout"] == expected
    monkeypatch.setenv("CERT_UTILS_TIMEOUT", "1.5,9")
    with cert_info.new_session() as session:
        with patch.object(
            requests.Session, "request", return_value=requests.Response()
        ) as request:
            session.get("https://example.com")
        assert request.call_args[1]["timeout"] == (1.5, 9.0)
    monkeypatch.setenv("CERT_UTILS_TIMEOUT", "invalid")
    with cert_info.new_session((2.0, 3.0)) as session:
        with patch.object(
            requests.Session, "request", return_value=requests.Response()
        ) as request:
            session.get("https://example.com", timeout=(7.0, 8.0))
        assert request.call_args[1]["timeout"] == (7.0, 8.0)


@pytest.mark.parametrize(
    "value", ["1", "1,2,3", "x,2", "0,1", "-1,2", "nan,2", "1,inf", ""]
)
def test_invalid_timeout_environment(monkeypatch, value):
    monkeypatch.setenv("CERT_UTILS_TIMEOUT", value)
    with pytest.raises(ValueError, match="timeout"):
        cert_info.new_session()


def test_timeout_cli_override(monkeypatch):
    monkeypatch.setenv("CERT_UTILS_TIMEOUT", "invalid")
    with patch.object(cert_info, "process_url") as process:
        cert_info.main(
            ["cert_info", "--timeout", "2,8", "https://example.com"]
        )
    process.assert_called_once_with("https://example.com", timeout=(2.0, 8.0))
    with patch.object(cert_info, "process_filepath") as process:
        cert_info.main(["cert_info", "file.pem", "--timeout=2,8"])
    process.assert_called_once_with("file.pem", timeout=(2.0, 8.0))
    with pytest.raises(SystemExit):
        cert_info.main(["cert_info", "--timeout", "nan,0", "file.pem"])


@pytest.mark.parametrize("operation", ["url", "ari"])
@pytest.mark.parametrize("fails", [False, True])
def test_owned_sessions_close(operation, fails):
    session = Mock()
    if fails:
        session.get.side_effect = requests.Timeout("stalled")
    elif operation == "ari":
        session.get.side_effect = [
            response_json({"renewalInfo": "https://ari"}),
            response_json({}),
        ]
    else:
        session.get.return_value._sock_data = None
    with patch.object(cert_info, "new_session", return_value=session):
        if fails:
            with pytest.raises(requests.Timeout):
                if operation == "ari":
                    cert_info.ari_query("https://directory", "id")
                else:
                    cert_info.process_url("https://example.com")
        elif operation == "ari":
            cert_info.ari_query("https://directory", "id")
        else:
            cert_info.process_url("https://example.com")
    session.close.assert_called_once_with()


def test_borrowed_session_stays_open_and_receives_timeout():
    session = Mock()
    session.get.return_value = response_json({})
    cert_info.process_ari_url(session, "https://ari", timeout=(2.0, 6.0))
    session.get.assert_called_once_with("https://ari", timeout=(2.0, 6.0))
    session.close.assert_not_called()


def test_positional_request_timeout_is_preserved():
    with cert_info.new_session((1.0, 2.0)) as session:
        with patch.object(
            requests.Session, "request", return_value=requests.Response()
        ) as request:
            session.request(
                "GET",
                "https://example.com",
                None,
                None,
                None,
                None,
                None,
                None,
                (7.0, 8.0),
            )
    assert request.call_args[0][-1] == (7.0, 8.0)
    assert "timeout" not in request.call_args[1]


def test_directory_timeout_propagates_to_ari_despite_invalid_env(monkeypatch):
    monkeypatch.setenv("CERT_UTILS_TIMEOUT", "invalid")
    session = Mock()
    session.get.side_effect = [
        response_json({"renewalInfo": "https://ari"}),
        response_json({}),
    ]
    with patch.object(cert_info, "new_session", return_value=session):
        cert_info.ari_query("https://directory", "id", timeout=(3.0, 4.0))
    assert session.get.call_args[1]["timeout"] == (3.0, 4.0)


def test_certificate_download_timeout(monkeypatch):
    from cert_utils.letsencrypt_info import certificates as letsencrypt_info

    monkeypatch.setenv("CERT_UTILS_TIMEOUT", "2,9")
    monkeypatch.setattr(
        letsencrypt_info,
        "CERT_CAS_DATA",
        {"fixture": {"url_pem": "https://certificate"}},
    )
    response = Mock(status_code=200, text="pem")
    with patch.object(requests, "get", return_value=response) as get:
        with patch.object(
            letsencrypt_info, "cleanup_pem_text", return_value="pem"
        ):
            letsencrypt_info.download_letsencrypt_certificates()
            assert get.call_args[1]["timeout"] == (2.0, 9.0)
            letsencrypt_info.download_letsencrypt_certificates(timeout=(1, 3))
            assert get.call_args[1]["timeout"] == (1.0, 3.0)
