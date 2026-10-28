from unittest.mock import patch

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
