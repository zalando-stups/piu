from os import path
from unittest.mock import MagicMock

from piu.cli import validate_ssh_key, check_ssh_key


def test_validate_ssh_fallback(monkeypatch):
    mock_exit = MagicMock()
    monkeypatch.setattr("sys.exit", mock_exit)
    fallback_path = path.join(path.abspath(path.dirname(__file__)), "resources/id_rsa_fallback.pub")
    final_path = validate_ssh_key("", "", fallback_path, False)
    assert final_path == fallback_path
    mock_exit.assert_not_called()


def test_validate_ssh_valid_input(monkeypatch):
    mock_exit = MagicMock()
    monkeypatch.setattr("sys.exit", mock_exit)
    option_path = path.join(path.abspath(path.dirname(__file__)), "resources/id_rsa_option.pub")
    config_path = path.join(path.abspath(path.dirname(__file__)), "resources/id_rsa_config.pub")
    fallback_path = path.join(path.abspath(path.dirname(__file__)), "resources/id_rsa_fallback.pub")
    final_path = validate_ssh_key(option_path, config_path, fallback_path, False)
    assert final_path == option_path
    mock_exit.assert_not_called()


def test_validate_ssh_valid_config(monkeypatch):
    mock_exit = MagicMock()
    monkeypatch.setattr("sys.exit", mock_exit)
    config_path = path.join(path.abspath(path.dirname(__file__)), "resources/id_rsa_config.pub")
    fallback_path = path.join(path.abspath(path.dirname(__file__)), "resources/id_rsa_fallback.pub")
    final_path = validate_ssh_key("", config_path, fallback_path, False)
    assert final_path == config_path
    mock_exit.assert_not_called()


def test_validate_ssh_valid_error(monkeypatch):
    mock_exit = MagicMock()
    monkeypatch.setattr("sys.exit", mock_exit)
    final_path = validate_ssh_key("", "", "", False)
    assert final_path == ""
    mock_exit.assert_called_with(1)


def test_validate_ssh_valid_no_error_interactive(monkeypatch):
    mock_exit = MagicMock()
    monkeypatch.setattr("sys.exit", mock_exit)
    final_path = validate_ssh_key("", "", "", True)
    assert final_path == ""
    mock_exit.assert_not_called()


def test_malformed_ssh_key(monkeypatch):
    malformed_path = path.join(path.abspath(path.dirname(__file__)), "resources/id_rsa_malformed.pub")
    assert not check_ssh_key(malformed_path)
