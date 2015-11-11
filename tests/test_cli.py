
from click.testing import CliRunner
from unittest.mock import MagicMock
import yaml
import zign.api
from piu.cli import cli


def test_missing_reason():
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['myuser@somehost.example.org'], catch_exceptions=False)

    assert 'Missing argument "reason"' in result.output


def test_success(monkeypatch):
    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')
    monkeypatch.setattr('zign.api.get_named_token', MagicMock(return_value={'access_token': '123'}))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('keyring.set_password', MagicMock())
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['myuser@127.31.0.1', '--lifetime=15', '--even-url=https://localhost/', '--odd-host=odd.example.org', '--password=foobar', 'my reason'], catch_exceptions=False)

    assert response.text in result.output


def test_bad_request(monkeypatch):
    response = MagicMock(status_code=400, text='**MAGIC-BAD-REQUEST**')
    monkeypatch.setattr('zign.api.get_named_token', MagicMock(return_value={'access_token': '123'}))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('keyring.set_password', MagicMock())
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['req', '--lifetime=15', '--even-url=https://localhost/', '--password=foobar', 'myuser@odd-host', 'my reason'], catch_exceptions=False)

    assert response.text in result.output
    assert 'Server returned status 400:' in result.output


def test_auth_failure(monkeypatch):
    response = MagicMock(status_code=403, text='**MAGIC-AUTH-FAILED**')
    monkeypatch.setattr('zign.api.get_named_token', MagicMock(return_value={'access_token': '123'}))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('keyring.set_password', MagicMock())
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['r', '--even-url=https://localhost/', '--password=invalid', 'myuser@odd-host', 'my reason'], catch_exceptions=False)

    assert response.text in result.output
    assert 'Server returned status 403:' in result.output


def test_dialog(monkeypatch):
    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')
    monkeypatch.setattr('zign.api.get_named_token', MagicMock(return_value={'access_token': '123'}))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    monkeypatch.setattr('socket.getaddrinfo', MagicMock())
    monkeypatch.setattr('keyring.set_password', MagicMock())
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=None))
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file=config.yaml', 'req', 'myuser@172.31.0.1', 'my reason'], catch_exceptions=False, input='even\nodd\npassword\n\n')

    assert result.exit_code == 0
    assert response.text in result.output

def test_oauth_failure(monkeypatch):
    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')
    monkeypatch.setattr('zign.api.get_named_token', MagicMock(side_effect=zign.api.ServerError('**MAGIC-FAIL**')))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    monkeypatch.setattr('socket.getaddrinfo', MagicMock())
    monkeypatch.setattr('keyring.set_password', MagicMock())
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=None))
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file=config.yaml', 'req', 'myuser@172.31.0.1', 'my reason'], catch_exceptions=False, input='even\nodd\npassword\n\n')

    assert result.exit_code == 500
    assert 'Server error: **MAGIC-FAIL**' in result.output
