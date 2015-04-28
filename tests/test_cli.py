
from click.testing import CliRunner
from mock import MagicMock
import yaml
from piu.cli import cli


def test_missing_reason():
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['myuser@somehost.example.org'], catch_exceptions=False)

    assert 'Missing argument "reason"' in result.output


def test_success(monkeypatch):
    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('keyring.set_password', MagicMock())
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--lifetime=15', '--even-url=https://localhost/', '--odd-host=odd.example.org', '--password=foobar', 'myuser@127.31.0.1', 'my reason'], catch_exceptions=False)

    assert response.text in result.output


def test_dialog(monkeypatch):
    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    monkeypatch.setattr('socket.getaddrinfo', MagicMock())
    monkeypatch.setattr('keyring.set_password', MagicMock())
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=None))
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file=config.yaml', 'myuser@172.31.0.1', 'my reason'], catch_exceptions=False, input='even\nodd\npassword\n\n')

    assert response.text in result.output

