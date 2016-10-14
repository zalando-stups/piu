
from click.testing import CliRunner
from unittest.mock import MagicMock
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
        result = runner.invoke(cli,
                               ['myuser@127.31.0.1',
                                '--lifetime=15',
                                '--even-url=https://localhost/',
                                '--odd-host=odd.example.org',
                                '--password=foobar',
                                'my reason'],
                               catch_exceptions=False)

    assert response.text in result.output


def test_bad_request(monkeypatch):
    response = MagicMock(status_code=400, text='**MAGIC-BAD-REQUEST**')
    monkeypatch.setattr('zign.api.get_named_token', MagicMock(return_value={'access_token': '123'}))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('keyring.set_password', MagicMock())
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli,
                               ['req',
                                '--lifetime=15',
                                '--even-url=https://localhost/',
                                '--password=foobar',
                                'myuser@odd-host',
                                'my reason'],
                               catch_exceptions=False)

    assert response.text in result.output
    assert 'Server returned status 400:' in result.output


def test_auth_failure(monkeypatch):
    response = MagicMock(status_code=403, text='**MAGIC-AUTH-FAILED**')
    monkeypatch.setattr('zign.api.get_named_token', MagicMock(return_value={'access_token': '123'}))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('keyring.set_password', MagicMock())
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli,
                               ['r',
                                '--even-url=https://localhost/',
                                '--password=invalid',
                                'myuser@odd-host',
                                'my reason'],
                               catch_exceptions=False)

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
        result = runner.invoke(cli, ['--config-file=config.yaml', 'req', 'myuser@172.31.0.1',
                                     'my reason'], catch_exceptions=False, input='even\nodd\npassword\n\n')

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
        result = runner.invoke(cli, ['--config-file=config.yaml', 'req', 'myuser@172.31.0.1',
                                     'my reason'], catch_exceptions=False, input='even\nodd\npassword\n\n')

    assert result.exit_code == 500
    assert 'Server error: **MAGIC-FAIL**' in result.output


def test_login_arg_user(monkeypatch, tmpdir):
    arg_user = 'arg_user'
    zign_user = 'zign_user'
    env_user = 'env_user'

    response = MagicMock()

    runner = CliRunner()

    def mock__request_access(even_url, cacert, username, first_host, reason,
                             remote_host, lifetime, user, password, clip):
        assert arg_user == username

    monkeypatch.setattr('zign.api.get_config', lambda: {'user': zign_user})
    monkeypatch.setattr('os.getenv', lambda x: env_user)
    monkeypatch.setattr('piu.cli._request_access', mock__request_access)
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    with runner.isolated_filesystem():
        runner.invoke(cli, ['request-access', '-U', arg_user], catch_exceptions=False)


def test_login_zign_user(monkeypatch, tmpdir):
    zign_user = 'zign_user'
    env_user = 'env_user'

    response = MagicMock()

    runner = CliRunner()

    def mock__request_access(even_url, cacert, username, first_host, reason,
                             remote_host, lifetime, user, password, clip):
        assert zign_user == username

    monkeypatch.setattr('zign.api.get_config', lambda: {'user': zign_user})
    monkeypatch.setattr('os.getenv', lambda: env_user)
    monkeypatch.setattr('piu.cli._request_access', mock__request_access)
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    with runner.isolated_filesystem():
        runner.invoke(cli, ['request-access'], catch_exceptions=False)


def test_login_env_user(monkeypatch, tmpdir):
    env_user = 'env_user'

    response = MagicMock()

    runner = CliRunner()

    def mock__request_access(even_url, cacert, username, first_host, reason,
                             remote_host, lifetime, user, password, clip):
        assert env_user == username

    monkeypatch.setattr('zign.api.get_config', lambda: {'user': ''})
    monkeypatch.setattr('os.getenv', lambda x: env_user)
    monkeypatch.setattr('piu.cli._request_access', mock__request_access)
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    with runner.isolated_filesystem():
        runner.invoke(cli, ['request-access'], catch_exceptions=False)


def test_interactive_success(monkeypatch):
    ec2 = MagicMock()
    request_access = MagicMock()

    response = []
    response.append(MagicMock(**{'instance_id': 'i-123456',
                                 'private_ip_address': '172.31.10.10',
                                 'tags': [{'Key': 'Name', 'Value': 'stack1-0o1o0'},
                                          {'Key': 'StackVersion', 'Value': '0o1o0'},
                                          {'Key': 'StackName', 'Value': 'stack1'}]
                                 }))
    response.append(MagicMock(**{'instance_id': 'i-789012',
                                 'private_ip_address': '172.31.10.20',
                                 'tags': [{'Key': 'Name', 'Value': 'stack2-0o1o0'},
                                          {'Key': 'StackVersion', 'Value': '0o2o0'},
                                          {'Key': 'StackName', 'Value': 'stack2'}]
                                 }))
    ec2.instances.filter = MagicMock(return_value=response)
    monkeypatch.setattr('boto3.resource', MagicMock(return_value=ec2))
    monkeypatch.setattr('piu.cli._request_access', MagicMock(side_effect=request_access))

    runner = CliRunner()
    input_stream = '\n'.join(['eu-west-1', '1', 'Troubleshooting']) + '\n'

    with runner.isolated_filesystem():
        runner.invoke(cli,
                      ['request-access',
                       '--interactive',
                       '--even-url=https://localhost/',
                       '--odd-host=odd.example.org'],
                      input=input_stream,
                      catch_exceptions=False)

    assert request_access.called


def test_interactive_single_instance_success(monkeypatch):
    ec2 = MagicMock()
    request_access = MagicMock()

    response = []
    response.append(MagicMock(**{'instance_id': 'i-123456',
                                 'private_ip_address': '172.31.10.10',
                                 'tags': [{'Key': 'Name', 'Value': 'stack1-0o1o0'},
                                          {'Key': 'StackVersion', 'Value': '0o1o0'},
                                          {'Key': 'StackName', 'Value': 'stack1'}]
                                 }))
    ec2.instances.filter = MagicMock(return_value=response)
    monkeypatch.setattr('boto3.resource', MagicMock(return_value=ec2))
    monkeypatch.setattr('piu.cli._request_access', MagicMock(side_effect=request_access))

    runner = CliRunner()
    input_stream = '\n'.join(['eu-west-1', '', 'Troubleshooting']) + '\n'

    with runner.isolated_filesystem():
        runner.invoke(cli,
                      ['request-access',
                       '--interactive',
                       '--even-url=https://localhost/',
                       '--odd-host=odd.example.org'],
                      input=input_stream,
                      catch_exceptions=False)

    assert request_access.called


def test_interactive_no_instances_failure(monkeypatch):
    ec2 = MagicMock()
    request_access = MagicMock()

    response = []
    ec2.instances.filter = MagicMock(return_value=response)
    monkeypatch.setattr('boto3.resource', MagicMock(return_value=ec2))
    monkeypatch.setattr('piu.cli._request_access', MagicMock(side_effect=request_access))

    runner = CliRunner()
    input_stream = '\neu-west-1\n'

    with runner.isolated_filesystem():
        result = runner.invoke(cli,
                               ['request-access',
                                '--interactive',
                                '--even-url=https://localhost/',
                                '--odd-host=odd.example.org'],
                               input=input_stream,
                               catch_exceptions=False)

    assert result.exception
    assert 'Error: No running instances were found.' in result.output


def test_tunnel_either_connect_or_tunnel():
    input_stream = '\neu-central-1\n'

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli,
                               ['request-access',
                                '--connect',
                                '--tunnel',
                                'myuser@somehost.example.org',
                                'Testing'],
                               input=input_stream,
                               catch_exceptions=False)
    assert result.exception
    assert 'Cannot specify both "connect" and "tunnel"'


def test_tunnel_should_have_correct_format():

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['request-access', '--tunnel', 'a2345:234a',
                                     'myuser@somehost.example.org', 'Testing'], catch_exceptions=False)
    assert result.exception

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['request-access', '--tunnel', '23434',
                                     'myuser@somehost.example.org', 'Testing'], catch_exceptions=False)
    assert result.exception

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['request-access', '--tunnel', 'a2345:2343',
                                     'myuser@somehost.example.org', 'Testing'], catch_exceptions=False)
    assert result.exception


def test_tunnel_success(monkeypatch):

    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')

    monkeypatch.setattr('zign.api.get_named_token', MagicMock(return_value={'access_token': '123'}))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('subprocess.call', MagicMock())

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['request-access',
                                     '--tunnel', '2380:2379',
                                     '--even-url=https://localhost/',
                                     '--odd-host=odd.example.org',
                                     'myuser@somehost.example.org',
                                     'Testing'],
                               catch_exceptions=False)

    assert response.text in result.output
    assert '-L 2380:somehost.example.org:2379' in result.output
