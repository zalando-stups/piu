from click.testing import CliRunner
from unittest.mock import MagicMock
import zign.api
from piu.cli import cli
import pytest


@pytest.fixture(autouse=True)
def mock_aws(monkeypatch):
    monkeypatch.setattr('piu.utils.current_region', lambda: 'eu-central-1')
    monkeypatch.setattr('piu.utils.find_odd_host', lambda region: None)
    yield


@pytest.fixture(autouse=True)
def prevent_config_overwrite(monkeypatch):
    monkeypatch.setattr('piu.cli.store_config', lambda config, path: None)


def expect_success(args, **kwargs):
    result = CliRunner().invoke(cli, args, **kwargs)
    print(result.output)
    assert result.exit_code == 0
    return result


def test_missing_reason():
    runner = CliRunner()
    result = runner.invoke(cli, ['myuser@somehost.example.org'], catch_exceptions=False)
    assert 'Missing argument "reason"' in result.output


def test_success(monkeypatch):
    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='123'))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))

    result = expect_success(['myuser@127.31.0.1',
                             '--lifetime=15',
                             '--even-url=https://localhost/',
                             '--odd-host=odd.example.org',
                             'my reason'],
                            catch_exceptions=False)

    assert response.text in result.output


def test_bad_request(monkeypatch):
    response = MagicMock(status_code=400, text='**MAGIC-BAD-REQUEST**')
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='123'))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    runner = CliRunner()

    result = runner.invoke(cli,
                           ['req',
                            '--lifetime=15',
                            '--even-url=https://localhost/',
                            'myuser@odd-host',
                            'my reason'],
                           catch_exceptions=False)

    assert response.text in result.output
    assert 'Server returned status 400:' in result.output


def test_auth_failure(monkeypatch):
    response = MagicMock(status_code=403, text='**MAGIC-AUTH-FAILED**')
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='123'))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    runner = CliRunner()

    result = runner.invoke(cli,
                           ['r',
                            '--even-url=https://localhost/',
                            'myuser@odd-host',
                            'my reason'],
                           catch_exceptions=False)

    assert response.text in result.output
    assert 'Server returned status 403:' in result.output


def test_dialog(monkeypatch):
    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='123'))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    monkeypatch.setattr('socket.getaddrinfo', MagicMock())

    result = expect_success(['--config-file=config.yaml', 'req', 'myuser@172.31.0.1',
                             'my reason'], catch_exceptions=False, input='even\nodd\npassword\n\n')
    assert response.text in result.output


def test_oauth_failure(monkeypatch):
    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')
    monkeypatch.setattr('zign.api.get_token', MagicMock(side_effect=zign.api.ServerError('**MAGIC-FAIL**')))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    monkeypatch.setattr('socket.getaddrinfo', MagicMock())
    runner = CliRunner()

    result = runner.invoke(cli, ['--config-file=config.yaml', 'req', 'myuser@172.31.0.1',
                                 'my reason'], catch_exceptions=False, input='even\nodd\npassword\n\n')

    assert result.exit_code == 500
    assert 'Server error: **MAGIC-FAIL**' in result.output


def mock_request_access(monkeypatch, expected_user=None, expected_odd_host=None):
    def mock_fn(even_url, cacert, username, odd_host, reason,
                remote_host, lifetime, user, password, clip):
        if expected_user:
            assert expected_user == username
        if expected_odd_host:
            assert expected_odd_host == odd_host
        return 200

    monkeypatch.setattr('piu.cli._request_access', mock_fn)


def test_bastion_arg_host(monkeypatch):
    monkeypatch.setattr('piu.cli.load_config', lambda _: {"even_url": "https://even.example.org",
                                                          "odd_host": "odd-config.example.org"})

    mock_request_access(monkeypatch, expected_odd_host='odd-arg.example.org')

    expect_success(['request-access', '-O', 'odd-arg.example.org', 'user@host.example.org', 'reason'],
                   catch_exceptions=False)


def test_bastion_autodetect_host(monkeypatch):
    monkeypatch.setattr('piu.utils.find_odd_host', lambda region: "odd-auto.example.org")
    monkeypatch.setattr('piu.cli.load_config', lambda file: {"even_url": "https://even.example.org",
                                                             "odd_host": "odd-config.example.org"})

    mock_request_access(monkeypatch, expected_odd_host='odd-auto.example.org')

    expect_success(['request-access', 'user@host.example.org', 'reason'], catch_exceptions=False)


def test_bastion_config_host(monkeypatch):
    monkeypatch.setattr('piu.cli.load_config', lambda file: {"even_url": "https://even.example.org",
                                                             "odd_host": "odd-config.example.org"})

    mock_request_access(monkeypatch, expected_odd_host='odd-config.example.org')

    expect_success(['request-access', 'user@host.example.org', 'reason'], catch_exceptions=False)


def test_login_zign_user(monkeypatch):
    zign_user = 'zign_user'
    env_user = 'env_user'

    response = MagicMock()

    monkeypatch.setattr('zign.api.get_config', lambda: {'user': zign_user})
    monkeypatch.setattr('piu.cli.load_config', lambda file: {"even_url": "https://even.example.org",
                                                             "odd_host": "odd-config.example.org"})
    monkeypatch.setattr('os.getenv', lambda: env_user)
    mock_request_access(monkeypatch, expected_user=zign_user)
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    expect_success(['request-access', 'host.example.org', 'reason'], catch_exceptions=False)


def test_login_env_user(monkeypatch):
    env_user = 'env_user'

    response = MagicMock()

    monkeypatch.setattr('zign.api.get_config', lambda: {'user': ''})
    monkeypatch.setattr('piu.cli.load_config', lambda file: {"even_url": "https://even.example.org",
                                                             "odd_host": "odd-config.example.org"})
    monkeypatch.setattr('os.getenv', lambda x: env_user)
    mock_request_access(monkeypatch, expected_user=env_user)
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    expect_success(['request-access', 'host.example.org', 'reason'], catch_exceptions=False)


def test_login_arg_user(monkeypatch, tmpdir):
    zign_user = 'zign_user'
    env_user = 'env_user'

    response = MagicMock()

    monkeypatch.setattr('zign.api.get_config', lambda: {'user': zign_user})
    monkeypatch.setattr('piu.cli.load_config', lambda file: {"even_url": "https://even.example.org",
                                                             "odd_host": "odd-config.example.org"})
    monkeypatch.setattr('os.getenv', lambda x: env_user)
    mock_request_access(monkeypatch, expected_user='arg_user')
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    expect_success(['request-access', 'arg_user@host.example.org', 'reason'], catch_exceptions=False)


def test_interactive_success(monkeypatch):
    ec2 = MagicMock()
    request_access = MagicMock(return_value=200)

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
    monkeypatch.setattr('piu.cli._request_access', request_access)

    input_stream = '\n'.join(['eu-west-1', 'odd-eu-west-1.test.example.org', '1', 'Troubleshooting']) + '\n'

    expect_success(['request-access',
                    '--interactive',
                    '--even-url=https://localhost/',
                    '--odd-host=odd.example.org'],
                   input=input_stream,
                   catch_exceptions=False)

    assert request_access.called


def test_interactive_single_instance_success(monkeypatch):
    ec2 = MagicMock()
    request_access = MagicMock(return_value=200)

    response = []
    response.append(MagicMock(**{'instance_id': 'i-123456',
                                 'private_ip_address': '172.31.10.10',
                                 'tags': [{'Key': 'Name', 'Value': 'stack1-0o1o0'},
                                          {'Key': 'StackVersion', 'Value': '0o1o0'},
                                          {'Key': 'StackName', 'Value': 'stack1'}]
                                 }))
    ec2.instances.filter = MagicMock(return_value=response)
    monkeypatch.setattr('boto3.resource', MagicMock(return_value=ec2))
    monkeypatch.setattr('piu.cli._request_access', request_access)

    input_stream = '\n'.join(['eu-west-1', '', 'Troubleshooting']) + '\n'

    expect_success(['request-access',
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
    result = runner.invoke(cli, ['request-access', '--tunnel', 'a2345:234a',
                                 'myuser@somehost.example.org', 'Testing'],
                           catch_exceptions=False)
    assert result.exception

    result = runner.invoke(cli, ['request-access', '--tunnel', '23434',
                                 'myuser@somehost.example.org', 'Testing'],
                           catch_exceptions=False)
    assert result.exception

    result = runner.invoke(cli, ['request-access', '--tunnel', 'a2345:2343',
                                 'myuser@somehost.example.org', 'Testing'],
                           catch_exceptions=False)
    assert result.exception


def test_tunnel_success(monkeypatch):

    response = MagicMock(status_code=200, text='**MAGIC-SUCCESS**')

    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='123'))
    monkeypatch.setattr('requests.post', MagicMock(return_value=response))
    monkeypatch.setattr('subprocess.call', MagicMock())

    result = expect_success(['request-access',
                             '--tunnel', '2380:2379',
                             '--even-url=https://localhost/',
                             '--odd-host=odd.example.org',
                             'myuser@somehost.example.org',
                             'Testing'],
                            catch_exceptions=False)

    assert response.text in result.output
    assert '-L 2380:somehost.example.org:2379' in result.output
