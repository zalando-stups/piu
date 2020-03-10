import tempfile

import boto3
from click.testing import CliRunner
from unittest.mock import MagicMock, Mock
import zign.api
from piu.cli import cli, compatible_ami, send_ssh_key, instance_attributes
import piu.utils
import pytest


def mock_list_running_instances(monkeypatch, *instances):
    def mock_fn(region, filter):
        yield from instances

    monkeypatch.setattr("piu.utils.list_running_instances", mock_fn)


@pytest.fixture(autouse=True)
def mock_aws(monkeypatch):
    monkeypatch.setattr("piu.utils.current_region", lambda: "eu-central-1")
    monkeypatch.setattr("piu.utils.find_odd_host", lambda region: None)
    monkeypatch.setattr("piu.cli.instance_attributes", MagicMock(return_value={"ImageId": "test"}))
    monkeypatch.setattr("boto3.client", MagicMock(return_value={}))
    monkeypatch.setattr("piu.cli.compatible_ami", MagicMock(return_value=False))
    monkeypatch.setattr("piu.cli.check_ssh_key", MagicMock(return_value=True))
    monkeypatch.setattr("piu.cli.send_odd_ssh_key", MagicMock(return_value=True))
    mock_list_running_instances(monkeypatch)
    yield


@pytest.fixture(autouse=True)
def prevent_config_overwrite(monkeypatch):
    monkeypatch.setattr("piu.cli.store_config", lambda config, path: None)


def expect_success(args, **kwargs):
    result = CliRunner().invoke(cli, args, **kwargs)
    print(result.output)
    assert result.exit_code == 0
    return result


def test_missing_reason():
    runner = CliRunner()
    result = runner.invoke(cli, ["myuser@somehost.example.org"], catch_exceptions=False)
    assert 'Missing argument "reason"' in result.output


def test_even_success(monkeypatch):
    response = MagicMock(status_code=200, text="**MAGIC-SUCCESS**")
    monkeypatch.setattr("zign.api.get_token", MagicMock(return_value="123"))
    monkeypatch.setattr("requests.post", MagicMock(return_value=response))

    result = expect_success(
        [
            "myuser@172.31.0.1",
            "--lifetime=15",
            "--even-url=https://localhost/",
            "--odd-host=odd.example.org",
            "--no-check",
            "--ssh-public-key=~/.ssh/nonexistent",
            "my reason",
        ],
        catch_exceptions=False,
    )

    assert response.text in result.output


def failed_instance_attributes(_, filter_name, filter_value):
    if filter_name == "private-ip-address":
        raise RuntimeError("something bad")
    return {"ImageId": "abc"}


def test_eic_success(monkeypatch):
    monkeypatch.setattr("zign.api.get_token", MagicMock(return_value="123"))
    monkeypatch.setattr("piu.cli.send_ssh_key", MagicMock(return_value=True))
    monkeypatch.setattr("piu.cli.compatible_ami", MagicMock(return_value=True))
    result = expect_success(
        [
            "myuser@172.31.0.1",
            "--lifetime=15",
            "--even-url=https://localhost/",
            "--odd-host=odd.example.org",
            "--no-check",
            "--ssh-public-key=~/.ssh/nonexistent",
            "my reason",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0


def test_eic_failure(monkeypatch):
    monkeypatch.setattr("zign.api.get_token", MagicMock(return_value="123"))
    monkeypatch.setattr("piu.cli.send_ssh_key", MagicMock(return_value=True))
    monkeypatch.setattr("piu.cli.compatible_ami", MagicMock(return_value=True))
    monkeypatch.setattr("piu.cli.instance_attributes", failed_instance_attributes)
    result = CliRunner().invoke(
        cli,
        [
            "myuser@172.31.0.1",
            "--lifetime=15",
            "--even-url=https://localhost/",
            "--odd-host=odd.example.org",
            "--no-check",
            "--ssh-public-key=~/.ssh/nonexistent",
            "my reason",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1
    assert "Failed to find instance with IP 172.31.0.1" in result.output


def mock_client(success: bool):
    def client(client_type: str):
        if client_type == "ec2-instance-connect":
            mock = MagicMock()
            mock.send_ssh_public_key.return_value = {"Success": success}
            return mock
        return {}

    return client


def test_send_ssh_key_success(monkeypatch):
    ssh_key = tempfile.NamedTemporaryFile()
    monkeypatch.setattr("boto3.client", mock_client(True))
    result = send_ssh_key(
        "test", {"InstanceId": "test-id", "Placement": {"AvailabilityZone": "an-central-10"}}, ssh_key.name
    )
    assert result == True


def test_send_ssh_key_failure(monkeypatch):
    ssh_key = tempfile.NamedTemporaryFile()
    monkeypatch.setattr("boto3.client", mock_client(False))
    result = send_ssh_key(
        "test", {"InstanceId": "test-id", "Placement": {"AvailabilityZone": "an-central-10"}}, ssh_key.name
    )
    assert not result


@pytest.mark.parametrize(
    "address,instance_exists,input,succeeded",
    [
        # Stups IP, instance found => success
        ("172.31.0.11", True, "", True),
        # Stups IP, no instance found, confirmed => success
        ("172.31.0.11", False, "y", True),
        # Stups IP, no instance found, not confirmed => failure
        ("172.31.0.11", False, "n", False),
        # Other IP => success
        ("10.0.1.1", False, None, True),
        # Hostname => success
        ("foo.example.org", False, None, True),
    ],
)
def test_instance_check(monkeypatch, address, instance_exists, input, succeeded):
    success_text = "**MAGIC-SUCCESS**"
    request = MagicMock(return_value=MagicMock(status_code=200, text=success_text))
    monkeypatch.setattr("zign.api.get_token", MagicMock(return_value="123"))
    monkeypatch.setattr("requests.post", request)

    if instance_exists:
        mock_list_running_instances(
            monkeypatch, piu.utils.Instance("i-123456", "stack1-0o1o0", "stack2", "0o1o0", address)
        )

    result = CliRunner().invoke(
        cli,
        [
            "myuser@{}".format(address),
            "--lifetime=15",
            "--even-url=https://localhost/",
            "--odd-host=odd.example.org",
            "--ssh-public-key=~/.ssh/nonexistent",
            "my reason",
        ],
        input=input,
        catch_exceptions=False,
    )

    if succeeded:
        assert request.called
        assert result.exit_code == 0
        assert success_text in result.output
    else:
        assert not request.called
        assert result.exit_code != 0
        assert success_text not in result.output


def test_bad_request(monkeypatch):
    response = MagicMock(status_code=400, text="**MAGIC-BAD-REQUEST**")
    monkeypatch.setattr("zign.api.get_token", MagicMock(return_value="123"))
    monkeypatch.setattr("requests.post", MagicMock(return_value=response))
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "req",
            "--lifetime=15",
            "--even-url=https://localhost/",
            "--ssh-public-key=~/.ssh/nonexistent",
            "-O",
            "odd-host",
            "192.168.1.1",
            "my reason",
        ],
        catch_exceptions=False,
    )

    assert response.text in result.output
    assert "Server returned status 400:" in result.output


def test_auth_failure(monkeypatch):
    response = MagicMock(status_code=403, text="**MAGIC-AUTH-FAILED**")
    monkeypatch.setattr("zign.api.get_token", MagicMock(return_value="123"))
    monkeypatch.setattr("requests.post", MagicMock(return_value=response))
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "r",
            "--even-url=https://localhost/",
            "-O",
            "myuser@odd-host",
            "--ssh-public-key=~/.ssh/nonexistent",
            "test-host",
            "my reason",
        ],
        catch_exceptions=False,
    )

    assert response.text in result.output
    assert "Server returned status 403:" in result.output


def test_send_odd_failure(monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr("piu.cli.instance_attributes", MagicMock(return_value={"ImageId": "test"}))
    monkeypatch.setattr("boto3.client", MagicMock(return_value={}))
    monkeypatch.setattr("piu.cli.compatible_ami", MagicMock(return_value=True))
    monkeypatch.setattr("piu.cli.send_odd_ssh_key", MagicMock(return_value=False))
    result = runner.invoke(
        cli,
        [
            "r",
            "--even-url=https://localhost/",
            "-O",
            "myuser@odd-host",
            "--ssh-public-key=~/.ssh/nonexistent",
            "test-host",
            "my reason",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1
    assert "Failed to send SSH key to odd host myuser@odd-host" in result.output


def test_dialog(monkeypatch):
    response = MagicMock(status_code=200, text="**MAGIC-SUCCESS**")
    monkeypatch.setattr("zign.api.get_token", MagicMock(return_value="123"))
    monkeypatch.setattr("requests.post", MagicMock(return_value=response))
    monkeypatch.setattr("requests.get", MagicMock(return_value=response))
    monkeypatch.setattr("socket.getaddrinfo", MagicMock())

    result = expect_success(
        [
            "--config-file=config.yaml",
            "req",
            "myuser@172.31.0.1",
            "--ssh-public-key=~/.ssh/nonexistent",
            "--no-check",
            "my reason",
        ],
        catch_exceptions=False,
        input="even\nodd\npassword\n\n",
    )
    assert response.text in result.output


def test_oauth_failure(monkeypatch):
    response = MagicMock(status_code=200, text="**MAGIC-SUCCESS**")
    monkeypatch.setattr("zign.api.get_token", MagicMock(side_effect=zign.api.ServerError("**MAGIC-FAIL**")))
    monkeypatch.setattr("requests.post", MagicMock(return_value=response))
    monkeypatch.setattr("requests.get", MagicMock(return_value=response))
    monkeypatch.setattr("socket.getaddrinfo", MagicMock())
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "--config-file=config.yaml",
            "req",
            "myuser@172.31.0.1",
            "--ssh-public-key=~/.ssh/nonexistent",
            "--no-check",
            "my reason",
        ],
        catch_exceptions=False,
        input="even\nodd\npassword\n\n",
    )

    assert result.exit_code == 1
    assert "Server error: **MAGIC-FAIL**" in result.output


def mock_request_access(monkeypatch, expected_user=None, expected_odd_host=None):
    def mock_fn(even_url, cacert, username, odd_host, reason, remote_host, lifetime, user, password, clip):
        if expected_user:
            assert expected_user == username
        if expected_odd_host:
            assert expected_odd_host == odd_host
        return 200

    monkeypatch.setattr("piu.cli._request_even_access", mock_fn)


def test_bastion_arg_host(monkeypatch):
    monkeypatch.setattr(
        "piu.cli.load_config", lambda _: {"even_url": "https://even.example.org", "odd_host": "odd-config.example.org"}
    )

    mock_request_access(monkeypatch, expected_odd_host="odd-arg.example.org")

    expect_success(
        [
            "request-access",
            "-O",
            "odd-arg.example.org",
            "--ssh-public-key=~/.ssh/nonexistent",
            "user@host.example.org",
            "reason",
        ],
        catch_exceptions=False,
    )


def test_bastion_autodetect_host(monkeypatch):
    monkeypatch.setattr("piu.utils.find_odd_host", lambda region: "odd-auto.example.org")
    monkeypatch.setattr(
        "piu.cli.load_config",
        lambda file: {"even_url": "https://even.example.org", "odd_host": "odd-config.example.org"},
    )

    mock_request_access(monkeypatch, expected_odd_host="odd-auto.example.org")

    expect_success(
        ["request-access", "--ssh-public-key=~/.ssh/nonexistent", "user@host.example.org", "reason"],
        catch_exceptions=False,
    )


def test_bastion_config_host(monkeypatch):
    monkeypatch.setattr(
        "piu.cli.load_config",
        lambda file: {"even_url": "https://even.example.org", "odd_host": "odd-config.example.org"},
    )

    mock_request_access(monkeypatch, expected_odd_host="odd-config.example.org")

    expect_success(["request-access", "user@host.example.org", "reason"], catch_exceptions=False)


def test_login_zign_user(monkeypatch):
    zign_user = "zign_user"
    env_user = "env_user"

    response = MagicMock()

    monkeypatch.setattr("zign.api.get_config", lambda: {"user": zign_user})
    monkeypatch.setattr(
        "piu.cli.load_config",
        lambda file: {"even_url": "https://even.example.org", "odd_host": "odd-config.example.org"},
    )
    monkeypatch.setattr("os.getenv", lambda: env_user)
    mock_request_access(monkeypatch, expected_user=zign_user)
    monkeypatch.setattr("requests.get", lambda x, timeout: response)

    expect_success(["request-access", "host.example.org", "reason"], catch_exceptions=False)


def test_login_env_user(monkeypatch):
    env_user = "env_user"

    response = MagicMock()

    monkeypatch.setattr("zign.api.get_config", lambda: {"user": ""})
    monkeypatch.setattr(
        "piu.cli.load_config",
        lambda file: {"even_url": "https://even.example.org", "odd_host": "odd-config.example.org"},
    )
    monkeypatch.setattr("os.getenv", lambda x: env_user)
    mock_request_access(monkeypatch, expected_user=env_user)
    monkeypatch.setattr("requests.get", lambda x, timeout: response)

    expect_success(["request-access", "host.example.org", "reason"], catch_exceptions=False)


def test_login_arg_user(monkeypatch, tmpdir):
    zign_user = "zign_user"
    env_user = "env_user"

    response = MagicMock()

    monkeypatch.setattr("zign.api.get_config", lambda: {"user": zign_user})
    monkeypatch.setattr(
        "piu.cli.load_config",
        lambda file: {"even_url": "https://even.example.org", "odd_host": "odd-config.example.org"},
    )
    monkeypatch.setattr("os.getenv", lambda x: env_user)
    mock_request_access(monkeypatch, expected_user="arg_user")
    monkeypatch.setattr("requests.get", lambda x, timeout: response)

    expect_success(["request-access", "arg_user@host.example.org", "reason"], catch_exceptions=False)


def test_interactive_success(monkeypatch):
    ec2 = MagicMock()
    request_access = MagicMock(return_value=200)

    instances = [
        piu.utils.Instance("i-123456", "stack1-0o1o0", "stack2", "0o1o0", "172.31.10.10"),
        piu.utils.Instance("i-789012", "stack1-0o1o0", "stack2", "0o2o0", "172.31.10.20"),
    ]

    mock_list_running_instances(monkeypatch, *instances)
    monkeypatch.setattr("boto3.resource", MagicMock(return_value=ec2))
    monkeypatch.setattr("piu.cli._request_even_access", request_access)

    input_stream = "\n".join(["eu-west-1", "odd-eu-west-1.test.example.org", "1", "Troubleshooting"]) + "\n"

    expect_success(
        ["request-access", "--interactive", "--even-url=https://localhost/", "--odd-host=odd.example.org"],
        input=input_stream,
        catch_exceptions=False,
    )

    assert request_access.called


def test_interactive_single_instance_success(monkeypatch):
    ec2 = MagicMock()
    request_access = MagicMock(return_value=200)

    instance = piu.utils.Instance("i-123456", "stack1-0o1o0", "stack1", "0o1o0", "172.31.10.10")
    mock_list_running_instances(monkeypatch, instance)
    monkeypatch.setattr("boto3.resource", MagicMock(return_value=ec2))
    monkeypatch.setattr("piu.cli._request_even_access", request_access)

    input_stream = "\n".join(["eu-west-1", "", "Troubleshooting"]) + "\n"

    expect_success(
        ["request-access", "--interactive", "--even-url=https://localhost/", "--odd-host=odd.example.org"],
        input=input_stream,
        catch_exceptions=False,
    )

    assert request_access.called


def test_interactive_no_instances_failure(monkeypatch):
    ec2 = MagicMock()
    request_access = MagicMock()

    response = []
    ec2.instances.filter = MagicMock(return_value=response)
    monkeypatch.setattr("boto3.resource", MagicMock(return_value=ec2))
    monkeypatch.setattr("piu.cli._request_even_access", MagicMock(side_effect=request_access))

    runner = CliRunner()
    input_stream = "\neu-west-1\n"

    result = runner.invoke(
        cli,
        ["request-access", "--interactive", "--even-url=https://localhost/", "--odd-host=odd.example.org"],
        input=input_stream,
        catch_exceptions=False,
    )

    assert result.exception
    assert "Error: No running instances were found." in result.output


def test_tunnel_either_connect_or_tunnel():
    input_stream = "\neu-central-1\n"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["request-access", "--connect", "--tunnel", "myuser@somehost.example.org", "Testing"],
        input=input_stream,
        catch_exceptions=False,
    )
    assert result.exception
    assert 'Cannot specify both "connect" and "tunnel"'


def test_tunnel_should_have_correct_format():

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["request-access", "--tunnel", "a2345:234a", "myuser@somehost.example.org", "Testing"],
        catch_exceptions=False,
    )
    assert result.exception

    result = runner.invoke(
        cli, ["request-access", "--tunnel", "23434", "myuser@somehost.example.org", "Testing"], catch_exceptions=False
    )
    assert result.exception

    result = runner.invoke(
        cli,
        ["request-access", "--tunnel", "a2345:2343", "myuser@somehost.example.org", "Testing"],
        catch_exceptions=False,
    )
    assert result.exception


def test_tunnel_success(monkeypatch):

    response = MagicMock(status_code=200, text="**MAGIC-SUCCESS**")

    monkeypatch.setattr("zign.api.get_token", MagicMock(return_value="123"))
    monkeypatch.setattr("requests.post", MagicMock(return_value=response))
    monkeypatch.setattr("subprocess.call", MagicMock())

    result = expect_success(
        [
            "request-access",
            "--tunnel",
            "2380:2379",
            "--even-url=https://localhost/",
            "--odd-host=odd.example.org",
            "myuser@somehost.example.org",
            "Testing",
        ],
        catch_exceptions=False,
    )

    assert response.text in result.output
    assert "-L 2380:somehost.example.org:2379" in result.output


def test_compatible_ami_success(monkeypatch):
    ec2mock = MagicMock()
    ec2mock.describe_images.return_value = {"Images": [{"CreationDate": "2028-02-05T19:39:50.000Z"}]}
    assert compatible_ami(ec2mock, ami_id="abc")


def test_incompatible_ami_success(monkeypatch):
    ec2mock = MagicMock()
    ec2mock.describe_images.return_value = {"Images": [{"CreationDate": "2018-02-05T19:39:50.000Z"}]}
    assert not compatible_ami(ec2mock, ami_id="abc")


def test_instance_attributes_success(monkeypatch):
    ec2 = MagicMock()
    attributes = {"abc": "test"}
    ec2.describe_instances.return_value = {"Reservations": [{"Instances": [attributes]}]}
    t = instance_attributes(ec2, "test-filter", "test-value")
    assert t == attributes
    ec2.describe_instances.assert_called_with(Filters=[{"Name": "test-filter", "Values": ["test-value"]}])


def test_instance_attributes_success(monkeypatch):
    ec2 = MagicMock()
    ec2.describe_instances.side_effect = Exception("random exception")
    with pytest.raises(Exception):
        instance_attributes(ec2, "test-filter", "test-value")
