#!/usr/bin/env python3
"""
Helper script to request access to a certain host.
"""

import boto3
import click
import operator
import ipaddress
import os
import subprocess

import socket
import sys

import sshpubkeys
import yaml
import re

from clickclick import error, AliasedGroup, print_table, warning

from .error_handling import handle_exceptions

import piu
import piu.utils

COMPATIBLE_AMI_CUTOFF = "2020-02-19T12:00:00.000Z"

try:
    import pyperclip
except ImportError:
    pyperclip = None

CONFIG_DIR_PATH = click.get_app_dir("piu")
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, "piu.yaml")

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
DEFAULT_COMMAND = "request-access"

STUPS_CIDR = ipaddress.ip_network("172.31.0.0/16")

STATUS_NAMES = ["REQUESTED", "GRANTED", "DENIED", "FAILED", "EXPIRED", "REVOKED"]

STYLES = {
    "REQUESTED": {"fg": "yellow", "bold": True},
    "GRANTED": {"fg": "green"},
    "DENIED": {"fg": "red", "bold": True},
    "FAILED": {"fg": "red", "bold": True},
    "EXPIRED": {"fg": "yellow", "bold": True},
    "REVOKED": {"fg": "red"},
    "OK": {"fg": "green"},
    "ERROR": {"fg": "red"},
}

TITLES = {"created_time": "Created", "lifetime_minutes": "TTL"}

MAX_COLUMN_WIDTHS = {"reason": 50, "remote_host": 20, "status_reason": 50}

output_option = click.option(
    "-o", "--output", type=click.Choice(["text", "json", "tsv"]), default="text", help="Use alternative output format"
)
region_option = click.option(
    "--region",
    envvar="AWS_DEFAULT_REGION",
    metavar="AWS_REGION_ID",
    default=piu.utils.current_region(),
    help="AWS region ID (e.g. eu-central-1)",
    callback=piu.utils.validate_region,
)
odd_host_option = click.option(
    "-O", "--odd-host", help="Odd SSH bastion hostname", envvar="ODD_HOST", metavar="HOSTNAME"
)


class AliasedDefaultGroup(AliasedGroup):
    def resolve_command(self, ctx, args):
        cmd_name = args[0]
        cmd = AliasedGroup.get_command(self, ctx, cmd_name)
        if not cmd:
            cmd_name = DEFAULT_COMMAND
            cmd = AliasedGroup.get_command(self, ctx, cmd_name)
            new_args = args
        else:
            new_args = args[1:]
        return cmd_name, cmd, new_args


def load_config(path):
    try:
        with open(path, "rb") as fd:
            return yaml.safe_load(fd)
    except Exception:
        return {}


def store_config(config, path):
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, "w") as fd:
        yaml.dump(config, fd)


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo("Piu {}".format(piu.__version__))
    ctx.exit()


def tunnel_validation(ctx, param, value):
    if value and not re.match("^[0-9]{1,5}:[0-9]{1,5}$", value):
        raise click.BadParameter("Tunnel needs to be in format localPort:remotePort")
    else:
        return value


def lookup_instance(region, ip_address):
    filters = [{"Name": "network-interface.addresses.private-ip-address", "Values": [str(ip_address)]}]
    return next(piu.utils.list_running_instances(region, filters), None)


def ssh_keys_added():
    try:
        # ssh-add -l exits with status 1 (and check_call throws) if there are no keys in the SSH agent
        subprocess.check_call(["ssh-add", "-l"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def _request_access(
    ec2, hostname: str, remote_host: str, clip: bool, connect: bool, tunnel: bool, ssh_public_key: str, reason: str
) -> bool:
    host_via = hostname
    click.secho("Requesting access with EIC to host {host_via}".format(host_via=host_via), bold=True)
    if remote_host and not tunnel:
        try:
            remote_attributes = instance_attributes(ec2, "private-ip-address", remote_host)
        except RuntimeError:
            print("Failed to get attributes for instances with private IP address {}".format(remote_host))
            return False
        if not send_ssh_key("ubuntu", remote_attributes, ssh_public_key, reason):
            return False
    ssh_connection(clip, connect, hostname, remote_host, tunnel, "odd", "ubuntu", quick_login=True)
    return True


def ssh_connection(clip, connect, hostname, remote_host, tunnel, odd_user, remote_user, quick_login=False):
    if tunnel:
        ports = tunnel.split(":")
        ssh_command = "ssh {odd_user}@{hostname} -L {local_port}:{remote_host}:{remote_port}".format(
            odd_user=odd_user, hostname=hostname, local_port=ports[0], remote_host=remote_host, remote_port=ports[1]
        )
    else:
        if remote_host:
            ssh_command = "ssh -J {odd_user}@{odd_host} {remote_user}@{remote_host}".format(
                odd_user=odd_user, odd_host=hostname, remote_user=remote_user, remote_host=remote_host
            )
        else:
            ssh_command = "ssh {odd_user}@{odd_host}".format(odd_user=odd_user, odd_host=hostname)
    if connect or tunnel:
        subprocess.call(ssh_command.split())
    elif quick_login:
        click.secho("Please login within the next 60 seconds.")
    if not ssh_keys_added():
        warning("No SSH identities found. Please add one using ssh-add, for example:")
        warning("ssh-add ~/.ssh/id_rsa")
    click.secho("You can access your server with the following command:")
    click.secho(ssh_command)
    if clip:
        click.secho('\nOr just check your clipboard and run ctrl/command + v (requires package "xclip" on Linux)')
        if pyperclip is not None:
            pyperclip.copy(ssh_command)


@click.group(cls=AliasedDefaultGroup, context_settings=CONTEXT_SETTINGS)
@click.option(
    "--config-file", "-c", help="Use alternative configuration file", default=CONFIG_FILE_PATH, metavar="PATH"
)
@click.option(
    "-V",
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Print the current version number and exit.",
)
@click.pass_context
def cli(ctx, config_file):
    ctx.obj = config_file


@cli.command("request-access")
@click.argument("host", metavar="[USER]@HOST", required=False)
@click.argument("reason", required=False)
@click.argument("reason_cont", nargs=-1, metavar="[..]", required=False)
@odd_host_option
@click.option("--interactive", help="Offers assistance", envvar="PIU_INTERACTIVE", is_flag=True, default=False)
@click.option("--clip", help="Copy SSH command into clipboard", is_flag=True, default=False)
@click.option("--connect", help="Directly connect to the host", envvar="PIU_CONNECT", is_flag=True, default=False)
@click.option(
    "--tunnel",
    help="Tunnel to the host",
    envvar="PIU_TUNNEL",
    callback=tunnel_validation,
    metavar="LOCALPORT:REMOTEPORT",
)
@click.option(
    "--check/--no-check",
    help="Verify that the EC2 instance exists and wasn't shutdown",
    envvar="PIU_CHECK_INSTANCE",
    default=True,
)
@click.option(
    "-i",
    "--ssh-public-key",
    help="The public key to use to SSH",
    type=click.Path(),
)
@region_option
@click.pass_obj
def request_access(
    config_file,
    host,
    reason,
    reason_cont,
    odd_host,
    interactive,
    clip,
    connect,
    tunnel,
    region,
    check,
    ssh_public_key,
):
    config = load_config(config_file)
    odd_host = odd_host or piu.utils.find_odd_host(region) or config.get("odd_host")
    ssh_public_key = validate_ssh_key(
        ssh_public_key, config.get("ssh_public_key"), os.path.expanduser("~/.ssh/id_rsa.pub"), interactive
    )

    if interactive:
        host, odd_host, reason, ssh_public_key = request_access_interactive(region, odd_host, ssh_public_key)
    if not host:
        raise click.UsageError('Missing argument "host".')
    if not reason:
        raise click.UsageError('Missing argument "reason".')

    if connect and tunnel:
        raise click.UsageError('Cannot specify both "connect" and "tunnel"')

    parts = host.split("@")
    hostname = parts[-1]

    try:
        ip = ipaddress.ip_address(hostname)

        if check and not interactive and ip in STUPS_CIDR:
            instance = lookup_instance(region, ip)
            if instance is None:
                click.confirm(
                    "No running instances found for {}, do you still want to request access?".format(ip), abort=True
                )
    except ValueError:
        ip = None

    reason = format_reason_message(reason, reason_cont)

    while ip and ip in STUPS_CIDR and not odd_host:
        odd_host = click.prompt("Please enter the Odd SSH bastion hostname")
        try:
            socket.getaddrinfo(odd_host, 22)
        except Exception:
            error("Could not resolve hostname {}".format(odd_host))
            odd_host = None
        config["odd_host"] = odd_host

    while not check_ssh_key(ssh_public_key):
        ssh_public_key = os.path.expanduser(click.prompt("Please enter path of a valid SSH public key"))

    config["ssh_public_key"] = ssh_public_key
    store_config(config, config_file)

    first_host = hostname
    remote_host = hostname
    if odd_host:
        first_host = odd_host

    if first_host == remote_host:
        # user friendly behavior: it makes no sense to jump from bastion to itself
        remote_host = None
    elif remote_host.startswith("odd-"):
        # user friendly behavior: if the remote host is obviously a odd host, just use it
        first_host = remote_host
        remote_host = None

    ec2 = boto3.client("ec2")
    if not send_odd_ssh_key(ec2, first_host, ssh_public_key, reason):
        error("Failed to send SSH key to odd host {host:s}".format(host=first_host))
        sys.exit(1)

    if not _request_access(ec2, first_host, remote_host, clip, connect, tunnel, ssh_public_key, reason):
        sys.exit(1)


def validate_ssh_key(option_path: str, config_path: str, fallback_path: str, interactive: bool) -> str:
    if option_path:
        if check_ssh_key(option_path):
            return option_path
        if not interactive:
            error("specified ssh public key at {0:s} is not a valid key".format(option_path))
            sys.exit(1)
    elif check_ssh_key(config_path):
        return config_path
    elif check_ssh_key(fallback_path):
        return fallback_path
    if not interactive:
        error(
            "No valid SSH public key could be determined. "
            "Please specify one with the -i flag. Consult help for details"
        )
        sys.exit(1)
    return ""


def check_ssh_key(key_path: str) -> bool:
    if key_path and os.path.exists(key_path):
        with open(key_path) as key:
            contents = key.read()
            key = sshpubkeys.SSHKey(contents)
            try:
                key.parse()
            except (sshpubkeys.InvalidKeyError, NotImplementedError) as e:
                return False
        return True
    return False


def send_odd_ssh_key(ec2, odd_hostname: str, public_key: str, reason: str) -> bool:
    odd_ip = socket.gethostbyname(odd_hostname)
    try:
        odd_attributes = instance_attributes(ec2, "ip-address", odd_ip)
    except RuntimeError as e:
        print("Failed to find odd host {0:s} in current account".format(odd_hostname))
        return False
    return send_ssh_key("odd", odd_attributes, public_key, reason)


def send_ssh_key(username: str, host: dict, public_key: str, reason: str) -> bool:
    with open(public_key) as key:
        contents = key.read()
    eic = boto3.client("ec2-instance-connect")

    def add_header(request, **kwargs):
        request.headers.replace_header("User-Agent", "Piu/{} ({})".format(piu.__version__, reason))

    eic.meta.events.register_first("before-sign.ec2-instance-connect.SendSSHPublicKey", add_header)

    result = eic.send_ssh_public_key(
        InstanceId=host["InstanceId"],
        InstanceOSUser=username,
        SSHPublicKey=contents,
        AvailabilityZone=host["Placement"]["AvailabilityZone"],
    )

    return result["Success"]


def request_access_interactive(region, odd_host, ssh_public_key):
    region = click.prompt("AWS region", default=region)
    odd_host = click.prompt("Odd SSH bastion hostname", default=odd_host)

    all_instances = piu.utils.list_running_instances(region, [])

    stack_instances = [
        instance for instance in all_instances if instance.name and instance.stack_name and instance.stack_version
    ]

    instance_count = len(stack_instances)
    if instance_count == 0:
        raise click.ClickException("No running instances were found.")

    stack_instances.sort(key=operator.attrgetter("stack_name", "stack_version"))

    print()
    table_entries = [dict(index=idx, **instance._asdict()) for idx, instance in enumerate(stack_instances, start=1)]
    print_table("index name stack_name stack_version private_ip instance_id".split(), table_entries)
    print()

    if instance_count > 1:
        allowed_choices = ["{}".format(n) for n in range(1, instance_count + 1)]
        instance_index = (
            int(click.prompt("Choose an instance (1-{})".format(instance_count), type=click.Choice(allowed_choices)))
            - 1
        )
    else:
        click.confirm("Connect to {}?".format(stack_instances[0].name), default=True, abort=True)
        instance_index = 0

    host = stack_instances[instance_index].private_ip
    reason = click.prompt("Reason", default="Troubleshooting")
    ssh_public_key = os.path.expanduser(click.prompt("SSH Public Key", default=ssh_public_key))
    return host, odd_host, reason, ssh_public_key


def format_reason_message(first, rest) -> str:
    result = " ".join([first] + list(rest)).strip()
    if len(result) > 1000:
        result = result[:997] + "..."

    # We'll be shoving this into the User-Agent HTTP header, so make sure we don't have anything weird
    return re.sub(r"[^.,; \w]", "?", result).encode("us-ascii", "replace").decode("us-ascii")


def instance_attributes(ec2, filter_name: str, filter_value: str) -> dict:
    instances = ec2.describe_instances(Filters=[{"Name": filter_name, "Values": [filter_value]}])
    if len(instances["Reservations"]) < 1 or len(instances["Reservations"][0]["Instances"]) < 1:
        raise RuntimeError("Failed to find instance with {0:s}: {1:s}".format(filter_name, filter_value))
    return instances["Reservations"][0]["Instances"][0]


def main():
    handle_exceptions(cli)()


if __name__ == "__main__":
    main()
