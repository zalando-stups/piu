#!/usr/bin/env python3
'''
Helper script to request access to a certain host.
'''

import click
import datetime
import operator
import ipaddress
import json
import os
import subprocess
import requests
import socket
import sys
import time
import yaml
import zign.api
import re

from clickclick import error, AliasedGroup, print_table, OutputFormat
from .error_handling import handle_exceptions

import piu
import piu.utils

try:
    import pyperclip
except:
    pyperclip = None


CONFIG_DIR_PATH = click.get_app_dir('piu')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'piu.yaml')

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
DEFAULT_COMMAND = 'request-access'

STUPS_CIDR = ipaddress.ip_network('172.31.0.0/16')

STATUS_NAMES = [
    'REQUESTED',
    'GRANTED',
    'DENIED',
    'FAILED',
    'EXPIRED',
    'REVOKED'
]

STYLES = {
    'REQUESTED': {'fg': 'yellow', 'bold': True},
    'GRANTED': {'fg': 'green'},
    'DENIED': {'fg': 'red', 'bold': True},
    'FAILED': {'fg': 'red', 'bold': True},
    'EXPIRED': {'fg': 'yellow', 'bold': True},
    'REVOKED': {'fg': 'red'},
    'OK': {'fg': 'green'},
    'ERROR': {'fg': 'red'},
    }


TITLES = {
    'created_time': 'Created',
    'lifetime_minutes': 'TTL'
}

MAX_COLUMN_WIDTHS = {
    'reason': 50,
    'remote_host': 20,
    'status_reason': 50
}

output_option = click.option('-o', '--output', type=click.Choice(['text', 'json', 'tsv']), default='text',
                             help='Use alternative output format')
region_option = click.option('--region', envvar='AWS_DEFAULT_REGION', metavar='AWS_REGION_ID',
                             default=piu.utils.current_region(),
                             help='AWS region ID (e.g. eu-central-1)',
                             callback=piu.utils.validate_region)
odd_host_option = click.option('-O', '--odd-host', help='Odd SSH bastion hostname',
                               envvar='ODD_HOST', metavar='HOSTNAME')


def parse_time(s: str) -> float:
    '''
    >>> parse_time('2015-04-14T19:09:01.000Z') > 0
    True
    '''
    try:
        utc = datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%fZ')
        ts = time.time()
        utc_offset = datetime.datetime.fromtimestamp(ts) - datetime.datetime.utcfromtimestamp(ts)
        local = utc + utc_offset
        return local.timestamp()
    except Exception as e:
        print(e)
        return None


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
        with open(path, 'rb') as fd:
            config = yaml.safe_load(fd)
    except:
        config = None
    return config or {}


def store_config(config, path):
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, 'w') as fd:
        yaml.dump(config, fd)


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('Piu {}'.format(piu.__version__))
    ctx.exit()


def tunnel_validation(ctx, param, value):
    if value and not re.match("^[0-9]{1,5}:[0-9]{1,5}$", value):
        raise click.BadParameter('Tunnel needs to be in format localPort:remotePort')
    else:
        return value


def lookup_instance(region, ip_address):
    filters = [{"Name": "network-interface.addresses.private-ip-address",
                "Values": [str(ip_address)]}]
    return next(piu.utils.list_running_instances(region, filters), None)


def _request_access(even_url, cacert, username, hostname, reason, remote_host,
                    lifetime, clip, connect, tunnel):
    data = {'username': username, 'hostname': hostname, 'reason': reason}
    host_via = hostname
    if remote_host:
        data['remote_host'] = remote_host
        host_via = '{} via {}'.format(remote_host, hostname)
    if lifetime:
        data['lifetime_minutes'] = lifetime
    try:
        access_token = zign.api.get_token("piu", ['uid'])
    except zign.api.ServerError as e:
        click.secho('{}'.format(e), fg='red', bold=True)
        return 500

    click.secho('Requesting access to host {host_via} for {username}..'.format(host_via=host_via, username=username),
                bold=True)
    r = requests.post(even_url, headers={'Content-Type': 'application/json',
                                         'Authorization': 'Bearer {}'.format(access_token)},
                      data=json.dumps(data),
                      verify=cacert)
    if r.status_code == 200:
        click.secho(r.text, fg='green', bold=True)
        ssh_command = ''
        if remote_host:
            ssh_command = 'ssh -o StrictHostKeyChecking=no {username}@{remote_host}'.format(**vars())
            if tunnel:
                ports = tunnel.split(':')
                ssh_command = '-L {local_port}:{remote_host}:{remote_port}'.format(
                    local_port=ports[0], remote_host=remote_host, remote_port=ports[1])
        command = 'ssh -tA {username}@{hostname} {ssh_command}'.format(
                  username=username, hostname=hostname, ssh_command=ssh_command)
        if connect or tunnel:
            subprocess.call(command.split())

        click.secho('You can access your server with the following command:')
        click.secho(command)

        if clip:
            click.secho('\nOr just check your clipboard and run ctrl/command + v (requires package "xclip" on Linux)')
            if pyperclip is not None:
                pyperclip.copy(command)
    else:
        click.secho('Server returned status {code}: {text}'.format(code=r.status_code, text=r.text),
                    fg='red', bold=True)
    return r.status_code


@click.group(cls=AliasedDefaultGroup, context_settings=CONTEXT_SETTINGS)
@click.option('--config-file', '-c', help='Use alternative configuration file',
              default=CONFIG_FILE_PATH, metavar='PATH')
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True,
              help='Print the current version number and exit.')
@click.pass_context
def cli(ctx, config_file):
    ctx.obj = config_file


@cli.command('request-access')
@click.argument('host', metavar='[USER]@HOST', required=False)
@click.argument('reason', required=False)
@click.argument('reason_cont', nargs=-1, metavar='[..]', required=False)
@click.option('-E', '--even-url', help='Even SSH Access Granting Service URL', envvar='EVEN_URL', metavar='URI')
@odd_host_option
@click.option('-t', '--lifetime', help='Lifetime of the SSH access request in minutes (default: 60)',
              type=click.IntRange(1, 525600, clamp=True))
@click.option('--interactive', help='Offers assistance', envvar='PIU_INTERACTIVE', is_flag=True, default=False)
@click.option('--insecure', help='Do not verify SSL certificate', is_flag=True, default=False)
@click.option('--clip', help='Copy SSH command into clipboard', is_flag=True, default=False)
@click.option('--connect', help='Directly connect to the host', envvar='PIU_CONNECT', is_flag=True, default=False)
@click.option('--tunnel', help='Tunnel to the host', envvar='PIU_TUNNEL',
              callback=tunnel_validation, metavar='LOCALPORT:REMOTEPORT')
@click.option('--check/--no-check', help='Verify that the EC2 instance exists and wasn\'t shutdown',
              envvar='PIU_CHECK_INSTANCE', default=True)
@region_option
@click.pass_obj
def request_access(config_file, host, reason, reason_cont, even_url, odd_host, lifetime, interactive,
                   insecure, clip, connect, tunnel, region, check):
    '''Request SSH access to a single host'''
    config = load_config(config_file)
    even_url = even_url or config.get('even_url')
    odd_host = odd_host or piu.utils.find_odd_host(region) or config.get('odd_host')

    if interactive:
        host, odd_host, reason = request_access_interactive(region, odd_host)
    if not host:
        raise click.UsageError('Missing argument "host".')
    if not reason:
        raise click.UsageError('Missing argument "reason".')

    if connect and tunnel:
        raise click.UsageError('Cannot specify both "connect" and "tunnel"')

    parts = host.split('@')
    if len(parts) > 1:
        username = parts[0]
    else:
        username = zign.api.get_config().get('user') or os.getenv('USER')

    hostname = parts[-1]

    try:
        ip = ipaddress.ip_address(hostname)

        if check and not interactive and ip in STUPS_CIDR:
            instance = lookup_instance(region, ip)
            if instance is None:
                click.confirm("No running instances found for {}, do you still want to request access?".format(ip),
                              abort=True)
    except ValueError:
        ip = None

    reason = ' '.join([reason] + list(reason_cont)).strip()

    cacert = not insecure
    if 'cacert' in config:
        cacert = config['cacert']

    while not even_url:
        even_url = click.prompt('Please enter the Even SSH access granting service URL')
        if not even_url.startswith('http'):
            # convenience for humans: add HTTPS by default
            even_url = 'https://{}'.format(even_url)
        try:
            requests.get(even_url)
        except:
            error('Could not reach {}'.format(even_url))
            even_url = None
        config['even_url'] = even_url

    while ip and ip in STUPS_CIDR and not odd_host:
        odd_host = click.prompt('Please enter the Odd SSH bastion hostname')
        try:
            socket.getaddrinfo(odd_host, 22)
        except:
            error('Could not resolve hostname {}'.format(odd_host))
            odd_host = None
        config['odd_host'] = odd_host

    store_config(config, config_file)

    if not even_url.endswith('/access-requests'):
        even_url = even_url.rstrip('/') + '/access-requests'

    first_host = hostname
    remote_host = hostname
    if odd_host:
        first_host = odd_host

    if first_host == remote_host:
        # user friendly behavior: it makes no sense to jump from bastion to itself
        remote_host = None
    elif remote_host.startswith('odd-'):
        # user friendly behavior: if the remote host is obviously a odd host, just use it
        first_host = remote_host
        remote_host = None

    return_code = _request_access(even_url, cacert, username, first_host, reason, remote_host, lifetime,
                                  clip, connect, tunnel)

    if return_code != 200:
        sys.exit(return_code)


def request_access_interactive(region, odd_host):
    region = click.prompt('AWS region', default=region)
    odd_host = click.prompt('Odd SSH bastion hostname', default=odd_host)

    all_instances = piu.utils.list_running_instances(region, [])

    stack_instances = [instance for instance in all_instances
                       if instance.name and instance.stack_name and instance.stack_version]

    instance_count = len(stack_instances)
    if instance_count == 0:
        raise click.ClickException('No running instances were found.')

    stack_instances.sort(key=operator.attrgetter('stack_name', 'stack_version'))

    print()
    table_entries = [dict(index=idx, **instance._asdict()) for idx, instance in enumerate(stack_instances, start=1)]
    print_table(
        'index name stack_name stack_version private_ip instance_id'.split(),
        table_entries)
    print()

    if instance_count > 1:
        allowed_choices = ["{}".format(n) for n in range(1, instance_count + 1)]
        instance_index = int(click.prompt('Choose an instance (1-{})'.format(instance_count),
                                          type=click.Choice(allowed_choices))) - 1
    else:
        click.confirm('Connect to {}?'.format(stack_instances[0].name), default=True, abort=True)
        instance_index = 0

    host = stack_instances[instance_index].private_ip
    reason = click.prompt('Reason', default='Troubleshooting')
    return (host, odd_host, reason)


@cli.command('list-access-requests')
@click.option('-u', '--user', help='Filter by username', metavar='NAME')
@odd_host_option
@click.option('-s', '--status', help='Filter by status', metavar='NAME', type=click.Choice(STATUS_NAMES))
@click.option('-l', '--limit', help='Limit number of results', type=int, default=20)
@click.option('--offset', help='Offset', type=int, default=0)
@output_option
@region_option
@click.pass_obj
def list_access_requests(config_file, user, odd_host, status, limit, offset, output, region):
    '''List access requests filtered by user, host and status'''
    config = load_config(config_file)

    if user == '*':
        user = None

    if odd_host == '*':
        odd_host = None
    elif odd_host is None:
        odd_host = piu.utils.find_odd_host(region) or config.get('odd_host')

    access_token = zign.api.get_token('piu', ['piu'])

    params = {'username': user, 'hostname': odd_host, 'status': status, 'limit': limit, 'offset': offset}
    r = requests.get(config.get('even_url').rstrip('/') + '/access-requests',
                     params=params,
                     headers={'Authorization': 'Bearer {}'.format(access_token)})
    r.raise_for_status()
    rows = []
    for req in r.json():
        req['created_time'] = parse_time(req['created'])
        rows.append(req)
    rows.sort(key=lambda x: x['created_time'])
    with OutputFormat(output):
        print_table('username hostname remote_host reason lifetime_minutes status status_reason created_time'.split(),
                    rows, styles=STYLES, titles=TITLES, max_column_widths=MAX_COLUMN_WIDTHS)


def main():
    handle_exceptions(cli)()


if __name__ == '__main__':
    main()
