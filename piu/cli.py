#!/usr/bin/env python3
'''
Helper script to request access to a certain host.
'''

import click
import datetime
import ipaddress
import json
import os
import requests
import socket
import sys
import time
import yaml
import zign.api

from clickclick import error, AliasedGroup, print_table, OutputFormat

import piu

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


def _request_access(even_url, cacert, username, hostname, reason, remote_host, lifetime, user, password, clip):
    data = {'username': username, 'hostname': hostname, 'reason': reason}
    host_via = hostname
    if remote_host:
        data['remote_host'] = remote_host
        host_via = '{} via {}'.format(remote_host, hostname)
    if lifetime:
        data['lifetime_minutes'] = lifetime
    try:
        token = zign.api.get_named_token(['uid'], 'employees', 'piu', user, password, prompt=True)
    except zign.api.ServerError as e:
        click.secho('{}'.format(e), fg='red', bold=True)
        return 500

    access_token = token.get('access_token')
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
        click.secho('You can now access your server with the following command:')
        command = 'ssh -tA {username}@{hostname} {ssh_command}'.format(
                  username=username, hostname=hostname, ssh_command=ssh_command)
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
@click.argument('host', metavar='[USER]@HOST')
@click.argument('reason')
@click.argument('reason_cont', nargs=-1, metavar='[..]')
@click.option('-U', '--user', help='Username to use for OAuth2 authentication', envvar='PIU_USER', metavar='NAME')
@click.option('-p', '--password', help='Password to use for OAuth2 authentication',
              envvar='PIU_PASSWORD', metavar='PWD')
@click.option('-E', '--even-url', help='Even SSH Access Granting Service URL', envvar='EVEN_URL', metavar='URI')
@click.option('-O', '--odd-host', help='Odd SSH bastion hostname', envvar='ODD_HOST', metavar='HOSTNAME')
@click.option('-t', '--lifetime', help='Lifetime of the SSH access request in minutes (default: 60)',
              type=click.IntRange(1, 525600, clamp=True))
@click.option('--insecure', help='Do not verify SSL certificate', is_flag=True, default=False)
@click.option('--clip', is_flag=True, help='Copy SSH command into clipboard', default=False)
@click.pass_obj
def request_access(obj, host, user, password, even_url, odd_host, reason, reason_cont, insecure, lifetime, clip):
    '''Request SSH access to a single host'''

    user = user or os.getenv('USER')

    parts = host.split('@')
    if len(parts) > 1:
        username = parts[0]
    else:
        username = user

    hostname = parts[-1]

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    reason = ' '.join([reason] + list(reason_cont)).strip()

    cacert = not insecure

    config_file = obj
    config = load_config(config_file)

    even_url = even_url or config.get('even_url')
    odd_host = odd_host or config.get('odd_host')
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
                                  user, password, clip)

    if return_code != 200:
        sys.exit(return_code)


@cli.command('list-access-requests')
@click.option('-u', '--user', help='Filter by username', metavar='NAME')
@click.option('-O', '--odd-host', help='Odd SSH bastion hostname (default: my configured odd host)',
              envvar='ODD_HOST', metavar='HOSTNAME', default='MY-ODD-HOST')
@click.option('-s', '--status', help='Filter by status', metavar='NAME', type=click.Choice(STATUS_NAMES))
@click.option('-l', '--limit', help='Limit number of results', type=int, default=20)
@click.option('--offset', help='Offset', type=int, default=0)
@output_option
@click.pass_obj
def list_access_requests(obj, user, odd_host, status, limit, offset, output):
    '''List access requests filtered by user, host and status'''
    config = load_config(obj)

    if user == '*':
        user = None

    if odd_host == '*':
        odd_host = None
    elif odd_host == 'MY-ODD-HOST':
        odd_host = config.get('odd_host')

    token = zign.api.get_existing_token('piu')
    if not token:
        raise click.UsageError('No valid OAuth token named "piu" found.')

    access_token = token.get('access_token')
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
    cli()

if __name__ == '__main__':
    main()
