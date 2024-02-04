#!/usr/bin/env python3
import argparse
import asyncio
import os
import os.path as osp
import sys
import typing as TYPE
import uuid
from logging import getLogger
from pathlib import Path
from time import sleep

from logfunc import logf

from . import config
from . import msgs as MSGS
from .main import Open2FA
from .utils import sec_trunc

logger = getLogger(__name__)
logger.setLevel('INFO')


@logf()
def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.
    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="open2fa CLI: simple 2FA CLI interface"
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Handle short aliases for commands
    if len(sys.argv) > 1:
        alias_map = {
            'list': {'l', '-l', '--list', '-list', 'list'},
            'add': {'a', '-a', '--add', '-add', 'add'},
            'delete': {'d', '-d', '--delete', '-delete', 'delete'},
            'generate': {'g', '-g', '--generate', '-generate', 'generate'},
            'init': {'i', '-i', '--init', '-init', 'init'},
        }
        first_arg = sys.argv[1].lower()
        for cmd, aliases in alias_map.items():
            if first_arg in aliases:
                sys.argv[1] = cmd
                break

    # Add command
    parser_add = subparsers.add_parser(
        'add',
        aliases=['a', '-a', '--add'],
        help='Add a new TOTP secret key for an organization',
    )
    parser_add.add_argument(
        'secret', type=str, help='The TOTP secret key', nargs='?'
    )
    # Name as an optional argument
    parser_add.add_argument(
        '--name', '-n', type=str, help='Name of the secret', dest='name'
    )

    # Delete command
    parser_delete = subparsers.add_parser(
        'delete',
        aliases=['d', '-d', '--delete'],
        help='Delete a TOTP secret key for an organization',
    )
    parser_delete.add_argument(
        'secret',
        type=str,
        help='Entire or partial secret to delete',
        nargs='?',
        default=None,
    )
    parser_delete.add_argument(
        'name',
        type=str,
        help='Name of the secret to delete',
        nargs='?',
        default=None,
    )

    # Generate command
    parser_generate = subparsers.add_parser(
        'generate',
        aliases=['g', '-g', '--generate'],
        help='Generate a TOTP code for an organization',
    )
    parser_generate.add_argument(
        'name',
        type=str,
        help='Name of the secret to generate codes for',
        nargs='?',
    )
    parser_generate.add_argument(
        '--repeat',
        '-r',
        dest='repeat',
        type=int,
        help='How code generation cycles to repeat',
        nargs='?',
    )

    # List command
    parser_list = subparsers.add_parser(
        'list', aliases=['l', '-l', '--list'], help='List TOTP keys'
    )
    parser_list.add_argument(
        '--secret',
        '-s',
        '--secrets',
        dest='secret',
        action='store_true',
        help='Show full secrets',
        default=False,
    )

    # remote command
    parser_remote = subparsers.add_parser(
        'remote', aliases=['r', '-r', '--remote'], help='Remote operations'
    )
    remote_subparsers = parser_remote.add_subparsers(
        dest='remote_command', required=True, help='Remote operations'
    )

    # Init remote command
    remote_subparsers.add_parser(
        'init',
        aliases=['i', '-i', '--init'],
        help='Initialize remote capabilities',
    )

    # Info/Status remote command
    info_parser = remote_subparsers.add_parser(
        'info',
        help='Get remote status',
        aliases=[
            'inf',
            '-inf',
            '--info',
            's',
            'stat',
            '-stat',
            'status',
            '--status',
        ],
    )

    info_parser.add_argument(
        '-s',
        help='Show all info/status info without censorship',
        dest='secret',
        action='store_true',
        default=False,
    )
    # Push remote command
    remote_subparsers.add_parser(
        'push',
        help='Push secrets to remote',
        aliases=['pus', '-pus', '--push'],
    )
    # Pull remote command
    remote_subparsers.add_parser(
        'pull',
        help='Pull secrets from remote',
        aliases=['pul', '-pul', '--pull'],
    )

    return parser.parse_args()


@logf()
def code_gen(op2fa: Open2FA, repeat: TYPE.Optional[int] = None) -> None:
    """Infinite code generation loop."""
    longest = max([len(str(s.name)) for s in op2fa.secrets])

    cols = ['Name'.ljust(longest), 'Code  ', 'Next Code']

    sys.stdout.write('\n%s    %s    %s' % (cols[0], cols[1], cols[2]) + '\n')
    sys.stdout.write('    '.join(['-' * len(str(c)) for c in cols]) + '\n')

    prev_lines = 0
    while True:
        buffer = []
        for c in op2fa.generate_codes():
            buffer.append(
                '%s    %s    %s'
                % (
                    str(c.name).ljust(longest),
                    c.code.code,
                    '%.2f' % round(c.code.next_interval_in, 2),
                )
            )

        # Clear the previous output
        sys.stdout.write('\033[F' * prev_lines)

        # Store the number of lines in the current buffer
        prev_lines = len(buffer) + 1

        # Write the current buffer
        sys.stdout.write('\n'.join(buffer) + '\n\n')
        sys.stdout.flush()

        if repeat is not None:
            repeat -= 1
            if repeat <= 0:
                break
        sleep(0.5)


@logf()
def handle_remote_init(op2fa: Open2FA) -> None:
    """Handles initialization of remote capabilities."""
    # Check if OPEN2FA_UUID is set or exists
    open2fa_dir = config.OPEN2FA_DIR
    uuid_file_path = os.path.join(open2fa_dir, 'open2fa.uuid')

    if config.OPEN2FA_UUID:
        print(MSGS.INIT_EVAR_SET)
    elif os.path.exists(uuid_file_path):
        print(MSGS.INIT_FOUND_UUID)
    else:
        user_response = input(MSGS.INIT_CONFIRM)
        if user_response.lower() == 'y':
            # Generate new UUID and write to file
            new_uuid = str(uuid.uuid4())
            print(uuid_file_path, '@' * 100)
            with open(uuid_file_path, 'w') as uuid_file:
                uuid_file.write(new_uuid)
            os.chmod(uuid_file_path, config.OPEN2FA_KEY_PERMS)
            print(MSGS.INIT_SUCCESS.format(new_uuid))
        else:
            print(MSGS.INIT_FAIL)


@logf()
def handle_info(op2fa: Open2FA, show_secrets: bool = False) -> None:
    """Prints the Open2FA info."""
    o_dir = op2fa.o2fa_dir
    o_api_url = op2fa.remote_url
    o_num_secrets = len(op2fa.secrets)
    o_uuid_str, o_id, o_secret = None, None, None
    if op2fa.o2fa_uuid:
        o_uuid = op2fa.o2fa_uuid
        if o_uuid:
            if o_uuid.uuid:
                o_uuid_str = str(o_uuid.uuid)
                if not show_secrets:
                    o_uuid_str = o_uuid_str[0:1] + '...'
            if o_uuid.o2fa_id:
                o_id = o_uuid.o2fa_id
                if not show_secrets:
                    o_id = o_id[0:1] + '...'
            if o_uuid.remote:
                o_secret = o_uuid.remote.b58
                if not show_secrets:
                    o_secret = o_secret[0:1] + '...'
    print(
        MSGS.INFO_STATUS.format(
            o_dir, o_api_url, o_num_secrets, o_uuid_str, o_id, o_secret
        )
    )


@logf()
def main(*args, **kwargs) -> None:
    cli_args = parse_args()
    cli_args.command = cli_args.command.lower()

    _dir = kwargs.get('dir', config.OPEN2FA_DIR)
    _uuid = kwargs.get('uuid', config.OPEN2FA_UUID)
    _api_url = kwargs.get('api_url', config.OPEN2FA_API_URL)

    Op2FA = Open2FA(_dir, _uuid, _api_url)

    # remote
    if cli_args.command.startswith('r'):
        Op2FA = Open2FA(
            o2fa_uuid=config.OPEN2FA_UUID, o2fa_api_url=config.OPEN2FA_API_URL
        )
        if cli_args.remote_command.startswith('ini'):
            handle_remote_init()
        # status/info both the same
        elif cli_args.remote_command.startswith(
            'inf'
        ) or cli_args.remote_command.startswith('s'):
            handle_info(Op2FA, cli_args.secret)
        elif cli_args.remote_command.startswith('pus'):
            Op2FA.remote_push()
        elif cli_args.remote_command.startswith('pul'):
            Op2FA.remote_pull()
        return
    if cli_args.command.startswith('a'):
        new_secret = Op2FA.add_secret(cli_args.secret, cli_args.name)
        print(
            '\n'
            + MSGS.SECRET_ADDED.format(
                '{} {}\n'.format(new_secret.name, sec_trunc(new_secret.secret))
            )
        )
    # gen
    elif cli_args.command.startswith('g'):
        code_gen(Op2FA, cli_args.repeat)
    # list
    elif cli_args.command.startswith('l'):
        longest_name = max([len(str(s.name)) for s in Op2FA.secrets])
        longest_secret = max([
            len(str(s.secret)) if cli_args.secret is True else 5
            for s in Op2FA.secrets
        ])
        longest = max(longest_name, longest_secret)
        print(
            '\n' + '\t'.join(['Name'.ljust(longest), 'Secret'.ljust(longest)])
        )

        print('%s    %s' % ('-' * longest_name, '-' * longest_secret))
        for s in Op2FA.secrets:
            _sec = (
                sec_trunc(s.secret).ljust(longest_secret)
                if cli_args.secret is False
                else s.secret.ljust(longest_secret)
            )
            print(
                '%s    %s'
                % (str(s.name).ljust(longest_name), _sec.ljust(longest_secret))
            )
        print()
    # delete
    elif args.command.startswith('d'):
        if set([cli_args.name, cli_args.secret]) == {None}:
            print(MSGS.DEL_NO_NAME_SECRET)
            return
        print(
            MSGS.DEL_SUCCESS.format(
                Op2FA.remove_secret(cli_args.name, cli_args.secret)
            )
        )


if __name__ == "__main__":
    main()
