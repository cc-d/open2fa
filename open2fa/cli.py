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
from .cli_utils import parse_cli_arg_aliases
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
    sys.argv = parse_cli_arg_aliases(sys.argv)
    parser = argparse.ArgumentParser(
        description="open2fa CLI: simple 2FA CLI interface"
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Add command
    parser_add = subparsers.add_parser(
        'add',
        help='Add a new TOTP secret key for an organization',
        aliases=['a'],
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
        help='Delete a TOTP secret key for an organization',
        aliases=['d'],
    )
    parser_delete.add_argument(
        '--secret',
        '-s',
        type=str,
        help='The TOTP secret key to delete',
        dest='secret',
    )
    parser_delete.add_argument(
        '--name',
        '-n',
        type=str,
        help='Name of the secret to delete',
        dest='name',
    )

    # Generate command
    parser_generate = subparsers.add_parser(
        'generate',
        help='Generate a TOTP code for an organization',
        aliases=['g'],
    )

    parser_generate.add_argument(
        '--repeat',
        '-r',
        dest='repeat',
        type=int,
        help='How code generation cycles to repeat',
    )

    # List command
    parser_list = subparsers.add_parser(
        'list', help='List TOTP keys', aliases=['l']
    )
    parser_list.add_argument(
        '-s',
        '--secrets',
        '--secret',
        dest='secrets',
        action='store_true',
        help='Show full secrets',
        default=False,
    )

    # remote command
    parser_remote = subparsers.add_parser(
        'remote', help='Remote operations', aliases=['r']
    )
    remote_subparsers = parser_remote.add_subparsers(
        dest='remote_command', required=True, help='Remote operations'
    )

    # Init remote command
    remote_subparsers.add_parser('init', help='Initialize remote capabilities')

    # Info/Status remote command
    parser_info = subparsers.add_parser(
        'info', help='Show Open2FA info/status', aliases=['i']
    )

    parser_info.add_argument(
        '-s',
        '--secret',
        '--secrets',
        help='Show all info/status info without censorship',
        dest='secret',
        action='store_true',
        default=False,
    )
    # Push remote command
    remote_subparsers.add_parser('push', help='Push secrets to remote')
    # Pull remote command
    remote_subparsers.add_parser('pull', help='Pull secrets from remote')

    # Delete remote command
    del_parser = remote_subparsers.add_parser(
        'delete', help='Delete remote secrets', aliases=['d']
    )
    del_parser.add_argument(
        'secret', type=str, help='The TOTP secret key to delete', nargs='?'
    )
    del_parser.add_argument(
        '--name',
        '-n',
        type=str,
        help='Name of the secret to delete',
        dest='name',
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
            with open(uuid_file_path, 'w') as uuid_file:
                uuid_file.write(new_uuid)
            os.chmod(uuid_file_path, config.OPEN2FA_KEY_PERMS)
            print(MSGS.INIT_SUCCESS.format(new_uuid))
            handle_info(Open2FA(open2fa_dir, new_uuid, config.OPEN2FA_API_URL))

        else:
            print(MSGS.INIT_FAIL)


@logf()
def handle_info(op2fa: Open2FA, show_secrets: bool = False) -> None:
    """Prints the Open2FA info."""
    o_dir = op2fa.o2fa_dir
    if hasattr(op2fa, 'o2fa_api_url'):
        o_api_url = op2fa.o2fa_api_url
    else:
        o_api_url = config.OPEN2FA_API_URL
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

    _dir = kwargs.get('dir', config.OPEN2FA_DIR)
    _uuid = kwargs.get('uuid', config.OPEN2FA_UUID)
    _api_url = kwargs.get('api_url', config.OPEN2FA_API_URL)

    Op2FA = Open2FA(_dir, _uuid, _api_url)

    # info
    if cli_args.command == 'info':
        handle_info(Op2FA, cli_args.secret)
    # remote
    elif cli_args.command == 'remote':
        if cli_args.remote_command.startswith('ini'):
            handle_remote_init(Op2FA)
        if cli_args.remote_command.startswith('pus'):
            pushed = Op2FA.remote_push()
            print(MSGS.PUSH_SUCCESS.format(len(pushed)))
        elif cli_args.remote_command.startswith('pul'):
            secs = Op2FA.remote_pull()
            print(MSGS.PULL_SUCCESS.format(secs))
        elif cli_args.remote_command.startswith('d'):
            if cli_args.name is None and cli_args.secret is None:
                print(MSGS.DEL_NO_NAME_SECRET)
                return
            del_count = Op2FA.remote_delete(
                secret=cli_args.secret, name=cli_args.name
            )
            print(MSGS.DEL_SUCCESS.format(del_count))

    elif cli_args.command == 'add':
        new_secret = Op2FA.add_secret(cli_args.secret, cli_args.name)
        print(
            '\n'
            + MSGS.SECRET_ADDED.format(
                '{} {}\n'.format(new_secret.name, sec_trunc(new_secret.secret))
            )
        )
    # gen
    elif cli_args.command == 'generate':
        code_gen(Op2FA, cli_args.repeat)
    # list
    elif cli_args.command == 'list':
        longest_name = max([len(str(s.name)) for s in Op2FA.secrets])
        longest_secret = max([
            len(str(s.secret)) if cli_args.secrets is True else 5
            for s in Op2FA.secrets
        ])
        longest = max(longest_name, longest_secret)
        print(
            '\n'
            + '    '.join(['Name'.ljust(longest), 'Secret'.ljust(longest)])
        )

        print('%s    %s' % ('-' * longest_name, '-' * longest_secret))
        for s in Op2FA.secrets:
            _sec = (
                sec_trunc(s.secret).ljust(longest_secret)
                if cli_args.secrets is False
                else s.secret.ljust(longest_secret)
            )
            print(
                '%s    %s'
                % (str(s.name).ljust(longest_name), _sec.ljust(longest_secret))
            )
        print()
    # delete
    elif cli_args.command == 'delete':
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
