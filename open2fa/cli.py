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
from . import version

logger = getLogger(__name__)
logger.setLevel('INFO')


@logf()
def parse_args() -> argparse.ArgumentParser:
    """Parse command-line arguments.
    Returns:
        argparse.ArgumentParser: The command-line argument parser.
    """
    sys.argv = parse_cli_arg_aliases(sys.argv)
    parser = argparse.ArgumentParser(
        description="open2fa CLI: simple 2FA CLI interface"
    )

    parser.add_argument(
        '--version',
        '-v',
        action='version',
        version=MSGS.VERSION.format(version.__version__),
        help="Show program's version number and exit.",
    )

    subparsers = parser.add_subparsers(
        dest='command', required=False, help='Open2FA command to execute'
    )

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

    parser_generate.add_argument(
        '--name',
        '-n',
        type=str,
        help='Generate codes only for secrets matching name',
        default=None,
    )

    parser_generate.add_argument(
        '--delay',
        '-d',
        type=float,
        help='Delay between code generation cycles',
        default=0.5,
    )

    # List command
    parser_list = subparsers.add_parser(
        'list', help='List TOTP keys', aliases=['l']
    )
    parser_list.add_argument(
        '-s',
        '--secrets',
        '--secret',
        dest='show_secrets',
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
        dest='show_secrets',
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

    return parser


@logf()
def main(
    o2fa_dir: str = config.OPEN2FA_DIR,
    o2fa_uuid: TYPE.Optional[str] = config.OPEN2FA_UUID,
    o2fa_api_url: str = config.OPEN2FA_API_URL,
    **kwargs,
) -> TYPE.Optional[Open2FA]:
    """Main function for the open2fa CLI. Returns an Open2FA object
    in all cases except when the version flag is set or no command is
    provided.
    Args:
        o2fa_dir (Optional[str]): The open2fa directory.
            Defaults to config.OPEN2FA_DIR.
        o2fa_uuid (Optional[str]): The open2fa UUID.
            Defaults to config.OPEN2FA_UUID.
        o2fa_api_url (Optional[str]): The open2fa API URL.
            Defaults to config.OPEN2FA_API_URL.
        **kwargs: dir, uuid, api_url can be passed as keyword arguments
            which will override their respective passed args/defaults.
            This was done to maintain backwards compatibility.
    Returns:
        Optional[Open2FA]: The Open2FA object.
    """
    cli_parser = parse_args()
    cli_args = cli_parser.parse_args()

    if cli_args.command is None:
        if '-v' in sys.argv or '--version' in sys.argv:
            print(MSGS.VERSION.format(version.__version__))
        else:
            cli_parser.print_help()
        return

    # maintain backwards compatibility
    o2fa_dir = kwargs.get('dir', o2fa_dir)
    o2fa_uuid = kwargs.get('uuid', o2fa_uuid)
    o2fa_api_url = kwargs.get('api_url', o2fa_api_url)

    Op2FA = Open2FA(
        o2fa_dir=o2fa_dir, o2fa_uuid=o2fa_uuid, o2fa_api_url=o2fa_api_url
    )

    # info
    if cli_args.command == 'info':
        # check if info -s flag is set
        # use the show_secrets flag to determine if secrets should be shown
        # do NOT use cli_args.secret
        Op2FA.cli_info(show_secrets=cli_args.show_secrets)
    # remote
    elif cli_args.command == 'remote':
        if cli_args.remote_command.startswith('ini'):
            Op2FA.remote_init()
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
        Op2FA.display_codes(
            repeat=cli_args.repeat, name=cli_args.name, delay=cli_args.delay
        )
    # list
    elif cli_args.command == 'list':
        max_name, max_secret = 4, 6
        if len(Op2FA.secrets) > 0:
            max_name = max([len(str(s.name)) for s in Op2FA.secrets])
            max_secret = max(
                [
                    len(str(s.secret)) if '-s' in sys.argv else 5
                    for s in Op2FA.secrets
                ]
            )

        print(
            '\n' + 'Name'.ljust(max_name) + '    ' + 'Secret'.ljust(max_secret)
        )

        print('%s    %s' % ('-' * max_name, '-' * max_secret))
        for s in Op2FA.secrets:
            _sec = (
                sec_trunc(s.secret).ljust(max_secret)
                if cli_args.show_secrets is False
                else s.secret.ljust(max_secret)
            )
            print(
                '%s    %s'
                % (str(s.name).ljust(max_name), _sec.ljust(max_secret))
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

    return Op2FA


if __name__ == "__main__":
    # avoid printing the open2fa object when called from the command line
    _ = main()
