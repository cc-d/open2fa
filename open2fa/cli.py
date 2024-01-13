#!/usr/bin/env python3
import asyncio
import argparse
import os
import os.path as osp
import typing as TYPE
import sys
from time import sleep
from pathlib import Path
from logging import getLogger
from .config import OPEN2FA_KEYDIR
from .cli_utils import Open2faKey, Open2FA

logger = getLogger(__name__)
logger.setLevel('INFO')


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
        'org_name', type=str, help='Name of the organization', nargs='?'
    )
    parser_add.add_argument(
        'secret', type=str, help='The TOTP secret key', nargs='?'
    )

    # Delete command
    parser_delete = subparsers.add_parser(
        'delete',
        aliases=['d', '-d', '--delete'],
        help='Delete a TOTP secret key for an organization',
    )
    parser_delete.add_argument(
        'org_name', type=str, help='Name of the organization', nargs='?'
    )

    # Generate command
    parser_generate = subparsers.add_parser(
        'generate',
        aliases=['g', '-g', '--generate'],
        help='Generate a TOTP code for an organization',
    )
    parser_generate.add_argument(
        'org_name', type=str, help='Name of the organization', nargs='?'
    )
    parser_generate.add_argument(
        '--repeat',
        '-r',
        dest='repeat',
        type=int,
        help='How many times to repeat the code generation?',
        nargs='?',
    )

    # List command
    parser_list = subparsers.add_parser(
        'list', aliases=['l', '-l', '--list'], help='List TOTP keys'
    )
    parser_list.add_argument(
        'org_name',
        type=str,
        help='Name of the organization or its prefix',
        nargs='?',
    )

    return parser.parse_args()


def _add_ensure_org_secret(args: argparse.Namespace) -> argparse.Namespace:
    """Ensure that both the org_name and secret args are present. If not,
    prompt the user for the missing argument(s).
    """
    # 0/2 args present
    if not args.secret and not args.org_name:
        args.org_name = input("Enter Organization name: ")
        args.secret = input("Enter Secret key: ")
    # 1/2 args present
    if not args.secret or not args.org_name:
        print('BOTH org_name and secret must be specified.')
        sys.exit(1)
    return args


def _print_gend_tokens(gend: TYPE.Dict[str, str]) -> None:
    """Print the generated tokens."""
    if len(gend) <= 0:
        return
    print(f'\n<<< Generated {len(gend)} codes >>>\n\n'.upper())
    for name, code in gend.items():
        print(f'{name}: {code}\n')


def main() -> None:
    args = parse_args()
    args.command = args.command.lower()
    repeat = args.repeat if hasattr(args, 'repeat') else None

    Op2FA = Open2FA(os.environ.get('OPEN2FA_KEYDIR') or OPEN2FA_KEYDIR)

    if args.command.startswith('a'):
        args = _add_ensure_org_secret(args)
        newkey = Op2FA.add(args.org_name, args.secret, ask_overwrite=True)
        print(f"Added key: {newkey}") if newkey else print(f"Key not added.")
    # gen
    elif args.command.startswith('g'):
        while True:
            gend = Op2FA.generate(args.org_name)
            _print_gend_tokens(gend)

            # only $x codes were requested
            if repeat is not None:
                repeat -= 1
                if repeat == 0:
                    break
            sleep(0.5)
    # list
    elif args.command.startswith('l'):
        Op2FA.print_keys()

    # delete
    elif args.command.startswith('d'):
        if not args.org_name:
            print("Must specify an organization name to delete.")
            sys.exit(1)
        if Op2FA.delete(args.org_name):
            print(f"Deleted key for '{args.org_name}'")
        else:
            print(f"Key for '{args.org_name}' not found.")
            sys.exit(1)


if __name__ == "__main__":
    main()
