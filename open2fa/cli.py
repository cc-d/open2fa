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
from .main import Open2FA
from . import msgs as MSGS
from pyshared import truncstr

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
    parser_add.add_argument(
        'name', type=str, help='Name of the secret', nargs='?'
    )

    # Delete command
    parser_delete = subparsers.add_parser(
        'delete',
        aliases=['d', '-d', '--delete'],
        help='Delete a TOTP secret key for an organization',
    )
    parser_delete.add_argument(
        'name', type=str, help='Name of the secret to delete', nargs='?'
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
        help='Repeatedly try to generate codes',
        nargs='?',
    )

    # List command
    parser_list = subparsers.add_parser(
        'list', aliases=['l', '-l', '--list'], help='List TOTP keys'
    )
    parser_list.add_argument(
        'name', type=str, help='Only list keys matching this name', nargs='?'
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.command = args.command.lower()

    Op2FA = Open2FA()
    if args.command.startswith('a'):
        new_secret = Op2FA.add_secret(args.secret, args.name)
        print(MSGS.SECRET_ADDED.format(new_secret))
    # gen
    elif args.command.startswith('g'):
        cols = ['Name', 'Code', 'Next Code In']
        sys.stdout.write('\t\t'.join(cols) + '\n')
        sys.stdout.write('\t\t'.join(['-' * len(c) for c in cols]) + '\n')

        prev_lines = 0
        while True:
            buffer = []
            for c in Op2FA.generate_codes():
                buffer.append(
                    '%s\t\t%s\t\t%.2f'
                    % (c.name, c.code.code, c.code.next_interval_in)
                )

            # Clear the previous output
            sys.stdout.write('\033[F' * prev_lines)

            # Store the number of lines in the current buffer
            prev_lines = len(buffer)

            # Write the current buffer
            sys.stdout.write('\n'.join(buffer) + '\n')
            sys.stdout.flush()
            sleep(0.5)
    # list
    elif args.command.startswith('l'):
        print('\t\t'.join(['Name', 'Secret']))
        print('\t\t'.join(['-' * len(c) for c in ['Name', 'Secret']]))
        for s in Op2FA.secrets:
            print('%s\t\t%s' % (s.name, truncstr(s.secret, start_chars=1, end_chars=1)))

    # delete
    elif args.command.startswith('d'):
        if not args.name:
            print("Must specify an organization name to delete.")
            sys.exit(1)
        print(Op2FA.remove_secret(args.name), 'secret(s) removed.')


if __name__ == "__main__":
    main()
