import json
import logging
import os
import os.path as osp
import sys
import time
import typing as TYPE
from glob import glob
from pathlib import Path

from .config import (
    INTERVAL,
    OPEN2FA_API_URL,
    OPEN2FA_DIR,
    OPEN2FA_DIR_PERMS,
    OPEN2FA_KEY_PERMS,
    OPEN2FA_UUID,
)

logger = logging.getLogger(__name__)


def ensure_open2fa_dir(dirpath: TYPE.Union[str, Path]) -> str:
    """Ensure the .open2fa directory exists in the user's home directory
    with the correct permissions.
    Args:
        dirpath (str | Path): Path to the open2fa directory.
    Returns:
        str: path to the open2fa directory w/ proper permissions.
    """
    if not osp.isdir(dirpath):
        logger.info(f"Creating open2fa directory at '{dirpath}'")
        os.mkdir(dirpath)
        logger.info(
            f"Setting open2fa directory permissions to {OPEN2FA_DIR_PERMS}"
        )
        os.chmod(dirpath, OPEN2FA_DIR_PERMS)
        logger.info(
            f"Setting group ownership of open2fa directory user's group"
        )
        os.chown(dirpath, os.getuid(), os.getgid())
    return dirpath


def ensure_secrets_json(key_json_path: TYPE.Union[str, Path]) -> str:
    """Ensure the secrets.json file exists in the open2fa directory.
    Args:
        key_json_path (str | Path): Path to the secrets.json file.
    Returns:
        str: path to the secrets.json file.
    """
    if not osp.isfile(key_json_path):
        logger.info(f"Creating secrets.json file at '{key_json_path}'")
        with open(key_json_path, 'w') as f:
            f.write(json.dumps({'secrets': []}))
        logger.info(
            f"Setting secrets.json file permissions to {OPEN2FA_KEY_PERMS}"
        )
        os.chmod(key_json_path, OPEN2FA_KEY_PERMS)
        logger.info(
            f"Setting group ownership of secrets.json file to user's group"
        )
        os.chown(key_json_path, os.getuid(), os.getgid())
    return key_json_path


def read_secrets_json(filepath: TYPE.Union[str, Path]) -> dict:
    """Read the secrets.json file and return the contents.
    Args:
        o2fa_dir (str | Path): Path to the open2fa directory.
        filename (str): The name of the secrets.json file.
    Returns:
        TYPE.Dict: The contents of the secrets.json file.
    """
    key_json_path = ensure_secrets_json(filepath)
    with open(key_json_path, 'r') as f:
        return json.load(f)


def write_secrets_json(filepath: TYPE.Union[str, Path], data: dict) -> None:
    """Safely write data to the secrets.json file.
    Args:
        o2fa_dir (str): Path to the open2fa directory.
        data (TYPE.Dict): The data to write to the secrets.json file.
        filename (str): The name of the secrets.json file.
    """
    json_path = ensure_secrets_json(filepath)
    # safely write the data to the file
    fd = os.open(
        '%s.tmp' % json_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )
    with os.fdopen(fd, 'w') as f:
        f.write(json.dumps({'secrets': data}))
    os.replace('%s.tmp' % json_path, json_path)


def dash_arg(arg: str) -> TYPE.Set[str]:
    """Adds - and -- to possible cli arg aliases"""
    return {arg, '-%s' % arg, '--%s' % arg}


def parse_cli_arg_aliases(argv_args: TYPE.List[str]) -> TYPE.List[str]:
    """turns cli arg aliases into their canonical form"""
    alias_map = {
        'list': {'l', '-l'}.union(dash_arg('list')),
        'add': {'a', '-a'}.union(dash_arg('add')),
        'delete': {'d', '-d'}.union(dash_arg('delete')),
        'generate': {'g', '-g'}.union(dash_arg('generate')),
        'remote': {'r', '-r'}.union(dash_arg('remote')),
        'info': {'i', '-i'}
        .union(dash_arg('inf'))
        .union(dash_arg('info'))
        .union(dash_arg('stat'))
        .union(dash_arg('status')),
    }
    first_arg = argv_args[1].lower()
    for cmd, aliases in alias_map.items():
        if first_arg in aliases:
            argv_args[1] = cmd
            break

    if len(argv_args) > 2:
        second_arg = argv_args[2].lower()
        use_alias_map = None
        if first_arg == 'remote':
            use_alias_map = {
                'push': dash_arg('pus').union(dash_arg('push')),
                'pull': dash_arg('pul').union(dash_arg('pull')),
                'init': dash_arg('ini').union(dash_arg('init')),
                'delete': dash_arg('del').union(dash_arg('delete')),
            }
        if use_alias_map:
            for cmd, aliases in use_alias_map.items():
                if second_arg in aliases:
                    argv_args[2] = cmd
                    break

    return argv_args
