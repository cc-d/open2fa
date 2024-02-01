import logging
import os
import os.path as osp
import sys
import time
import typing as TYPE
import json
from glob import glob
from pathlib import Path
from .config import (
    INTERVAL,
    OPEN2FA_UUID,
    OPEN2FA_KEY_PERMS,
    OPEN2FA_DIR,
    OPEN2FA_DIR_PERMS,
    OPEN2FA_API_URL,
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
