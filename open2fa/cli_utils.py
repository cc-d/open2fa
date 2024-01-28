import logging
import os
import os.path as osp
import sys
import time
import typing as TYPE
import json
from glob import glob
from pathlib import Path
from .common import gen_uuid, enc_totp_secret, dec_totp_secret
from .cli_config import MSGS
from .config import (
    INTERVAL,
    OPEN2FA_ID,
    OPEN2FA_KEY_PERMS,
    OPEN2FA_DIR,
    OPEN2FA_DIR_PERMS,
    OPEN2FA_API_URL,
)
from .ex import NoKeyFoundError

logger = logging.getLogger(__name__)


def ensure_open2fa_dir(dirpath: str):
    """Ensure the .open2fa directory exists in the user's home directory
    with the correct permissions.
    Args:
        dirpath (str): Path to the open2fa directory.
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


def ensure_secrets_json(o2fa_dir: str, filename: str = 'secrets.json'):
    """Ensure the secrets.json file exists in the open2fa directory.
    Args:
        key_json_path (str): Path to the secrets.json file.
        filename (str): The name of the secrets.json file.
    Returns:
        str: path to the secrets.json file.
    """
    key_json_path = osp.join(o2fa_dir, filename)
    if not osp.isfile(key_json_path):
        logger.info(f"Creating secrets.json file at '{key_json_path}'")
        with open(key_json_path, 'w') as f:
            json.dump({}, f)
        logger.info(
            f"Setting secrets.json file permissions to {OPEN2FA_KEY_PERMS}"
        )
        os.chmod(key_json_path, OPEN2FA_KEY_PERMS)
        logger.info(
            f"Setting group ownership of secrets.json file to user's group"
        )
        os.chown(key_json_path, os.getuid(), os.getgid())
    return key_json_path


def get_secret_key(org_name: str, open2fa_dir: str = OPEN2FA_DIR) -> str:
    """Retrieve the secret key for an organization from the open2fa dir if
    it exists.
    Args:
        org_name (str): The name of the organization.
        open2fa_dir (str): Path to the open2fa directory.
            Defaults to config.OPEN2FA_DIR.
    Returns:
        Optional[str]: The base32 encoded secret key for the organization if
        available. Otherwise, None.
    """
    key_path = Path(osp.join(open2fa_dir, f'{org_name}.key'))
    if key_path.is_file():
        logger.debug(f"Found key file '{key_path}'")
        with open(key_path, 'r') as f:
            return f.read().strip()
    return None


def delete_secret_key(org_name: str, open2fa_dir: str = OPEN2FA_DIR) -> bool:
    """Delete the secret key for an organization from the open2fa dir if
    it exists.
    Args:
        org_name (str): The name of the organization.
    Returns:
        Optional[bool]: True if the key was deleted, False otherwise.

    """
    key_path = osp.join(open2fa_dir, f'{org_name}.key')
    if osp.isfile(key_path):
        logger.info(f"Deleting key file '{key_path}'")
        os.remove(key_path)
        return True
    logger.warning(f"No key file found for '{org_name}'")
    return False
