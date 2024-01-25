import logging
import os
import os.path as osp
import sys
import time
import typing as TYPE
from glob import glob
from pathlib import Path
from .common import gen_uuid, enc_totp_secret, dec_totp_secret
from .cli_config import MSGS
from .config import (
    INTERVAL,
    OPEN2FA_ID,
    OPEN2FA_KEY_PERMS,
    OPEN2FA_KEYDIR,
    OPEN2FA_KEYDIR_PERMS,
    OPEN2FA_API_URL,
)
from .ex import NoKeyFoundError

logger = logging.getLogger(__name__)


def ensure_open2fa_dir(dirpath: str = OPEN2FA_KEYDIR) -> str:
    """Ensure the .open2fa directory exists in the user's home directory
    with the correct permissions.
    Args:
        dirpath (str): Path to org key directory.
            Defaults to config.OPEN2FA_KEYDIR.
    Returns:
        str: path to the org key directory w/ proper permissions.
    """
    if not osp.isdir(dirpath):
        logger.info(f"Creating open2fa directory at '{dirpath}'")
        os.mkdir(dirpath)
        logger.info(
            f"Setting open2fa directory permissions to {OPEN2FA_KEYDIR_PERMS}"
        )
        os.chmod(dirpath, OPEN2FA_KEYDIR_PERMS)
        logger.info(
            f"Setting group ownership of open2fa directory user's group"
        )
        os.chown(dirpath, os.getuid(), os.getgid())
    return dirpath


def add_secret_key(
    org_name: str, secret: str, open2fa_dir: str = OPEN2FA_KEYDIR
):
    """Add a secret key for an organization.
    Args:
        org_name (str): The name of the organization.
        secret (str): The TOTP secret key.
        open2fa_dir (str): Path to the open2fa directory.
            Defaults to config.OPEN2FA_KEYDIR.
    Returns:
        str: The path to the key file
    """
    ensure_open2fa_dir(open2fa_dir)
    keypath = osp.join(open2fa_dir, f'{org_name}.key')
    if osp.isfile(keypath):
        logger.warning(f"Key file '{keypath}' already exists. Overwriting.")

    logger.info(f"Creating key file '{keypath}'")
    with open(keypath, 'w') as f:
        f.write(secret)

    logger.info(f"Setting key file permissions to {OPEN2FA_KEY_PERMS}")
    os.chmod(keypath, OPEN2FA_KEY_PERMS)

    return keypath


def get_secret_key(org_name: str, open2fa_dir: str = OPEN2FA_KEYDIR) -> str:
    """Retrieve the secret key for an organization from the open2fa dir if
    it exists.
    Args:
        org_name (str): The name of the organization.
        open2fa_dir (str): Path to the open2fa directory.
            Defaults to config.OPEN2FA_KEYDIR.
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


def delete_secret_key(
    org_name: str, open2fa_dir: str = OPEN2FA_KEYDIR
) -> bool:
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
