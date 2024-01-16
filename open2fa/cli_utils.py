import logging
import os
import os.path as osp
import typing as TYPE
import sys
import time
from glob import glob
from pathlib import Path
from .utils import generate_totp_token
from .config import (
    OPEN2FA_KEYDIR,
    OPEN2FA_KEYDIR_PERMS,
    INTERVAL,
    OPEN2FA_KEY_PERMS,
)
from .cli_config import MSGS
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


def get_key_files(
    org_name: TYPE.Optional[str] = None, open2fa_dir: str = OPEN2FA_KEYDIR
) -> TYPE.List[Path]:
    """Get the file path for the secret key of an organization.
    Args:
        org_name (Optional[str]): The name of the organization. If empty,
            return all key files.
        open2fa_dir (str): Path to the open2fa directory.
            Defaults to config.OPEN2FA_KEYDIR.
    Returns:
        List[Path]: The filepath for secret keys matching the org name, or all
            key files if org_name is None.
    """
    open2fa_dir = ensure_open2fa_dir(open2fa_dir)
    dirfiles = os.listdir(open2fa_dir)
    dirfiles = [
        f
        for f in dirfiles
        if f.endswith('.key') and osp.isfile(osp.join(open2fa_dir, f))
    ]

    if org_name is not None:
        logger.debug(f'filtering key files that dont start with {org_name}')
        dirfiles = [f for f in dirfiles if f.startswith(org_name.lower())]

    return [Open2faKey(Path(osp.join(open2fa_dir, f))) for f in dirfiles]


class Open2faKey:
    def __init__(self, keypath: Path):
        keypath = Path(os.path.abspath(keypath))
        self.keypath = keypath
        self.name = keypath.stem
        with open(keypath, 'r') as f:
            self.secret = f.read().strip()
            self.censored = f'{self.secret[0]}...{self.secret[-1]}'
        self.current_token = None
        self.last_interval = -1

    def generate(self) -> TYPE.Optional[str]:
        print_token = False
        cur_interval = int(time.time()) // INTERVAL
        cur_token = generate_totp_token(self.secret)

        # Only print the token if it is different from the last token
        # or if the interval has changed or if this is the first token
        if (
            self.current_token is None
            or cur_token != self.current_token
            or cur_interval > self.last_interval
        ):
            self.current_token = cur_token
            print_token = True

        if print_token:
            self.last_interval = cur_interval
            self.last_token = cur_token
            return self.current_token

        return None

    def __repr__(self) -> str:
        _rstr = '<Open2faKey '
        for k, v in {
            'path': self.keypath,
            'name': self.name,
            'secret': self.censored,
            'token': self.current_token,
            'interval': self.last_interval,
        }.items():
            _rstr += f'{k}={v}, '
        return _rstr[:-2] + '>'


class Open2FA:
    """Open2fa class for managing TOTP keys in the open2fa directory."""

    def __init__(
        self,
        open2fa_keydir: TYPE.Union[str, Path] = OPEN2FA_KEYDIR,
        interval: int = INTERVAL,
    ):
        ensure_open2fa_dir(open2fa_keydir)
        self.dirpath, self.dirstr = (Path(open2fa_keydir), str(open2fa_keydir))
        self.interval = interval

        self.keys = [
            Open2faKey(keypath)
            for keypath in glob(osp.join(self.dirstr, '*.key'))
        ]
        self.keymap = {key.name: key for key in self.keys}

    def __iter__(self):
        return iter(self.keys)

    def __getitem__(self, org_name: str) -> Open2faKey:
        for key in self.keys:
            if key.name == org_name:
                return key
        raise NoKeyFoundError(org_name)

    def __repr__(self):
        censored_keys = ' '.join([key.censored for key in self.keys])
        return f'<AllOpen2faKeys: {censored_keys}>'

    def _build_keypath(self, org_name: str, case_sensitive: bool = True):
        """Build the path to the key file for an added key org."""
        org_name = org_name.strip()
        if not case_sensitive:
            org_name = org_name.lower()

        return osp.join(self.dirstr, '%s.key' % org_name)

    def refresh_keys(self) -> None:
        """Refresh the keys in the open2fa directory."""
        self.keys = [
            Open2faKey(keypath)
            for keypath in glob(osp.join(self.dirstr, '*.key'))
        ]
        self.keymap = {key.name: key for key in self.keys}

    def add(
        self, org_name: str, secret: str, ask_overwrite: bool = True
    ) -> TYPE.Optional[Open2faKey]:
        """Add a secret key for an organization.
        Args:
            org_name (str): The name of the organization.
            secret (str): The TOTP secret key.
            ask_overwrite (bool): If True, ask the user before overwriting an
                existing key. If False, overwrite without asking.
                Defaults to True.
        Returns:
            Optional[Open2faKey]: The Open2faKey object for the added key.
                If the key was not added, return None
        """
        if osp.isfile(self._build_keypath(org_name)):
            logger.warning(
                f"Key for '{org_name}' already exists. Overwriting."
            )
            if ask_overwrite:
                overwrite = input(
                    f"Key for '{org_name}' already exists. Overwrite? [y/N] "
                )
                if not overwrite.lower().startswith('y'):
                    return None

        keypath = add_secret_key(org_name, secret, self.dirstr)
        key = Open2faKey(Path(keypath))
        self.keys.append(key)
        return key

    def delete(self, org_name: str) -> bool:
        """Delete the secret key for an organization from the open2fa dir if
        it exists.
        Args:
            org_name (str): The name of the organization.
        Returns:
            Optional[bool]: True if the key was deleted, False otherwise.
        """
        success = delete_secret_key(org_name, self.dirstr)
        if success:
            for i, key in enumerate(self.keys):
                if key.name == org_name:
                    del self.keys[i]
                    break
        return success

    def print_keys(self) -> None:
        """Print all keys in the open2fa directory if org_name is None.
        Otherwise, print all keys starting with org_name.
        """
        print('Org Name'.ljust(20), 'Secret', '\t', 'Key Path')
        for key in self.keys:
            print(key.name.ljust(20), key.censored, '\t', key.keypath)

    def generate(self, org_name: TYPE.Optional[str] = None) -> dict:
        """Generate a TOTP token for an organization.
        Args:
            org_name (Optional[str]): The name of the organization. If empty,
                return all key files.
        Returns:
            dict: A dictionary mapping org names to TOTP tokens.
        """
        new_tokens = {}
        for key in self.keys:
            if org_name is not None:
                if not key.name.startswith(org_name):
                    continue
            try:
                token = key.generate()
            except Exception as e:
                logger.error(f"Error generating token for '{key.name}': {e}")
                continue
            if token is not None:
                new_tokens[key.name] = token
        return new_tokens
