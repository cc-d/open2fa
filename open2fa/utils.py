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
from .crypto import generate_totp_token
from .cli_utils import (
    add_secret_key,
    delete_secret_key,
    ensure_open2fa_dir,
    get_secret_key,
)

logger = logging.getLogger(__name__)


class Open2faKey:
    def __init__(self, keypath: Path, enc_id: TYPE.Optional[str] = OPEN2FA_ID):
        keypath = Path(os.path.abspath(keypath))
        self.keypath = keypath
        self.name = keypath.stem
        with open(keypath, 'r') as f:
            self.secret = f.read().strip()
            self.censored = f'{self.secret[0]}...{self.secret[-1]}'
        self.current_token = None
        self.last_interval = -1

        self.enc_totp_secret = None
        if enc_id is not None:
            self.enc_totp_secret = enc_totp_secret(self.secret, enc_id)

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
            'enc_totp_secret': self.enc_totp_secret,
        }.items():
            _rstr += f'{k}={v}, '
        return _rstr[:-2] + '>'


class Open2FA:
    """Open2fa class for managing TOTP keys in the open2fa directory."""

    def __init__(
        self,
        open2fa_keydir: TYPE.Union[str, Path] = OPEN2FA_KEYDIR,
        interval: int = INTERVAL,
        o2fa_id: TYPE.Optional[str] = OPEN2FA_ID,
    ):
        ensure_open2fa_dir(open2fa_keydir)
        self.dirpath, self.dirstr = (Path(open2fa_keydir), str(open2fa_keydir))
        self.interval = interval

        self.keys = [
            Open2faKey(keypath)
            for keypath in glob(osp.join(self.dirstr, '*.key'))
        ]
        self.keymap = {key.name: key for key in self.keys}
        self.o2fa_id = o2fa_id

    def __iter__(self):
        return iter(self.keys)

    def __getitem__(self, org_name: str) -> Open2faKey:
        for key in self.keys:
            if key.name == org_name:
                return key
        raise NoKeyFoundError(org_name)

    def __repr__(self):
        censored_keys = ' '.join([key.censored for key in self.keys])
        return (
            '<Open2fa:'
            f' id={self.o2fa_id[0:2] if self.o2fa_id else None} {censored_keys}>'
        )

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

    def cli_init(self) -> None:
        """Initialize the open2fa directory and key file."""
        if OPEN2FA_ID is not None:
            logger.info(
                f"OPEN2FA_ID is set. Skipping creation of '{OPEN2FA_ID}'"
            )
            new_uuid = OPEN2FA_ID
        else:
            new_uuid = gen_uuid()
            with open(self.dirpath / 'open2fa.id', 'w') as f:
                f.write(new_uuid)

        logger.info(f'NEW OPEN2FA_ID: {new_uuid}')

        # implement sync logic here
        # for key in self.keys:
