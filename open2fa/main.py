from . import config
import os
import os.path as osp
from pathlib import Path
from .common import O2FAUUID, RemoteSecret, TOTPSecret
from .totp import TOTP2FACode, generate_totp_2fa_code
from .cli_utils import (
    ensure_open2fa_dir,
    ensure_secrets_json,
    read_secrets_json,
    write_secrets_json,
)
import typing as TYPE
import json


class Open2FA:
    def __init__(
        self,
        remote: bool = False,
        o2fa_dir: TYPE.Union[str, Path] = config.OPEN2FA_DIR,
        o2fa_uuid: TYPE.Optional[str] = None,
    ):
        """Create a new Open2FA object."""
        self.remote = remote
        self.o2fa_dir = ensure_open2fa_dir(str(o2fa_dir))
        self.secrets_json_path = ensure_secrets_json(
            osp.join(self.o2fa_dir, 'secrets.json')
        )
        self.secrets = [
            TOTPSecret(s['secret'], s['name'])
            for s in read_secrets_json(self.secrets_json_path)['secrets']
        ]

        self.o2fa_uuid = o2fa_uuid or config.OPEN2FA_UUID

    def add_secret(self, secret: str, name: str) -> TOTPSecret:
        """Add a new TOTP secret to the Open2FA object.
        Args:
            secret (str): the TOTP secret
            name (str): the name of the secret
        Returns:
            TOTPSecret: the new TOTPSecret object
        """
        new_secret = TOTPSecret(secret, name)
        self.secrets.append(new_secret)
        self.write_secrets()
        return new_secret

    def remove_secret(self, name: str, force: bool = False) -> int:
        """Remove a TOTP secret from the Open2FA object. Force can
        also be used to confirm specific secret removals if multiple
        secrets have the same name.
        Args:
            name (str): the name of the secret to remove
            force (bool): whether to remove the secret without confirmation
                Default: False
        Returns:
            int: the number of secrets removed
        """
        new_secrets = []
        _seclen = len(self.secrets)
        for s in self.secrets:
            if s.name == name:
                if force:
                    continue
                if input(
                    'Are you sure you want to remove %s %s? (y/n): '
                    % (s.name, s.secret)
                ).startswith('y'):
                    continue
            new_secrets.append(s)
        self.secrets = new_secrets
        self.write_secrets()
        return _seclen - len(new_secrets)

    def generate_codes(
        self, name: TYPE.Optional[str] = None
    ) -> TYPE.Generator:
        """Generate TOTP 2FA codes for a specific secret.
        Args:
            name (str, optional): the name of the secret to generate a code for
                if excluded, codes for all secrets will be generated
        Yields:
            str: the TOTP 2FA code
        """
        for s in self.secrets:
            prev_code = s.code.code
            s.generate_code()
            if s.code != prev_code:
                yield s.code

    def write_secrets(self) -> None:
        """Write the secrets to the secrets.json file."""
        write_secrets_json(
            self.secrets_json_path, [s.json() for s in self.secrets]
        )
