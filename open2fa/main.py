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
from . import ex as EX
from . import msgs as MSGS
from .utils import sec_trunc
import requests as req
from logfunc import logf


class Open2FA:
    o2fa_dir: str
    secrets_json_path: str
    secrets: TYPE.List[TOTPSecret]
    o2fa_uuid: TYPE.Union[O2FAUUID, None]
    o2fa_api_url: TYPE.Union[str, None]

    def __init__(
        self,
        o2fa_dir: TYPE.Union[str, Path] = config.OPEN2FA_DIR,
        o2fa_uuid: TYPE.Optional[str] = None,
        o2fa_api_url: TYPE.Optional[str] = None,
    ):
        """Create a new Open2FA object."""
        self.o2fa_dir = ensure_open2fa_dir(str(o2fa_dir))
        self.secrets_json_path = ensure_secrets_json(
            osp.join(self.o2fa_dir, 'secrets.json')
        )
        self.secrets = [
            TOTPSecret(s['secret'], s['name'])
            for s in read_secrets_json(self.secrets_json_path)['secrets']
        ]
        self.secrets.sort(key=lambda s: str(s.name).lower())

        if o2fa_uuid is not None:
            self.o2fa_uuid = O2FAUUID(o2fa_uuid)
            self.remote_url = o2fa_api_url or config.OPEN2FA_API_URL

    def add_secret(self, secret: str, name: str) -> TOTPSecret:
        """Add a new TOTP secret to the Open2FA object.
        Args:
            secret (str): the TOTP secret
            name (str): the name of the secret
        Returns:
            TOTPSecret: the new TOTPSecret object
        """
        for s in self.secrets:
            if s.name == name and s.secret == secret:
                raise EX.SecretExistsError(
                    'Secret name={} secret={} already exists'.format(
                        name, sec_trunc(secret)
                    )
                )

        new_secret = TOTPSecret(secret, name)
        self.secrets.append(new_secret)
        self.write_secrets()
        return new_secret

    def remove_secret(self, *args, **kwargs):
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
        force = kwargs.get('force', False)
        del_vals = args
        for s in self.secrets:
            if (
                s.name is not None
                and s.name in del_vals
                or s.secret in del_vals
            ):
                if force:
                    continue

                if (
                    input(
                        MSGS.CONFIRM_REMOVE.format(s.name, sec_trunc(s.secret))
                    )
                    .lower()
                    .startswith('y')
                ):
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
            Generator[TOTPSecret, None, None]: the TOTPSecret object[s]
        """
        for s in self.secrets:
            s.generate_code()
            if name is None or s.name == name:
                yield s

    def write_secrets(self) -> None:
        """Write the secrets to the secrets.json file."""
        write_secrets_json(
            self.secrets_json_path, [s.json() for s in self.secrets]
        )

    @logf(use_print=True)
    def remote_push(self) -> TYPE.List[TOTPSecret]:
        """Push the secrets to the remote server."""
        if self.o2fa_uuid is None:
            raise EX.NoUUIDError()

        remote = self.o2fa_uuid.remote
        uhash = self.o2fa_uuid.o2fa_id
        enc_secrets = [
            {'enc_secret': remote.encrypt(s.secret), 'name': s.name}
            for s in self.secrets
            if s.name != 'pypi'
        ]
        r = req.post(
            self.remote_url + '/totps',
            headers={'X-User-Hash': uhash},
            json={'totps': enc_secrets},
        )
        if r.status_code != 200:
            raise EX.RemoteError(
                'Remote server returned: {} {} {}'.format(
                    r.status_code, r.reason, r.text
                )
            )
        new_secrets = []
        for sec in r.json()['totps']:
            new_sec = TOTPSecret(
                remote.decrypt(sec['enc_secret']), sec['name']
            )
            new_secrets.append(new_sec)
        return new_secrets

    @logf(use_print=True)
    def remote_pull(self) -> TYPE.List[TOTPSecret]:
        """Pull the secrets from the remote server."""
        if self.o2fa_uuid is None:
            raise EX.NoUUIDError()

        remote = self.o2fa_uuid.remote
        uhash = self.o2fa_uuid.o2fa_id
        r = req.get(self.remote_url + '/totps', headers={'X-User-Hash': uhash})
        if r.status_code != 200:
            raise EX.RemoteError(
                'Remote server returned: {} {} {}'.format(
                    r.status_code, r.reason, r.text
                )
            )
        new_secrets = []
        for sec in r.json()['totps']:
            new_sec = TOTPSecret(
                remote.decrypt(sec['enc_secret']), sec['name']
            )
            new_secrets.append(new_sec)
        return new_secrets