import json
import os
import os.path as osp
import typing as TYPE
from pathlib import Path

import requests as req
from logfunc import logf
from pyshared import truncstr, default_repr

from . import config
from . import ex as EX
from . import msgs as MSGS
from .cli_utils import (
    ensure_open2fa_dir,
    ensure_secrets_json,
    read_secrets_json,
    write_secrets_json,
)
from .common import O2FAUUID, RemoteSecret, TOTPSecret
from .totp import TOTP2FACode, generate_totp_2fa_code
from .utils import ApiResponse, apireq, sec_trunc, input_confirm


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

    @logf()
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

    @logf()
    def remove_secret(
        self,
        name: TYPE.Optional[str] = None,
        sec: TYPE.Optional[str] = None,
        force: bool = False,
    ) -> int:
        """Remove a TOTP secret from the Open2FA object.
        Args:
            name (str, optional): the name of the secret to remove
            sec (str, optional): the secret to remove
            force (bool): whether to remove the secret without confirmation
                Default: False
        Returns:
            int: the number of secrets removed
        """
        new_secrets = []
        _seclen = len(self.secrets)
        for s in self.secrets:
            remove = False
            str_name, str_secret = str(s.name), str(s.secret)
            if sec is not None:
                if str_secret == sec:
                    if force or input_confirm(
                        MSGS.CONFIRM_REMOVE.format(str_name, str_secret)
                    ):
                        remove = True
            if name is not None:
                if str_name == name:
                    if force or input_confirm(
                        MSGS.CONFIRM_REMOVE.format(str_name, str_secret)
                    ):
                        remove = True
            if not remove:
                new_secrets.append(s)
        self.secrets = new_secrets
        self.write_secrets()
        return _seclen - len(new_secrets)

    @logf()
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

    @logf()
    def write_secrets(self) -> None:
        """Write the secrets to the secrets.json file."""
        write_secrets_json(
            self.secrets_json_path, [s.json() for s in self.secrets]
        )

    @logf()
    def remote_push(self) -> TYPE.List[TOTPSecret]:
        """Push the secrets to the remote server."""
        if self.o2fa_uuid is None:
            raise EX.NoUUIDError()

        remote = self.o2fa_uuid.remote
        uhash = self.o2fa_uuid.o2fa_id
        enc_secrets = [
            {'enc_secret': remote.encrypt(s.secret), 'name': s.name}
            for s in self.secrets
            # remove before deployment
            if str(s.name).lower() != 'pypi'
        ]
        r = apireq(
            'POST',
            'totps',
            data={'totps': enc_secrets},
            headers={'X-User-Hash': uhash},
            api_url=self.remote_url,
        )
        new_secrets = []
        for sec in r.data['totps']:
            new_sec = TOTPSecret(
                remote.decrypt(sec['enc_secret']), sec['name']
            )
            new_secrets.append(new_sec)
        return new_secrets

    @logf()
    def remote_pull(self) -> TYPE.List[TOTPSecret]:
        """Pull the secrets from the remote server."""
        if self.o2fa_uuid is None:
            raise EX.NoUUIDError()

        remote = self.o2fa_uuid.remote
        uhash = self.o2fa_uuid.o2fa_id
        api_resp = apireq(
            'GET',
            'totps',
            headers={'X-User-Hash': uhash},
            api_url=self.remote_url,
        )
        new_secrets = []
        for sec in api_resp.data['totps']:
            new_sec = TOTPSecret(
                remote.decrypt(sec['enc_secret']), sec['name']
            )
            new_secrets.append(new_sec)
            self.secrets.append(new_sec)
        self.write_secrets()
        return new_secrets

    @logf()
    def remote_delete(
        self,
        secret: TYPE.Optional[str] = None,
        name: TYPE.Optional[str] = None,
    ) -> int:
        """Delete the remote secrets.
        Args:
            secret (str, optional): the secret to delete
            name (str, optional): the name of the secret to delete
        Returns:
            int: the number of secrets deleted
        """
        if self.o2fa_uuid is None:
            raise EX.NoUUIDError()

        if secret is None and name is None:
            raise EX.DelNoNameSec()

        delsec = None

        for s in self.secrets:
            if secret is not None and s.secret == secret:
                delsec = s
                break
            elif name is not None and s.name == name:
                delsec = s
                break

        if delsec is None:
            raise EX.DelNoNameSecFound()

        uhash = self.o2fa_uuid.o2fa_id
        resp = apireq(
            'DELETE',
            'totps',
            headers={'X-User-Hash': uhash},
            api_url=self.remote_url,
            data={
                'totps': [{
                    'name': getattr(delsec, 'name', None),
                    'enc_secret': self.o2fa_uuid.remote.encrypt(delsec.secret),
                }]
            },
        )
        return int(resp.data['deleted'])

    def __repr__(self) -> str:
        return default_repr(
            self, repr_format='<{obj_name} {attributes}>', join_attrs_on=' '
        )
