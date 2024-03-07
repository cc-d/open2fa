import json
import os
import uuid
import os.path as osp
import typing as TYPE
import time
import sys
from pathlib import Path
from signal import signal, SIGWINCH

import requests as req
from shutil import get_terminal_size
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

        self.o2fa_uuid = None
        if o2fa_uuid is not None:
            self.o2fa_uuid = O2FAUUID(o2fa_uuid)

        self.o2fa_api_url = (
            o2fa_api_url
            if o2fa_api_url is not None
            else config.OPEN2FA_API_URL
        )

    @logf()
    def set_uuid(self, uuid: str) -> O2FAUUID:
        """Set the Open2FA UUID attribute to O2FAUUID(uuid)"""
        self.o2fa_uuid = O2FAUUID(uuid)
        return self.o2fa_uuid

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
            if name is None or str(s.name).find(name) != -1:
                yield s

    def display_codes(
        self,
        repeat: TYPE.Optional[int] = None,
        name: TYPE.Optional[str] = None,
        delay: float = 0.5,
    ):
        """
        Live generate and display 2FA codes for the Open2FA object.
        ~repeat (Optional[int]): Number of 2FA code generation iterations.
            Default: None (infinite).
        ~name (Optional[str]): Only generate for secrets matching this name.
            Default: None (all secrets).
        ~delay (float): Time between code generation iterations.
            Default: 0.5 seconds.
        """

    def display_codes(
        self,
        repeat: TYPE.Optional[int] = None,
        name: TYPE.Optional[str] = None,
        delay: float = 0.5,
    ):
        """
        Live generate and display 2FA codes for the Open2FA object.
        ~repeat (Optional[int]): Number of 2FA code generation iterations.
        ~name (Optional[str]): Only generate for secrets matching this name.
        ~delay (float): Time between code generation iterations.
        """
        prev_lines = 0
        try:
            _sep = '    '
            name_pool = [str(s.name) for s in self.secrets]
            if name is not None:
                name_pool = [n for n in name_pool if n.find(name) != -1]
            MAXH = 0
            while repeat is None or repeat > 0:
                tsize = get_terminal_size()
                TW, TH = tsize.columns, tsize.lines
                TW, TH = max(TW, 30), max(TH, 4)
                MAXH = max(MAXH, TH)

                name_w = max(10, max(len(n) for n in name_pool))
                MAX_NAME_W = TW - (len(_sep) * 2) - 6 - 5
                widths = [min(name_w, MAX_NAME_W), 6, 5]
                buffer = []

                # Move up the cursor to the top of the previous output
                if prev_lines > 0:
                    sys.stdout.write('\033[F' * prev_lines)
                    sys.stdout.flush()
                    if MAXH > TH:
                        for _ in range(MAXH - TH):
                            print(''.ljust(TW) + '\n')

                # Header
                header = _sep.join(
                    [
                        'Name'.ljust(widths[0]),
                        'Code'.ljust(widths[1]),
                        'Next'.ljust(widths[2]),
                    ]
                )
                buffer.append(header)
                buffer.append(_sep.join(['-' * w for w in widths]))

                # Generate and display codes
                for s in self.generate_codes(name):
                    secret_name = (
                        truncstr(str(s.name), start_chars=MAX_NAME_W - 3)
                        if len(str(s.name)) > MAX_NAME_W
                        else str(s.name)
                    )
                    row = [
                        secret_name.ljust(widths[0]),
                        s.code.code.ljust(widths[1]),
                        '%.2f' % s.code.next_interval_in,
                    ]
                    buffer.append(_sep.join(row))
                    if (len(buffer)) >= TH - 2:
                        break

                # Footer
                if len(name_pool) > len(buffer) - 2:
                    buffer.append(
                        MSGS.GEN_CODES_NOT_SHOWN.format(
                            len(name_pool) - len(buffer) + 2
                        )
                    )

                # Print buffer and remember the number of lines printed
                print('\n'.join(buffer))
                sys.stdout.flush()
                prev_lines = len(buffer)

                time.sleep(delay)
                if repeat is not None:
                    repeat -= 1

        except KeyboardInterrupt:
            print("\nCancelled by user.")

    @logf()
    def write_secrets(self) -> None:
        """Write the secrets to the secrets.json file."""
        write_secrets_json(
            self.secrets_json_path, [s.json() for s in self.secrets]
        )

    @logf()
    def remote_push(self) -> TYPE.List[TOTPSecret]:
        """Push the secrets to the remote server."""
        if getattr(self, 'o2fa_uuid', None) is None:
            raise EX.NoUUIDError()

        remote = self.o2fa_uuid.remote
        uhash = self.o2fa_uuid.o2fa_id
        enc_secrets = [
            {'enc_secret': remote.encrypt(s.secret), 'name': s.name}
            for s in self.secrets
        ]
        r = apireq(
            'POST',
            'totps',
            data={'totps': enc_secrets},
            headers={'X-User-Hash': uhash},
            api_url=self.o2fa_api_url,
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
            api_url=self.o2fa_api_url,
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
            api_url=self.o2fa_api_url,
            data={
                'totps': [
                    {
                        'name': getattr(delsec, 'name', None),
                        'enc_secret': self.o2fa_uuid.remote.encrypt(
                            delsec.secret
                        ),
                    }
                ]
            },
        )
        return int(resp.data['deleted'])

    @logf()
    def cli_info(self, show_secrets: bool) -> None:
        """Prints the Open2FA info."""
        o_dir = self.o2fa_dir
        o_api_url = self.o2fa_api_url or config.OPEN2FA_API_URL

        def itrunc(s):
            return str(s)[0] + '...' if show_secrets is False else str(s)

        o_num_secrets = len(self.secrets)
        o_uuid_str, o_id, o_secret = None, None, None
        if self.o2fa_uuid:
            o_uuid_str = itrunc(self.o2fa_uuid.uuid)
            o_id = itrunc(self.o2fa_uuid.o2fa_id)
            o_secret = itrunc(self.o2fa_uuid.remote.b58)
        msg = MSGS.INFO_STATUS
        if show_secrets is True:
            msg = msg.replace(MSGS.INFO_SEC_TIP + '\n', '')
        print(
            msg.format(
                o_dir, o_api_url, o_num_secrets, o_uuid_str, o_id, o_secret
            )
        )

    @logf()
    def remote_init(self) -> TYPE.Optional[O2FAUUID]:
        """Handles initialization of remote capabilities of Open2FA instance
        Returns:
            O2FAUUID: the Open2FA UUID if newly created else None
        """
        uuid_file_path = os.path.join(self.o2fa_dir, 'open2fa.uuid')

        if self.o2fa_uuid is not None:
            print(MSGS.INIT_UUID_SET)
            return

        if os.path.exists(uuid_file_path):
            with open(uuid_file_path, 'r') as uuid_file:
                self.o2fa_uuid = O2FAUUID(uuid_file.read().strip())
            print(MSGS.INIT_FOUND_UUID.format(self.o2fa_uuid))
        else:
            user_response = input(MSGS.INIT_CONFIRM)
            if user_response.lower() == 'y':
                # Generate new UUID, set it, and write to file
                self.set_uuid(str(uuid.uuid4()))

                with open(uuid_file_path, 'w') as uuid_file:
                    uuid_file.write(str(self.o2fa_uuid.uuid))

                os.chmod(uuid_file_path, config.OPEN2FA_KEY_PERMS)
                print(MSGS.INIT_SUCCESS.format(str(self.o2fa_uuid.uuid)))
                return self.o2fa_uuid
            else:
                print(MSGS.INIT_FAIL)

    def __repr__(self) -> str:
        return default_repr(
            self, repr_format='<{obj_name} {attributes}>', join_attrs_on=' '
        )
