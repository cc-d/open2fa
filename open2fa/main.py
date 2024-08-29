import json
import os
import uuid
import os.path as osp
import typing as TYPE
import time
import sys
import logging
from binascii import Error as BinError
from functools import wraps
from pathlib import Path
from signal import signal, SIGWINCH

import requests as req
from shutil import get_terminal_size
from logfunc import logf
from pyshared import truncstr, default_repr
from getpass import getpass

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
from .utils import (
    ApiResponse,
    apireq,
    sec_trunc,
    input_confirm,
    valid_totp_secret as valid_sec,
)

_log = logging.getLogger(__name__)


@logf()
def _uinput() -> TYPE.Tuple[str, TYPE.Union[str, None]]:
    """Get user input for the secret and name."""
    secret = getpass('Enter the TOTP secret: ')
    if not valid_sec(secret):
        raise ValueError('Invalid User Input secret: %s' % secret)
    name = input('Enter the name of the secret: ')
    return secret, name


@logf()
def _add_secinput(*args) -> TYPE.Tuple[str, TYPE.Union[str, None]]:
    """Parse the secret and name arguments."""
    if len(args) == 0 or set(args[0:2]) == {None}:
        return tuple(_uinput())
    if valid_sec(args[0]):
        return args[0], args[1] if len(args) > 1 else None
    elif len(args) > 1 and valid_sec(args[1]):
        return args[1], args[0]
    raise ValueError('Invalid secret/name arguments: %s' % str(args))


class Open2FA:
    o2fa_dir: str
    secrets_json_path: str
    o2fa_uuid: TYPE.Union[O2FAUUID, None]
    o2fa_api_url: TYPE.Union[str, None]

    remote_secrets: TYPE.List[TOTPSecret]
    secrets: TYPE.List[TOTPSecret] = []

    def __init__(
        self,
        o2fa_dir: TYPE.Union[str, Path] = config.OPEN2FA_DIR,
        o2fa_uuid: TYPE.Optional[str] = None,
        o2fa_api_url: TYPE.Optional[str] = None,
        **kwargs,
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

    @logf(max_str_len=50)
    def add_secret(self, *args) -> TOTPSecret:
        """Add a new TOTP secret to the Open2FA object.
        ~secret (str): the TOTP secret
        ~name (str): the name of the secret
        -> TOTPSecret: the new TOTPSecret object
        """
        sec, name = _add_secinput(*args)

        new_secret = TOTPSecret(sec, name)
        self.secrets.append(new_secret)
        self.write_secrets()
        return new_secret

    @logf()
    def remove_secret(
        self,
        name: TYPE.Optional[str] = None,
        sec: TYPE.Optional[str] = None,
        skip_confirm: bool = False,
    ) -> int:
        """Remove a TOTP secret from the Open2FA object.
        name (str, optional): the name of the secret to remove
        sec (str, optional): the secret to remove
        int: the number of secrets removed
        skip_confirm (bool): Skip the confirmation prompt.
        """
        new_secrets = []
        _seclen = len(self.secrets)
        for s in self.secrets:
            remove = False
            str_name, str_secret = str(s.name), str(s.secret)
            if sec is not None:
                if str_secret == sec:
                    if skip_confirm or input_confirm(
                        MSGS.CONFIRM_REMOVE.format(str_name, str_secret)
                    ):
                        remove = True
            if name is not None:
                if str_name == name:
                    if skip_confirm or input_confirm(
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
    ) -> TYPE.Generator[TOTPSecret, None, None]:
        """Generate TOTP 2FA codes for a specific secret.
        name (str, optional): the name of the secret to generate a code for
            if excluded, codes for all secrets will be generated
        YIELDS: Generator[TOTPSecret, None, None]: the TOTPSecret object[s]
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
        """Live generate and display 2FA codes for the Open2FA object.
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
            print(f'\n{MSGS.CTRL_C}\n')
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

                if repeat is not None:
                    repeat -= 1
                if repeat != 0:
                    time.sleep(delay)

        except KeyboardInterrupt:
            print(f"\n{MSGS.SIGINT_MSG}\n")

    @logf()
    def write_secrets(self) -> None:
        """Write the secrets to the secrets.json file."""
        write_secrets_json(
            self.secrets_json_path, [s.json() for s in self.secrets]
        )

    @property
    def remote(self) -> TYPE.Union[RemoteSecret, None]:
        """Shortcut for open2fa.o2fa_uuid.remote"""
        return getattr(self.o2fa_uuid, 'remote', None)

    @logf()
    def remote_push(
        self,
        name: TYPE.Optional[str] = None,
        secret: TYPE.Optional[str] = None,
        skip_confirm: bool = True,
    ) -> TYPE.List[TOTPSecret]:
        """Push the secrets to the remote server. If secret/name is provided,
        only secrets with name/secrets containing the secret/name as
        a substring will be pushed.
        ?name (str]): Only push secrets containing this name.
        ?secret (str): Only push secrets containing this secret.
        @skip_confirm (bool): Skip the confirmation prompt.
            Default: True
        -> TOTPSecret[]: The new secrets pushed to the remote server.
        """
        if getattr(self, 'o2fa_uuid', None) is None:
            raise EX.NoUUIDError()

        localsecs = list(self.secrets)
        for a in [x for x in [name, secret] if x is not None]:
            _log.debug(
                'filtering local secrets %s without %s' % (localsecs, a)
            )
            localsecs = [s for s in localsecs if a in getattr(s, a)]

        uhash = self.o2fa_uuid.o2fa_id

        enc_secrets = [
            {'enc_secret': self.remote.encrypt(s.secret), 'name': s.name}
            for s in localsecs
        ]

        if not skip_confirm:
            print(
                'Pushing the following secrets to the remote server:\n',
                json.dumps(enc_secrets, indent=2),
            )
            if input('Continue? (y/n): ').lower() != 'y':
                return []

        r = apireq(
            'POST',
            'totps',
            data={
                'totps': [s.enc_json(self.remote.encrypt) for s in localsecs]
            },
            headers={'X-User-Hash': uhash},
            api_url=self.o2fa_api_url,
        )
        new_secrets = []
        for sec in r.data['totps']:
            new_sec = TOTPSecret(
                self.remote.decrypt(sec['enc_secret']), sec['name']
            )
            new_secrets.append(new_sec)
        return new_secrets

    @logf()
    def has_secret(self, secret: str, name: str) -> bool:
        """Check if a secret exists in the Open2FA object."""
        for s in self.secrets:
            if s.secret == secret and s.name == name:
                return True
        return False

    @logf()
    def remote_pull(
        self, no_save_remote: bool = False
    ) -> TYPE.List[TOTPSecret]:
        """Pull the secrets from the remote server.
        ~return_only (bool): Only return the new secrets, do not write to file
            or update the Open2FA object. Default: False
        """
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
        pull_secrets = [
            TOTPSecret(remote.decrypt(s['enc_secret']), s['name'])
            for s in api_resp.data['totps']
        ]

        # duplicate secrets are filtered out
        new_secs = [
            s for s in pull_secrets if not self.has_secret(s.secret, s.name)
        ]

        # Only return the secrets without saving, used in remote info
        if no_save_remote:
            _log.debug('Returning pull_secrets no save: %s' % pull_secrets)
            return pull_secrets

        _log.debug('saving new secrets: %s' % new_secs)

        self.secrets.extend(new_secs)
        self.write_secrets()
        return pull_secrets

    @property
    def remote_secrets(self) -> TYPE.List[TOTPSecret]:
        """Returns non-save self.remote_pull()"""
        return self.remote_pull(no_save_remote=True)

    @property
    def uuid(self) -> TYPE.Union[str, None]:
        """Return the Open2FA UUID."""
        if hasattr(self, 'o2fa_uuid') and self.o2fa_uuid is not None:
            return str(self.o2fa_uuid.uuid)

    @property
    def uuid_file_path(self) -> str:
        """Return the Open2FA UUID file path."""
        return os.path.join(self.o2fa_dir, 'open2fa.uuid')

    @wraps(RemoteSecret.encrypt)
    def encrypt(self, *args, **kwargs):
        if hasattr(self, 'remote') and hasattr(self.remote, 'encrypt'):
            return self.remote.encrypt(*args, **kwargs)

    encrypt.__doc__ = RemoteSecret.encrypt.__doc__

    @property
    def decrypt(self, *args, **kwargs):
        """shortcut for open2fa.o2fa_uuid.remote.decrypt"""
        if hasattr(self, 'remote') and hasattr(self.remote, 'decrypt'):
            return self.remote.decrypt(*args, **kwargs)

    @property
    def dir(self) -> str:
        """abspath of self.o2fa_dir"""
        return str(osp.abspath(self.o2fa_dir))

    @property
    def api_url(self) -> TYPE.Union[str, None]:
        """shorthand for self.o2fa_api_url"""
        return self.o2fa_api_url

    def refresh(self) -> 'Open2FA':
        """Return most-recent new Open2FA object of the current instance."""
        # create new o2fa object with the same attributes
        self = Open2FA(
            o2fa_dir=self.o2fa_dir,
            o2fa_uuid=self.uuid,
            o2fa_api_url=self.api_url,
        )
        return self

    @logf()
    def remote_delete(
        self,
        secret: TYPE.Optional[str] = None,
        name: TYPE.Optional[str] = None,
    ) -> int:
        """Delete the remote secrets.

        secret (str, optional): the secret to delete
        name (str, optional): the name of the secret to delete
        -> int: the number of secrets deleted
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

        margs = (o_dir, o_api_url, o_num_secrets, o_uuid_str, o_id, o_secret)
        msg = MSGS.INFO_STATUS
        if show_secrets is True:
            msg = msg.replace(MSGS.INFO_SEC_TIP + '\n', '')

        print(msg.format(*margs))
        if self.o2fa_uuid is not None:
            remote_secrets = self.remote_pull(no_save_remote=True)
            print('Remote Secrets: %s' % len(remote_secrets))
            for s in remote_secrets:
                print(s.name, itrunc(s.secret))

    @logf()
    def remote_init(self) -> TYPE.Optional[O2FAUUID]:
        """Handles initialization of remote capabilities of Open2FA instance
        -> O2FAUUID: the Open2FA UUID if newly created else None
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
