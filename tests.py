import pytest as pt
from io import StringIO
from unittest.mock import patch, MagicMock

import os
import os.path as osp

from shutil import rmtree
from typing import Union as U, Generator as Gen
from uuid import UUID, uuid4
import base64 as _b64
import secrets as _secs

from open2fa.cli import Open2FA, main, sys
from open2fa.main import apireq, _uinput
from open2fa.common import TOTP2FACode, RemoteSecret, O2FAUUID, TOTPSecret
from open2fa import ex as EX
from open2fa import msgs as MSGS
from open2fa.version import __version__
from open2fa.cli_utils import parse_cli_arg_aliases as pargs

# Assuming ranstr function exists for generating random strings
from pyshared import ranstr

_TOTP, _NAME, _URL, _DIR, _UUID = (
    'I65VU7K5ZQL7WB4E',
    'DefaultSecret',
    'http://test',
    '/tmp/' + ranstr(10),
    str(uuid4()),
)
_OP2FA = Open2FA(_DIR, _UUID, _URL)
_SECRETS = [
    ('RRGADJF5GXWRRXWY', 'Name0'),
    ('AOJPJPFNP7MQZR5I', 'Name1'),
    ('X4NTOY77HQV3BPCY', 'Name2'),
    ('RMA7DSSV7RO6JQQP', 'Name3'),
    ('W75HGIFLWBU757SU', None),
    ('ZU6FRTLEONDMFSPDRAZZ7FMLXS4IRNWP', 'LongSecret0'),
    ('LYMXJUCIIIJWFRTX', 'Name4'),
    ('B6ED2USGCIJXPUID', 'Name5'),
    ('FRDCHVCFASMUCWZZ', 'Name6'),
]
# add encrypted secrets to _SECRETS
_SECRETS = [(sec[0], sec[1], _OP2FA.encrypt(sec[0])) for sec in _SECRETS]

_ENC_SECRETS = [
    {'enc_secret': _OP2FA.encrypt(sec[0]), 'name': sec[1]} for sec in _SECRETS
]


def _totp(length: int = 32) -> str:
    """Generate a random base32-encoded TOTP secret of the specified length."""
    random_bytes = _secs.token_bytes(length)
    return _b64.b32encode(random_bytes).decode()


@pt.fixture()
def ranuuid():
    """Fixture to generate a random UUID for testing."""
    yield str(uuid4())


@pt.fixture()
def randir():
    """Fixture to generate a random directory path for testing."""
    _tmpdir = '/tmp/' + ranstr(10)
    if not osp.exists(_tmpdir):
        os.mkdir(_tmpdir)

    yield _tmpdir
    if osp.exists(_tmpdir):
        rmtree(_tmpdir, ignore_errors=True)


@pt.fixture()
def local_client(ranuuid: str, randir: str):
    """Fixture to create a TOTPSecret instance for testing."""
    o2fa = Open2FA(
        o2fa_dir=randir, o2fa_uuid=ranuuid, o2fa_api_url='http://test'
    )
    for sec in _SECRETS:
        if sec not in o2fa.secrets:
            o2fa.add_secret(sec[0], sec[1])
    yield o2fa


@pt.fixture
def remote_client(local_client: Open2FA):
    """Fixture to create a RemoteSecret instance for testing."""
    with patch('open2fa.main.apireq') as mock_apireq:
        mock_apireq.return_value = _ENC_SECRETS
        local_client.remote_pull()

    yield local_client


def exec_cmd(cmd: list, client: Open2FA) -> tuple[Open2FA, str]:
    cmd = ['cli.py'] + [str(c) for c in cmd]

    with patch('sys.argv', cmd), patch(
        'sys.stdout', new_callable=StringIO
    ) as out:

        main(
            o2fa_api_url=client.api_url,
            o2fa_dir=client.o2fa_dir,
            return_open2fa=True,
            o2fa_uuid=client.uuid,
        )

        return client, out.getvalue()


def _handle_dash_h(cmd: list[str], client: Open2FA):
    with patch('sys.stdout', new_callable=StringIO) as out:
        with pt.raises(SystemExit):
            exec_cmd(cmd, client)
            out = out.getvalue()
            assert 'usage: ' in out


@pt.mark.parametrize('cmd', [['list'], ['list', '-s'], ['list', '-h']])
def test_list_cmd(cmd: list[str], local_client: Open2FA):
    if '-h' in cmd:
        _handle_dash_h(cmd, local_client)
    else:
        o2fa, out = exec_cmd(cmd, local_client)
        assert len(o2fa.secrets) == len(_SECRETS)
        for sec in _SECRETS:
            if '-s' in cmd:
                assert sec[0] in out
            else:
                assert sec[0] not in out
                assert sec[0][0] + '...' in out


@pt.mark.parametrize(
    'cmd',
    [
        ['add', _totp(), '-n', 'unique_secret_dash_n'],
        ['add', _totp(), 'unique_secret_no_dash_n'],
        ['add', '-h'],
        ['add', _totp(), _totp() + 'unique_secret_and_name_no_dashes'],
        ['add', tuple()],
        ['add', (_totp(),)],
        ['add', (_TOTP, _NAME)],
    ],
)
def test_add_cmd(cmd: list[str], local_client: Open2FA):
    # no params
    if '-h' in cmd:
        _handle_dash_h(cmd, local_client)
    # empty add
    elif cmd[0] == 'add' and len(cmd) >= 1 and isinstance(cmd[1], tuple):
        with patch('open2fa.main._uinput') as mock_input:
            mock_input.return_value = cmd[1]
            with patch('sys.argv', ['cli.py', 'add']):
                if len(cmd[1]) < 2:
                    with pt.raises(ValueError):
                        main(
                            o2fa_api_url=local_client.api_url,
                            o2fa_dir=local_client.dir,
                        )
                    return
                o2fa = main(
                    o2fa_api_url=local_client.api_url,
                    o2fa_dir=local_client.dir,
                    return_open2fa=True,
                )
                assert o2fa.has_secret(
                    cmd[1][0], None if len(cmd[1]) < 2 else cmd[1][1]
                )
    else:
        o2fa, out = exec_cmd(cmd, local_client)
        assert cmd[1][0] + '...' in out
        assert cmd[-1] in out


from open2fa.utils import input_confirm


@pt.mark.parametrize(
    'cmd, secret, confirm',
    [
        (['delete', '-s', _SECRETS[0][0]], _SECRETS[0], 'n'),
        (['delete', '-s', _SECRETS[0][0]], _SECRETS[0], 'y'),
        (['delete', '-n', _SECRETS[1][1]], _SECRETS[1], 'y'),
        (['delete', '-h'], None, 'y'),
        (['delete', '--name', _SECRETS[2][1]], _SECRETS[2], 'y'),
        (['delete', '--secret', _SECRETS[3][0]], _SECRETS[3], 'y'),
        (['delete', _SECRETS[4][0]], _SECRETS[4], 'y'),
    ],
)
def test_delete_cmd(
    cmd: list[str],
    secret: tuple[str, str, str],
    confirm: str,
    local_client: Open2FA,
):
    if '-h' in cmd:
        _handle_dash_h(cmd, local_client)
    else:
        # incorrect args should raise error
        if not cmd[1].startswith('-'):
            with pt.raises(SystemExit):
                o2fa, out = exec_cmd(cmd, local_client)
            return

        with patch('builtins.input', return_value=confirm) as mock_input:
            print('mock_input', mock_input, 'cmd', cmd)
            o2fa, out = exec_cmd(cmd, local_client)
        o2fa = o2fa.refresh()

        if confirm == 'y':
            assert o2fa.has_secret(secret[0], secret[1]) is False
        else:
            print(o2fa.secrets)
            assert o2fa.has_secret(secret[0], secret[1])
