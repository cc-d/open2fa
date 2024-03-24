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

    yield _tmpdir


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
    if osp.exists(randir):
        rmtree(randir, ignore_errors=True)
    if osp.exists(_DIR):
        rmtree(_DIR, ignore_errors=True)


def exec_cmd(cmd: list, client: Open2FA) -> tuple[Open2FA, str]:
    cmd = ['cli.py'] + [str(c) for c in cmd]

    with patch('sys.argv', cmd), patch(
        'sys.stdout', new_callable=StringIO
    ) as out:

        client = main(
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

        if confirm == 'y':
            assert o2fa.has_secret(secret[0], secret[1]) is False
        else:
            print(o2fa.secrets)
            assert o2fa.has_secret(secret[0], secret[1])


@pt.mark.parametrize('cmd', [['g', '-h'], ['generate', '-r', '1']])
def test_generate_cmd(cmd: list[str], local_client: Open2FA):
    if '-h' in cmd:
        _handle_dash_h(cmd, local_client)
        return
    o2fa, out = exec_cmd(cmd, local_client)
    for head_cell in ['Name', 'Code', 'Next']:
        assert head_cell in out
    out = out.splitlines()
    out = [l for l in out if l.find('---') == -1]
    for head_cell in ['Name', 'Code', 'Next']:
        assert head_cell in out[0]
    out = out[1:]
    sec_names = [str(sec[1]) for sec in _SECRETS]
    for line in out:
        assert len(line.split()) == 3
        assert line.split()[0] in sec_names
        assert len(line.split()[1]) == 6
        assert float(line.split()[2]) > 0


# remote command tests
@pt.fixture
def remote_client(randir: str):
    client = Open2FA(o2fa_dir=randir, o2fa_uuid=None, o2fa_api_url=_URL)
    with patch('sys.argv', ['cli.py', 'remote', 'init']):
        o2fa = main(
            o2fa_dir=client.o2fa_dir,
            o2fa_api_url=client.api_url,
            return_open2fa=True,
        )
    yield o2fa
    if osp.exists(randir):
        rmtree(randir, ignore_errors=True)


@pt.fixture
def rclient_w_secrets(remote_client: Open2FA):
    _ENC_SECRETS = [
        {'enc_secret': remote_client.encrypt(sec[0]), 'name': sec[1]}
        for sec in _SECRETS
    ]
    with patch('open2fa.main.apireq') as mock_apireq:
        mock_apireq.return_value = MagicMock(
            status_code=200, data={'totps': _ENC_SECRETS}
        )
        remote_client.remote_pull()
        yield remote_client


def test_remote_init(remote_client: Open2FA):
    assert remote_client.uuid is not None


def test_remote_pull(rclient_w_secrets: Open2FA):
    assert len(rclient_w_secrets.secrets) == len(_SECRETS)
    for sec in _SECRETS:
        assert rclient_w_secrets.has_secret(sec[0], sec[1])


@pt.mark.parametrize('dash_s', [True, False])
def test_cli_info_cmd(rclient_w_secrets: Open2FA, dash_s: bool):
    rclient = rclient_w_secrets
    with patch('open2fa.main.print') as mock_print:
        rclient.cli_info(dash_s)
        calls = [c[0] for c in mock_print.call_args_list]
    secs, secnames = [sec[0] for sec in _SECRETS], [sec[1] for sec in _SECRETS]
    for sec in _SECRETS:
        assert sec[0] in secs
        assert sec[1] in secnames


def test_remote_push(rclient_w_secrets: Open2FA):
    with patch('open2fa.main.apireq') as mock_apireq:
        with patch('sys.argv', ['cli.py', 'remote', 'push']):
            rclient_w_secrets.remote_push()

    assert mock_apireq.call_count == 1
    mock_api_req_args = mock_apireq.call_args[0]
    assert mock_api_req_args[0] == 'POST'
    assert mock_api_req_args[1] == 'totps'
    _ENC_SECRETS = [
        {'enc_secret': rclient_w_secrets.encrypt(sec[0]), 'name': sec[1]}
        for sec in _SECRETS
    ]
    for sec in _ENC_SECRETS:
        assert sec in mock_apireq.call_args[1]['data']['totps']


@pt.mark.parametrize('cmd', [['remote', 'list'], ['remote', 'list', '-s']])
def test_remote_list(rclient_w_secrets: Open2FA, cmd: list[str]):
    _ENC_SECRETS = [
        {'enc_secret': rclient_w_secrets.encrypt(sec[0]), 'name': sec[1]}
        for sec in _SECRETS
    ]
    with patch('sys.argv', ['cli.py'] + cmd):
        with patch('open2fa.main.apireq') as mock_apireq:
            mock_apireq.return_value = MagicMock(
                status_code=200, data={'totps': _ENC_SECRETS}
            )
            with patch('builtins.print') as mock_print:
                o2fa = main(
                    o2fa_dir=rclient_w_secrets.dir,
                    o2fa_api_url=rclient_w_secrets.api_url,
                    o2fa_uuid=rclient_w_secrets.uuid,
                    return_open2fa=True,
                )
            pcalls = [c[0] for c in mock_print.call_args_list]
            pcalls = [p for p in pcalls if p and len(p) > 0]
            pcalls = [p[0] for p in pcalls]
            pcalls = ''.join(pcalls)
            for sec in _SECRETS:
                if '-s' in cmd:
                    assert sec[0] in pcalls
                else:
                    assert sec[0] not in pcalls
                    assert sec[0][0] + '...' in pcalls


def test_remote_delete(rclient_w_secrets: Open2FA):
    _ENC_SECRETS = [
        {'enc_secret': rclient_w_secrets.encrypt(sec[0]), 'name': sec[1]}
        for sec in _SECRETS
    ]
    with patch('open2fa.main.apireq') as mock_apireq:
        with patch(
            'sys.argv', ['cli.py', 'remote', 'delete', '-s', _SECRETS[0][0]]
        ):
            rclient_w_secrets.remote_delete(
                secret=_SECRETS[0][0], name=_SECRETS[0][1]
            )
    assert mock_apireq.call_count == 1
    mock_api_req_args = mock_apireq.call_args[0]
    assert mock_api_req_args[0] == 'DELETE'
    assert mock_api_req_args[1] == 'totps'
    assert mock_apireq.call_args[1]['data'] == {'totps': [_ENC_SECRETS[0]]}
