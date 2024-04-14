import pytest as pt
from io import StringIO
from unittest.mock import patch, MagicMock
from functools import wraps

import os
import os.path as osp

from shutil import rmtree
from typing import Union as U, Generator as Gen, Callable as Call, Any
from uuid import UUID, uuid4
import base64 as _b64
import secrets as _secs

from pyshared import multiscope_fixture as scope_fixture, ranstr
from open2fa.cli import Open2FA, main, sys
from open2fa.main import apireq, _uinput
from open2fa.common import TOTP2FACode, RemoteSecret, O2FAUUID, TOTPSecret
from open2fa import ex as EX
from open2fa import msgs as MSGS
from open2fa.version import __version__
from open2fa.cli_utils import parse_cli_arg_aliases as pargs


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


@scope_fixture
def ranuuid():
    yield str(uuid4())


@scope_fixture
def randir():
    _tmpdir = '/tmp/' + ranstr(10)
    yield _tmpdir


@pt.fixture()
def local_client(ranuuid_module: str, randir: str):
    """Fixture to create a TOTPSecret instance for testing."""
    _uuid = ranuuid_module
    o2fa = Open2FA(
        o2fa_dir=randir, o2fa_uuid=_uuid, o2fa_api_url='http://test'
    )
    for sec in _SECRETS:
        if sec not in o2fa.secrets:
            s = o2fa.add_secret(sec[0], sec[1])
            assert s.code == s['code']  # test coverage lol
    yield o2fa
    [
        rmtree(x, ignore_errors=True)
        for x in [randir, _DIR]
        if os.path.exists(x)
    ]


def exec_cmd(cmd: list, client: Open2FA) -> tuple[Open2FA, str]:
    cmd = ['cli.py'] + [str(c) for c in cmd]
    with patch('sys.argv', cmd), patch(
        'sys.stdout', new_callable=StringIO
    ) as out:
        client = main(
            **{
                'o2fa_api_url': client.api_url,
                'o2fa_dir': client.dir,
                'return_open2fa': True,
                'o2fa_uuid': client.uuid,
            }
        )
        return client, out.getvalue()


def _handle_dash_h(cmd: list[str], client: Open2FA):
    with patch('sys.stdout', new_callable=StringIO) as out, pt.raises(
        SystemExit
    ):
        exec_cmd(cmd, client)
        assert 'usage: ' in out.getvalue().lower()


@pt.mark.parametrize('cmd', [['list'], ['list', '-s'], ['list', '-h']])
def test_list_cmd(cmd: list[str], local_client: Open2FA):
    if '-h' in cmd:
        return _handle_dash_h(cmd, local_client)
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
        return _handle_dash_h(cmd, local_client)
    # empty add
    if cmd[0] == 'add' and len(cmd) >= 1 and isinstance(cmd[1], tuple):
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
        return
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
        (['delete', _SECRETS[5][0]], _SECRETS[5], 'y'),
        (['delete', '-s', _SECRETS[6][0], '-f'], _SECRETS[6], 'y'),
    ],
)
def test_delete_cmd(
    cmd: list[str],
    secret: tuple[str, str, str],
    confirm: str,
    local_client: Open2FA,
):
    if '-h' in cmd:
        return _handle_dash_h(cmd, local_client)

    # incorrect args should raise error
    if not cmd[1].startswith('-'):
        with pt.raises(SystemExit):
            o2fa, out = exec_cmd(cmd, local_client)
        return
    with patch('builtins.input', return_value=confirm) as mock_input:
        o2fa, out = exec_cmd(cmd, local_client)
    if '-f' in cmd:
        assert mock_input.call_count == 0
    if confirm == 'y':
        assert o2fa.has_secret(secret[0], secret[1]) is False
    else:
        assert o2fa.has_secret(secret[0], secret[1])


@pt.mark.parametrize('cmd', [['g', '-h'], ['generate', '-r', '1']])
def test_generate_cmd(cmd: list[str], local_client: Open2FA):
    if '-h' in cmd:
        return _handle_dash_h(cmd, local_client)
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
            **{
                'o2fa_dir': client.dir,
                'o2fa_api_url': client.api_url,
                'return_open2fa': True,
            }
        )
    yield o2fa
    if osp.exists(randir):
        rmtree(randir, ignore_errors=True)


@pt.fixture
def rclient_w_secrets(remote_client: Open2FA):
    with patch('open2fa.main.apireq') as mock_apireq:
        mock_apireq.return_value = MagicMock(
            status_code=200,
            data={
                'totps': [
                    {
                        'enc_secret': remote_client.encrypt(sec[0]),
                        'name': sec[1],
                    }
                    for sec in _SECRETS
                ]
            },
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

    secs, secnames = [sec[0] for sec in _SECRETS], [sec[1] for sec in _SECRETS]
    for sec in _SECRETS:
        assert sec[0] in secs
        assert sec[1] in secnames


def test_remote_push(rclient_w_secrets: Open2FA):
    with patch('open2fa.main.apireq') as mock_apireq, patch(
        'sys.argv', ['cli.py', 'remote', 'push']
    ):
        rclient_w_secrets.remote_push()

    assert mock_apireq.call_count == 1
    mock_args = mock_apireq.call_args[0]
    assert mock_args[0:2] == ('POST', 'totps')
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
    with patch('sys.argv', ['cli.py'] + cmd), patch(
        'open2fa.main.apireq'
    ) as mock_apireq:
        mock_apireq.return_value = MagicMock(
            status_code=200, data={'totps': _ENC_SECRETS}
        )
        with patch('builtins.print') as mock_print:
            main(
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


def test_autosize_generate_code(randir):
    """Test the autosize_generate_code function."""
    _WIDTHS = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    _HEIGHTS = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    o2fa = Open2FA(randir, None, 'http://example')
    for i in [5, 20, 50, 100]:
        o2fa.add_secret(_TOTP, 'a' * i)

    for w, h in zip(_WIDTHS, _HEIGHTS):

        with patch(
            'os.get_terminal_size', return_value=MagicMock(columns=w, lines=h)
        ):
            _, out = exec_cmd(['g', '-r', '1'], o2fa)

            for line in out.lower().splitlines():
                if line == '':
                    continue
                s = {line.find(x) for x in ['not shown', '---', 'name', 'aaa']}
                assert len(s) > 1


def test_code_generated_differs(local_client: Open2FA):
    """Test to ensure codes are only returned if they differ."""
    s = local_client.secrets[0]
    with patch('open2fa.common.generate_totp_2fa_code') as mock_gen:
        mock_gen.side_effect = [
            TOTP2FACode(code='654321'),
            TOTP2FACode(code='654321'),
            TOTP2FACode(code='123456'),
        ]
        assert s.generate_code().code == '654321'
        assert s.generate_code() is None
        assert s.generate_code().code == '123456'


def test_parse_cliargs_less_2_args():
    """Test that parse_cli_arg_aliases returns the original list if less than 2 args."""
    assert pargs(['t']) == ['t']


def test_refresh_code(local_client: Open2FA):
    """Test the refresh_code method."""
    assert id(local_client.refresh()) != id(local_client)
