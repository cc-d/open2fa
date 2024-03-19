import pytest as pt
from io import StringIO
from unittest.mock import patch, MagicMock

import os
import os.path as osp
from shutil import rmtree
from typing import Union as U, Generator as Gen
from uuid import UUID, uuid4
from open2fa.cli import Open2FA, main, sys
from open2fa.main import apireq
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


@pt.fixture(scope='module')
def ranuuid():
    """Fixture to generate a random UUID for testing."""
    yield str(uuid4())


@pt.fixture(scope='module')
def randir():
    """Fixture to generate a random directory path for testing."""
    _tmpdir = '/tmp/' + ranstr(10)
    if not osp.exists(_tmpdir):
        os.mkdir(_tmpdir)

    yield _tmpdir
    if osp.exists(_tmpdir):

        # delete the directory

        # ensure it si deleted even if ti is not empty
        rmtree(_tmpdir, ignore_errors=True)


@pt.fixture(scope='module')
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


from logfunc import logf


def exec_cmd(cmd, local_client: U[Open2FA, None] = None) -> U[Open2FA, Gen]:
    cmd = ['cli.py'] + [str(c) for c in cmd]
    client = local_client if local_client else Open2FA()
    with patch('open2fa.cli_utils.parse_cli_arg_aliases') as mock_pargs:
        mock_pargs.return_value = cmd
        with patch('sys.argv', cmd):
            with patch('sys.stdout', new_callable=StringIO) as out:
                with patch('sys.stderr', new_callable=StringIO) as err:
                    main(
                        o2fa_api_url=client.api_url,
                        o2fa_uuid=client.uuid,
                        o2fa_dir=client.dir,
                    )

                    return client, out.getvalue()


@pt.mark.parametrize('cmd', [['list'], ['list', '-s']])
def test_list_cmd(cmd: list[str], local_client: Open2FA):
    o2fa, out = exec_cmd(cmd, local_client=local_client)
    for sec in _SECRETS:
        if '-s' in cmd:
            assert sec[0] in out
        else:
            assert sec[0] not in out
