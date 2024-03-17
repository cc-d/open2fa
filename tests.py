import pytest as pt
from io import StringIO
from unittest.mock import patch, MagicMock

import sys
import os
import os.path as osp
from typing import Union as U, Generator as Gen
from uuid import UUID, uuid4
from open2fa.cli import Open2FA, main
from open2fa.main import apireq
from open2fa.common import TOTP2FACode, RemoteSecret, O2FAUUID, TOTPSecret
from open2fa import ex as EX
from open2fa import msgs as MSGS
from open2fa.version import __version__

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


@pt.fixture
def ranuuid():
    """Fixture to generate a random UUID for testing."""
    yield str(uuid4())


@pt.fixture
def randir():
    """Fixture to generate a random directory path for testing."""
    _tmpdir = '/tmp/' + ranstr(10)
    os.mkdir(_tmpdir, exist_ok=True)

    yield _tmpdir

    os.rmdir(_tmpdir)


@pt.fixture
def local_client():
    """Fixture to create a TOTPSecret instance for testing."""
    o2fa = Open2FA(_DIR, None, _URL)
    for sec in _SECRETS:
        o2fa.add_secret(sec[0], sec[1])
    yield o2fa


@pt.fixture
def remote_client(local_client: Open2FA):
    """Fixture to create a RemoteSecret instance for testing."""
    with patch('open2fa.main.apireq') as mock_apireq:
        mock_apireq.return_value = _ENC_SECRETS
        local_client.remote_pull()

    yield local_client


def exec_cmd(cmd: list[str], client: Open2FA) -> tuple[Open2FA, str]:
    """Execute the command and return the output."""
    with patch('sys.argv', cmd), patch(
        'sys.stdout', new_callable=StringIO
    ) as mock_out:
        o2fa = main(
            o2fa_dir=client.dir,
            o2fa_uuid=client.uuid,
            o2fa_api_url=client.api_url,
            return_open2fa=True,
        )
        return o2fa.refresh(), mock_out.getvalue()


def test_list(local_client: Open2FA):
    """Test the list command."""
    cmd = ['open2fa', 'list']
    o2fa, out = exec_cmd(cmd, local_client)
    print('o2fa', o2fa, '\n\n', 'local_client', local_client, sep='\n')
    for sec in _SECRETS:
        assert sec[0][0] + '...' in out
        assert str(sec[1]) in out
