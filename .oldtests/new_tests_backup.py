import pytest as pt
from io import StringIO
from unittest.mock import patch, MagicMock

import os
import os.path as osp
from uuid import UUID, uuid4
from open2fa.cli import Open2FA, main, sys

from open2fa.common import TOTP2FACode, RemoteSecret, O2FAUUID, TOTPSecret
from open2fa import ex as EX
from open2fa import msgs as MSGS
from open2fa.version import __version__
from open2fa.utils import default_repr, sec_trunc
from open2fa.main import Open2FA

# Assuming ranstr function exists for generating random strings
from pyshared import ranstr

_TOTP, _NAME, _URL, _DIR, _UUID = (
    'I65VU7K5ZQL7WB4E',
    'DefaultSecret',
    'http://test',
    '/tmp/' + ranstr(20),
    str(uuid4()),
)

_tmp2fa = Open2FA(o2fa_dir=_DIR, o2fa_uuid=_UUID, o2fa_api_url=_URL)
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
for i in range(len(_SECRETS)):
    _SECRETS[i] = (
        _SECRETS[i][0],
        _SECRETS[i][1],
        _tmp2fa.encrypt(_SECRETS[i][0]),
    )

_ENC_SECRETS = [
    {'enc_secret': _tmp2fa.encrypt(sec[0]), 'name': sec[1]} for sec in _SECRETS
]

_open2fa = Open2FA(o2fa_dir=_DIR, o2fa_uuid=_UUID, o2fa_api_url=_URL)


@pt.fixture
def ranuuid():
    """Fixture to generate a random UUID for testing."""
    yield str(uuid4())


@pt.fixture
def randir():
    """Fixture to generate a random directory path for testing."""
    _tmpdir = '/tmp/' + ranstr(20)
    if not osp.exists(_tmpdir):
        os.mkdir(_tmpdir)
    yield _tmpdir
    if osp.exists(os.path.join(_tmpdir, 'open2fa.uuid')):
        os.remove(os.path.join(_tmpdir, 'open2fa.uuid'))
    if osp.exists(os.path.join(_tmpdir, 'secrets.json')):
        os.remove(os.path.join(_tmpdir, 'secrets.json'))
    os.rmdir(_tmpdir)


@pt.fixture
def fake_apireq():
    """Fixture to return a fake apireq function."""
    with patch('open2fa.main.apireq') as mock_apireq:
        yield mock_apireq


@pt.fixture
def mock_stdout():
    """Fixture to return a fake stdout."""
    with patch('open2fa.cli.sys.stdout', new_callable=StringIO) as mock_stdout:
        out = mock_stdout.getvalue()
        print(out)
        yield mock_stdout


@pt.fixture
def local_open2fa(randir, ranuuid):
    """Fixture to return an Open2FA object."""
    yield Open2FA(o2fa_dir=randir, o2fa_uuid=ranuuid, o2fa_api_url=_URL)


@pt.fixture
def local_open2fa_secs(local_open2fa: Open2FA):
    """Fixture to return an Open2FA object with secrets."""
    total_outs = []
    for sec in _SECRETS:
        local_open2fa.add_secret(sec[0], sec[1])

    yield local_open2fa, total_outs


def test_info(local_open2fa_secs):
    """Test the info method."""
    o2fa, outs = local_open2fa_secs
    t = main(
        o2fa_dir=o2fa.o2fa_dir, o2fa_uuid=o2fa.o2fa_uuid, o2fa_api_url=_URL
    )
