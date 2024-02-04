import pytest
from io import StringIO
from unittest.mock import patch, MagicMock
import sys
import os
from uuid import UUID, uuid4
from open2fa.cli import Open2FA, handle_remote_init
from open2fa.main import apireq
from open2fa.common import TOTP2FACode, RemoteSecret, O2FAUUID, TOTPSecret

# Assuming ranstr function exists for generating random strings
from pyshared import ranstr

TEST_NAME = 'test_secret'
TEST_TOTP = 'I65VU7K5ZQL7WB4E'


@pytest.fixture
def add_secret():
    """Fixture to add a secret before a test and ensure environment is clean."""
    os.environ['OPEN2FA_DIR'] = '/tmp/' + ranstr(10)
    from open2fa.cli import main

    # Add the secret
    sys.argv = ['open2fa', 'add', TEST_TOTP, '-n', TEST_NAME]
    with patch('sys.stdout', new=StringIO()):
        main(dir=os.environ['OPEN2FA_DIR'])

    # Return values that might be useful for the test
    yield TEST_NAME, TEST_TOTP, os.environ['OPEN2FA_DIR']

    # Here you can add steps to delete the secret if necessary
    sys.argv = ['open2fa', 'delete', '-n', TEST_NAME]
    with patch('sys.stdout', new=StringIO()) as fake_delete:
        with patch('builtins.input', return_value='y') as fake_input:
            main()
    del os.environ['OPEN2FA_DIR']


def test_generate_key(add_secret):
    """Test generating a TOTP code for the added secret."""
    from open2fa.cli import main

    _name, _secret, _dir = add_secret

    # Use the added secret to generate a code
    sys.argv = ['open2fa', 'generate', '-r', '1']
    with patch('sys.stdout', new=StringIO()) as fake_generate:
        main(dir=_dir)

    assert _name in fake_generate.getvalue()


def test_info(add_secret):
    """Test getting information about the added secret."""
    from open2fa.cli import main

    _name, _secret, _dir = add_secret

    # Use the added secret to generate a code
    sys.argv = ['open2fa', 'info']
    with patch('sys.stdout', new=StringIO()) as fake_info:
        main(dir=_dir)

    for t in [
        'Directory',
        'Remote API URL',
        'Number of secrets',
        'UUID',
        'ID',
        'Secret',
    ]:
        assert t in fake_info.getvalue()


@patch('open2fa.cli.handle_remote_init')
def test_init(fake_remote_init, add_secret):
    """Test initializing the remote capabilities of Open2FA."""
    from open2fa.cli import main

    _name, _secret, _dir = add_secret
    sys.argv = ['open2fa', 'remote', 'init']
    with patch('sys.stdout', new=StringIO()) as fake_init:
        main(dir=_dir)

    # Assertions about the generated code can go here
    # For example, check if the output contains expected elements of a TOTP code
    assert fake_remote_init.called_once


def test_list(add_secret):
    """Test listing the added secret."""
    from open2fa.cli import main

    _name, _secret, _dir = add_secret

    # Use the added secret to generate a code
    sys.argv = ['open2fa', 'list']
    with patch('sys.stdout', new=StringIO()) as fake_list:
        main(dir=_dir)

    assert _name in fake_list.getvalue()
    assert '...' in fake_list.getvalue()

    with patch('sys.stdout', new=StringIO()) as fake_list:
        sys.argv = ['open2fa', 'list', '-s']
        main(dir=_dir)

    assert _secret in fake_list.getvalue()
    assert _name in fake_list.getvalue()
    assert '...' not in fake_list.getvalue()


def test_remote_pull(add_secret):
    """Test pulling the remote capabilities of Open2FA."""
    from open2fa.cli import main

    sec2 = 'JBSWY3DPEHPK3PXP'
    _name, _secret, _dir = add_secret
    new_secret = _secret
    fake_uuid = str(uuid4())
    o2fa = Open2FA(_dir, fake_uuid, 'https://example.com')
    enc = o2fa.o2fa_uuid.remote.encrypt(sec2)

    fake_totp_data = {'totps': [{'name': _name, 'enc_secret': enc}]}

    class FakeResp:
        data = fake_totp_data

    sys.argv = ['open2fa', 'remote', 'pull']
    with patch('sys.stdout', new=StringIO()) as fake_pull:
        with patch('open2fa.main.apireq', return_value=FakeResp()):
            main(dir=_dir, uuid=fake_uuid, api_url='https://example.com')
    assert 'Pulled' in fake_pull.getvalue()
    with open(os.path.join(_dir, 'secrets.json')) as f:
        assert sec2 in f.read()
