import pytest
from io import StringIO
from unittest.mock import patch, MagicMock
import sys
import os
from uuid import UUID, uuid4
from open2fa.cli import Open2FA, handle_remote_init
from open2fa.main import apireq
from open2fa.common import TOTP2FACode, RemoteSecret, O2FAUUID, TOTPSecret
from open2fa import ex as EX
from open2fa import msgs as MSGS

# Assuming ranstr function exists for generating random strings
from pyshared import ranstr

TEST_NAME = 'test_secret'
TEST_TOTP = 'I65VU7K5ZQL7WB4E'
TEST_URL = 'http://test'


@pytest.fixture
def add_secret():
    """Fixture to add a secret before a test and ensure environment is clean."""
    from open2fa.cli import main

    randir = '/tmp/' + ranstr(10)

    # Add the secret
    sys.argv = ['open2fa', 'add', TEST_TOTP, '-n', TEST_NAME]
    with patch('sys.stdout', new=StringIO()):
        main(dir=randir)

    # Return values that might be useful for the test
    yield TEST_NAME, TEST_TOTP, randir

    # Here you can add steps to delete the secret if necessary
    sys.argv = ['open2fa', 'delete', '-n', TEST_NAME]
    with patch('sys.stdout', new=StringIO()) as fake_delete:
        with patch('builtins.input', return_value='y') as fake_input:
            main()


@pytest.fixture
def remote_init():
    """Fixture to initialize remote capabilities."""
    randir = '/tmp/' + ranstr(10)
    from open2fa.cli import main

    with patch('builtins.input', return_value='y') as fake_input:
        with patch('open2fa.cli.sys.argv', ['open2fa', 'remote', 'init']):
            o2fa = main(dir=randir, api_url='http://test', uuid=None)

    yield o2fa


@pytest.fixture
def randir():
    """Fixture to generate a random directory path for testing."""
    return '/tmp/' + ranstr(10)


def test_init(remote_init):
    """Test initializing the remote capabilities of Open2FA."""
    o2fa = remote_init
    assert o2fa.o2fa_uuid is not None
    assert o2fa.o2fa_api_url is TEST_URL
    assert os.path.exists(os.path.join(o2fa.o2fa_dir, 'open2fa.uuid'))


def test_generate_key(add_secret):
    """Test generating a TOTP code for the added secret."""
    from open2fa.cli import main

    _name, _secret, _dir = add_secret

    # Use the added secret to generate a code
    sys.argv = ['open2fa', 'generate', '-r', '1']
    with patch('sys.stdout', new=StringIO()) as fake_generate:
        main(dir=_dir)

    assert _name in fake_generate.getvalue()


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
    o2fa = Open2FA(_dir, fake_uuid, 'http://example')
    enc = o2fa.o2fa_uuid.remote.encrypt(sec2)

    fake_totp_data = {'totps': [{'name': _name, 'enc_secret': enc}]}

    class FakeResp:
        data = fake_totp_data

    sys.argv = ['open2fa', 'remote', 'pull']
    with patch('sys.stdout', new=StringIO()) as fake_pull:
        with patch('open2fa.main.apireq', return_value=FakeResp()):
            main(dir=_dir, uuid=fake_uuid, api_url='https://example')
    assert 'Pulled' in fake_pull.getvalue()
    with open(os.path.join(_dir, 'secrets.json')) as f:
        assert sec2 in f.read()


def test_remote_push(remote_init):
    """Test pushing the remote capabilities of Open2FA."""
    o2fa: Open2FA = remote_init
    o2fa.add_secret(TEST_TOTP, 'name1')
    _enc = o2fa.o2fa_uuid.remote.encrypt(TEST_TOTP)

    with patch('open2fa.main.apireq') as fake_apireq:
        fake_apireq.return_value.data = {
            'totps': [{'name': 'name1', 'enc_secret': _enc}]
        }
        o2fa.remote_push()

    assert fake_apireq.call_args_list[0][1]['data'] == {
        'totps': [{'name': 'name1', 'enc_secret': _enc}]
    }


def test_remote_push_no_uuid_error():
    """Test pushing the remote capabilities of Open2FA."""

    o2fa = Open2FA('/tmp', None, 'http://example')

    with pytest.raises(EX.NoUUIDError):
        o2fa.remote_push()


def test_handle_remote_init():
    """Test the handle_remote_init function."""
    no_uuid_o2fa = Open2FA('/tmp/%s' % ranstr(10), None, 'http://example')

    with patch('builtins.input', return_value='y'):
        with patch('open2fa.cli.handle_info') as fake_info:
            with patch('builtins.print') as fake_print, patch(
                'open2fa.main.os.chmod'
            ) as fake_chmod:

                handle_remote_init(no_uuid_o2fa)

    assert fake_info.called_once
    assert '...' not in fake_print.call_args[0][0]
    assert fake_chmod.called_once


def test_handle_remote_delete_errors_nosecs():
    """Test the handle_remote_delete function."""
    o2fa = Open2FA('/tmp/%s' % ranstr(10), None, 'http://example')

    with pytest.raises(EX.NoUUIDError):
        o2fa.remote_delete()

    o2fa = Open2FA('/tmp/%s' % ranstr(10), str(uuid4()), 'http://example')

    with pytest.raises(EX.DelNoNameSec):
        o2fa.remote_delete()


def test_handle_remote_delete_no_sec_found(remote_init):
    """Test the handle_remote_delete function."""
    o2fa: Open2FA = remote_init
    o2fa.add_secret(TEST_TOTP, 'name1')

    with pytest.raises(EX.DelNoNameSecFound):
        o2fa.remote_delete('name2')


def test_info_no_s(randir):
    from open2fa.cli import main

    with patch('open2fa.cli.sys.argv', ['open2fa', 'info', '-s']):
        with patch('sys.stdout', new=StringIO()) as fake_info:
            main(dir=randir)
    assert MSGS.INFO_SEC_TIP in fake_info.getvalue()


def test_info_dash_s(randir):
    """Ensure that the -s tip is not printed with info"""
    from open2fa.cli import main

    with patch('open2fa.cli.sys.argv', ['open2fa', 'info']):
        with patch('sys.stdout', new=StringIO()) as fake_info:
            main(dir=randir)
    assert MSGS.INFO_SEC_TIP not in fake_info.getvalue()
