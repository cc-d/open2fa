import pytest
from io import StringIO
from unittest.mock import patch, MagicMock
import sys
import os
import os.path as osp
from uuid import UUID, uuid4
from open2fa.cli import Open2FA, main
from open2fa.main import apireq
from open2fa.common import TOTP2FACode, RemoteSecret, O2FAUUID, TOTPSecret
from open2fa import ex as EX
from open2fa import msgs as MSGS
from open2fa.version import __version__

# Assuming ranstr function exists for generating random strings
from pyshared import ranstr

TEST_NAME = 'test_secret'
TEST_TOTP = 'I65VU7K5ZQL7WB4E'
TEST_URL = 'http://test'


@pytest.fixture
def remote_init():
    """Fixture to initialize remote capabilities."""
    _rand = '/tmp/' + ranstr(10)
    from open2fa.cli import main

    with patch('builtins.input', return_value='y') as fake_input:
        with patch('open2fa.cli.sys.argv', ['open2fa', 'remote', 'init']):
            o2fa = main(
                dir=_rand,
                api_url='http://test',
                uuid=None,
                return_open2fa=True,
            )

    yield o2fa


@pytest.fixture
def randir():
    """Fixture to generate a random directory path for testing."""
    _tmpdir = '/tmp/' + ranstr(10)
    yield _tmpdir
    if osp.exists(os.path.join(_tmpdir, 'open2fa.uuid')):
        os.remove(os.path.join(_tmpdir, 'open2fa.uuid'))
    if osp.exists(os.path.join(_tmpdir, 'secrets.json')):
        os.remove(os.path.join(_tmpdir, 'secrets.json'))
    os.rmdir(_tmpdir)


@pytest.fixture
def ranuuid():
    """Fixture to generate a random UUID for testing."""
    yield str(uuid4())


@pytest.fixture
def o2fa_with_secret(randir):
    """Fixture to add a secret to the Open2FA instance."""
    with patch(
        'open2fa.cli.sys.argv', ['open2fa', 'add', TEST_TOTP, '-n', TEST_NAME]
    ):
        o2fa = main(
            dir=randir, api_url='http://test', uuid=None, return_open2fa=True
        )

    yield o2fa


def main_out(sysargs, *args, **kwargs) -> str:
    """returns open2fa cli main() output"""
    with patch('open2fa.cli.sys.argv', sysargs):
        with patch('sys.stdout', new=StringIO()) as fake_output:
            main(*args, **kwargs)
    return fake_output.getvalue()


def test_remote_init(remote_init):
    """Test initializing the remote capabilities of Open2FA."""
    o2fa = remote_init
    assert o2fa.o2fa_uuid is not None
    assert o2fa.o2fa_api_url is TEST_URL
    assert os.path.exists(os.path.join(o2fa.o2fa_dir, 'open2fa.uuid'))


def test_add_secret(o2fa_with_secret):
    """Test adding a secret to the Open2FA instance."""
    assert o2fa_with_secret.o2fa_uuid is None
    assert o2fa_with_secret.o2fa_api_url == TEST_URL

    with open(o2fa_with_secret.secrets_json_path, 'r') as f:
        secjson = f.read()

    assert TEST_NAME in secjson
    assert TEST_TOTP in secjson

    assert not os.path.exists(
        os.path.join(o2fa_with_secret.o2fa_dir, 'open2fa.uuid')
    )


def test_add_secret_no_args(randir):
    """Test adding a secret to the Open2FA instance."""
    with patch('builtins.input', side_effect=[TEST_TOTP, TEST_NAME]):
        with patch('open2fa.cli.sys.argv', ['open2fa', 'add']):
            o2fa = main(
                dir=randir, api_url=TEST_URL, uuid=None, return_open2fa=True
            )

    assert o2fa.o2fa_uuid is None
    assert o2fa.o2fa_api_url == TEST_URL
    assert len(o2fa.secrets) == 1
    with open(o2fa.secrets_json_path, 'r') as f:
        secjson = f.read()

    assert TEST_NAME in secjson
    assert TEST_TOTP in secjson


def test_add_secret_no_args_none_name(randir):
    """Test adding a secret to the Open2FA instance."""
    with patch('open2fa.cli.sys.argv', ['open2fa', 'add']):
        with patch('sys.stdout', new=StringIO()) as fake_output:
            with patch('builtins.input', side_effect=[TEST_TOTP, '']):
                o2fa = main(
                    dir=randir,
                    api_url=TEST_URL,
                    uuid=None,
                    return_open2fa=True,
                )
    with open(o2fa.secrets_json_path, 'r') as f:
        secjson = f.read()

    assert o2fa.secrets[0].name is None


def test_add_secret_no_args_no_input(randir):
    """Test adding a secret to the Open2FA instance."""
    with patch('open2fa.cli.sys.argv', ['open2fa', 'add']):
        with patch('sys.stdout', new=StringIO()) as fake_output:
            with patch('builtins.input', side_effect=['a', 'b', 'c', 'd']):
                with pytest.raises(SystemExit):
                    main(dir=randir, api_url=TEST_URL, uuid=None)

    assert 'exiting' in fake_output.getvalue().lower()


def test_delete_secret(o2fa_with_secret):
    """Test removing a secret from the Open2FA instance."""
    o2fa = o2fa_with_secret

    with patch('builtins.input', return_value='y') as fake_input:
        with patch(
            'open2fa.cli.sys.argv', ['open2fa', 'delete', '-n', TEST_NAME]
        ):
            o2fa = main(
                dir=o2fa.o2fa_dir,
                api_url=TEST_URL,
                uuid=None,
                return_open2fa=True,
            )
    assert o2fa.o2fa_uuid is None
    assert len(o2fa.secrets) == 0
    with open(o2fa.secrets_json_path, 'r') as f:
        secjson = f.read()

    assert TEST_NAME not in secjson
    assert TEST_TOTP not in secjson


def test_generate_key(o2fa_with_secret):
    """Test generating a TOTP code for the added secret."""
    out = main_out(['open2fa', 'g', '-r', '1'], dir=o2fa_with_secret.o2fa_dir)
    assert TEST_NAME in out
    for line in out.splitlines():
        if TEST_NAME in line:
            assert len(line.split()) >= 3
            _name, _code, _time = line.split()
            assert _name == TEST_NAME
            assert int(_code)
            assert float(_time)


def test_list_no_s(o2fa_with_secret):
    """Test listing the added secret."""
    out = main_out(['open2fa', 'list'], dir=o2fa_with_secret.o2fa_dir)
    assert TEST_NAME in out
    assert '...' in out


def test_list_dash_s(o2fa_with_secret):
    """Test listing the added secret."""
    out = main_out(['open2fa', 'list', '-s'], dir=o2fa_with_secret.o2fa_dir)
    assert TEST_NAME in out
    assert '...' not in out
    assert TEST_TOTP in out


def test_list_with_no_secrets(remote_init):
    """regression test for error occuring if no secrets were added"""
    out = main_out(
        ['open2fa', 'list'],
        dir=remote_init.o2fa_dir,
        api_url=TEST_URL,
        uuid=remote_init.o2fa_uuid.uuid,
    )
    assert 'Name' in out and 'Secret' in out


def test_remote_pull(remote_init):
    """Test pulling the remote capabilities of Open2FA."""
    enc = remote_init.o2fa_uuid.remote.encrypt(TEST_TOTP)
    secname = 'name2'
    fake_totp_data = {'totps': [{'name': secname, 'enc_secret': enc}]}

    class FakeResp:
        data = fake_totp_data

    with patch('open2fa.main.apireq', return_value=FakeResp()) as fake_apireq:
        out = main_out(
            ['open2fa', 'remote', 'pull'],
            dir=remote_init.o2fa_dir,
            api_url=TEST_URL,
            uuid=remote_init.o2fa_uuid.uuid,
        )

    assert 'Pulled' in out
    assert osp.exists(remote_init.secrets_json_path)
    with open(remote_init.secrets_json_path, 'r') as f:
        secjson = f.read()
    assert secname in secjson
    assert TEST_TOTP in secjson
    assert TEST_NAME not in secjson


def test_remote_push(remote_init: Open2FA):
    """Test pushing the remote capabilities of Open2FA."""
    o2fa = remote_init
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


def test_remote_push_no_uuid_error(o2fa_with_secret):
    """Test pushing the remote capabilities of Open2FA."""
    o2fa = o2fa_with_secret

    with pytest.raises(EX.NoUUIDError):
        o2fa.remote_push()


def test_handle_remote_init(remote_init):
    """Test the handle_remote_init function."""
    assert remote_init.o2fa_uuid is not None
    assert remote_init.o2fa_api_url == TEST_URL
    assert os.path.exists(os.path.join(remote_init.o2fa_dir, 'open2fa.uuid'))


def test_handle_remote_delete_errors_nosecs():
    """Test the handle_remote_delete function."""
    o2fa = Open2FA('/tmp/%s' % ranstr(10), None, 'http://example')

    with pytest.raises(EX.NoUUIDError):
        o2fa.remote_delete()

    o2fa = Open2FA('/tmp/%s' % ranstr(10), str(uuid4()), 'http://example')

    with pytest.raises(EX.DelNoNameSec):
        o2fa.remote_delete()


def test_handle_remote_delete_no_sec_found(remote_init: Open2FA):
    """Test the handle_remote_delete function."""
    o2fa = remote_init
    o2fa.add_secret(TEST_TOTP, 'name1')

    with pytest.raises(EX.DelNoNameSecFound):
        o2fa.remote_delete('name2')


def test_info_no_dash_s(remote_init):
    """Ensure that the -s tip is printed and secs are truncated with info"""
    out = main_out(
        ['open2fa', 'info'],
        dir=remote_init.o2fa_dir,
        api_url=TEST_URL,
        uuid=remote_init.o2fa_uuid.uuid,
    )
    assert '...' in out
    assert remote_init.o2fa_api_url in out
    assert str(remote_init.o2fa_uuid.uuid) not in out
    assert MSGS.INFO_SEC_TIP in out
    assert str(remote_init.o2fa_uuid.remote.b58) not in out


def test_info_dash_s(remote_init):
    """Ensure that the -s tip is not printed and secs are not truncated with info"""
    out = main_out(
        ['open2fa', 'info', '-s'],
        dir=remote_init.o2fa_dir,
        api_url=TEST_URL,
        uuid=remote_init.o2fa_uuid.uuid,
    )
    assert '...' not in out
    assert remote_init.o2fa_api_url in out
    assert str(remote_init.o2fa_uuid.uuid) in out
    assert MSGS.INFO_SEC_TIP not in out
    assert str(remote_init.o2fa_uuid.remote.b58) in out


def test_remote_delete(remote_init):
    """Test deleting the remote capabilities of Open2FA."""
    o2fa = remote_init
    o2fa.add_secret(TEST_TOTP, 'name1')

    with patch('builtins.input', return_value='y') as fake_input:
        with patch(
            'open2fa.cli.sys.argv',
            ['open2fa', 'remote', 'delete', '-n', 'name1'],
        ):
            with patch(
                'open2fa.main.apireq',
                return_value=MagicMock(data={'deleted': '1'}),
            ) as fake_apireq, patch(
                'sys.stdout', new=StringIO()
            ) as fake_output:
                o2fa = main(
                    dir=o2fa.o2fa_dir,
                    api_url=TEST_URL,
                    uuid=str(o2fa.o2fa_uuid.uuid),
                    return_open2fa=True,
                )

    assert 'Deleted 1 secret' in fake_output.getvalue()


@pytest.mark.parametrize('version_arg', ['-v', '--version'])
def test_version(version_arg):
    """Test the version command."""
    with patch('open2fa.cli.sys.argv', ['open2fa', version_arg]):
        # prevent exit
        with patch('sys.exit') as fake_exit:
            with patch('sys.stdout', new=StringIO()) as fake_output:
                cli_ret = main(return_open2fa=True)

    assert MSGS.VERSION.format(__version__) in fake_output.getvalue()
    assert cli_ret is None


def test_empty_command():
    """Test the empty command."""
    with patch('open2fa.cli.sys.argv', ['open2fa']):
        with patch('sys.stdout', new=StringIO()) as fake_output:
            main(return_open2fa=True)

    out = fake_output.getvalue().lower()

    for hstr in ['usage', 'options', 'positional', '-h', '-v']:
        assert hstr in out


def test_new_cli_kwargs(randir, ranuuid):
    """Test the new cli keyword arguments."""

    with patch('open2fa.cli.sys.argv', ['open2fa', 'info', '-s']):
        with patch('sys.stdout', new=StringIO()) as fake_output:
            o2fa = main(
                o2fa_dir=randir,
                o2fa_uuid=ranuuid,
                o2fa_api_url='http://example',
                return_open2fa=True,
            )

    assert o2fa.o2fa_dir == randir
    assert o2fa.o2fa_uuid.uuid == UUID(ranuuid)
    assert o2fa.o2fa_api_url == 'http://example'


TEST_NAMES = ['a' * i for i in range(1, 13, 2)]
TEST_WIDTHS = [30, 40, 100]
TEST_HEIGHTS = [4, 10, 20]


def test_autosize_generate_code(randir):
    """Test the autosize_generate_code function."""
    o2fa = Open2FA(randir, None, 'http://example')
    for i in [5, 20, 50, 100]:
        o2fa.add_secret(TEST_TOTP, 'a' * i)

    def _autosize_generate_code(o2fa, **kwargs):
        w, h = kwargs['w'], kwargs['h']
        with patch(
            'os.get_terminal_size', return_value=MagicMock(columns=w, lines=h)
        ):
            out = main_out(
                ['open2fa', 'g', '-r', '1'],
                dir=o2fa.o2fa_dir,
                api_url='http://example',
                uuid=None,
            ).lower()

            for i, line in enumerate(out.splitlines()):
                if line == '':
                    continue
                _s = {
                    line.find(x) for x in ['not shown', '---', 'name', 'aaa']
                }
                assert len(_s) > 1

    for w, h in zip(TEST_WIDTHS, TEST_HEIGHTS):
        _autosize_generate_code(o2fa, w=w, h=h)
