import pytest as pt
from io import StringIO
from unittest.mock import patch, MagicMock

import sys
import os
import os.path as osp
from uuid import UUID, uuid4
from open2fa.cli import Open2FA, main, _print_secrets
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
_tmp2fa = Open2FA(_DIR, _UUID, _URL)
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


@pt.fixture
def fake_enc_secrets(randir, fake_apireq):
    """Fixture to generate encrypted secrets."""
    o2fa = Open2FA(randir, _UUID, _URL)
    for sec in _SECRETS:
        o2fa.add_secret(sec[0], sec[1])

    with patch('open2fa.main.apireq') as fake_apireq:
        fake_apireq.return_value.data = {'totps': _ENC_SECRETS}
        o2fa.remote_pull()

    yield o2fa.secrets


@pt.fixture
def fake_apireq():
    """Fixture to generate a fake apireq for testing."""
    with patch('open2fa.main.apireq') as fake_apireq:
        yield fake_apireq


@pt.fixture
def remote_init(randir, o2fa_no_remote):
    """Fixture to initialize the remote capabilities of Open2FA."""
    with patch('builtins.input', return_value='y'):
        with patch('open2fa.cli.sys.argv', ['open2fa', 'remote', 'init']):
            o2fa = main(
                dir=randir, api_url=_URL, uuid=None, return_open2fa=True
            )

    yield o2fa


@pt.fixture
def randir():
    """Fixture to generate a random directory path for testing."""
    _tmpdir = '/tmp/' + ranstr(10)
    yield _tmpdir
    if osp.exists(os.path.join(_tmpdir, 'open2fa.uuid')):
        os.remove(os.path.join(_tmpdir, 'open2fa.uuid'))
    if osp.exists(os.path.join(_tmpdir, 'secrets.json')):
        os.remove(os.path.join(_tmpdir, 'secrets.json'))
    os.rmdir(_tmpdir)


@pt.fixture
def ranuuid():
    """Fixture to generate a random UUID for testing."""
    yield str(uuid4())


@pt.fixture
def o2fa_no_remote(randir):
    """Fixture to add a secret to the Open2FA instance."""
    o2fa = Open2FA(randir, None, _URL)
    for sec in _SECRETS:
        o2fa.add_secret(sec[0], sec[1])
    yield o2fa


@pt.fixture
def o2fa_remote(ranuuid, o2fa_no_remote):
    """Fixture to add a secret to the Open2FA instance."""
    new_o2fa = Open2FA(
        o2fa_no_remote.o2fa_dir, o2fa_uuid=ranuuid, o2fa_api_url=_URL
    )
    assert not os.path.exists(new_o2fa.uuid_file_path)
    with open(new_o2fa.uuid_file_path, 'w') as f:
        f.write(ranuuid)
    o2fa = Open2FA(new_o2fa.o2fa_dir, ranuuid, _URL)
    yield o2fa


def main_out(sysargs, *args, **kwargs):
    """returns open2fa cli main() output"""
    with patch('open2fa.cli.sys.argv', sysargs):
        with patch('sys.stdout', new=StringIO()) as fake_output:
            o2fa = main(*args, **kwargs, return_open2fa=True)
    return o2fa, fake_output.getvalue()


def test_remote_init(remote_init):
    """Test initializing the remote capabilities of Open2FA."""
    o2fa = remote_init
    _dir, _url, _uuid = o2fa.o2fa_dir, o2fa.api_url, o2fa.uuid
    assert o2fa.o2fa_dir == _dir
    assert o2fa.o2fa_api_url == _url
    assert o2fa.uuid == str(_uuid)
    assert os.path.exists(os.path.join(_dir, 'open2fa.uuid'))


def test_add_secret(o2fa_no_remote: Open2FA):
    """Test adding a secret to the Open2FA instance."""
    _o2fa = o2fa_no_remote
    assert _o2fa.o2fa_uuid is None
    assert _o2fa.o2fa_api_url == _URL
    assert _o2fa.uuid is None
    assert _o2fa.api_url == _URL

    assert not os.path.exists(_o2fa.uuid_file_path)


def test_add_secret_no_args(randir):
    """Test adding a secret to the Open2FA instance."""
    with patch('builtins.input', side_effect=[_TOTP, _NAME]):
        with patch('open2fa.cli.sys.argv', ['open2fa', 'add']):
            o2fa = main(
                dir=randir, api_url=_URL, uuid=None, return_open2fa=True
            )

    assert o2fa.o2fa_uuid is None
    assert o2fa.o2fa_api_url == _URL
    assert len(o2fa.secrets) == 1
    with open(o2fa.secrets_json_path, 'r') as f:
        secjson = f.read()

    assert _NAME in secjson
    assert _TOTP in secjson


def test_add_secret_no_args_none_name(randir):
    """Test adding a secret to the Open2FA instance."""
    with patch('open2fa.cli.sys.argv', ['open2fa', 'add']):
        with patch('sys.stdout', new=StringIO()) as fake_output:
            with patch('builtins.input', side_effect=[_TOTP, '']):
                o2fa = main(
                    dir=randir, api_url=_URL, uuid=None, return_open2fa=True
                )
    with open(o2fa.secrets_json_path, 'r') as f:
        secjson = f.read()

    assert o2fa.secrets[0].name is None


def test_add_secret_no_args_no_input(randir):
    """Test adding a secret to the Open2FA instance."""
    with patch('open2fa.cli.sys.argv', ['open2fa', 'add']):
        with patch('sys.stdout', new=StringIO()) as fake_output:
            with patch('builtins.input', side_effect=['a', 'b', 'c', 'd']):
                with pt.raises(SystemExit):
                    main(dir=randir, api_url=_URL, uuid=None)

    assert 'exiting' in fake_output.getvalue().lower()


@patch('builtins.input', return_value='y')
def test_delete_secret(o2fa_no_remote):
    """Test removing a secret from the Open2FA instance."""

    o2fa = o2fa_no_remote
    print(o2fa.secrets, len(o2fa.secrets))
    og = len(o2fa.secrets)
    with patch('open2fa.cli.sys.argv', ['open2fa', 'delete', '-n %s' % _NAME]):
        main(dir=o2fa.o2fa_dir, api_url=None, uuid=None)
    print(o2fa.secrets, len(o2fa.secrets), 'before refresh')
    o2fa.refresh_secrets()
    print(o2fa.secrets, len(o2fa.secrets), 'after refresh')


def test_generate_key(ranuuid, randir, o2fa_no_remote):
    """Test generating a TOTP code for the added secret."""
    o2fa = Open2FA(randir, ranuuid, _URL)
    o2fa.add_secret(_TOTP, _NAME)
    for s in ['Name', 'Code', 'Next'] + [
        o.name for o in o2fa.secrets if o.name
    ]:
        print(s)


def test_list_no_s(o2fa_remote):
    """Test listing the added secret."""
    o2fa, out = main_out(['open2fa', 'list'])
    for s in o2fa.secrets:
        print(s.name, s.secret, out, s, vars(s))
        assert s.name in out
        assert '...' in out


def test_list_dash_s(fake_enc_secrets, randir, ranuuid):
    """Test listing the added secret."""
    o2fa, out = main_out(
        ['open2fa', 'list', '-s'],
        open2fa_dir=randir,
        api_url=_URL,
        uuid=ranuuid,
    )
    for s in o2fa.secrets:
        assert s.name in out
        assert s.secret in out


def test_list_with_no_secrets(remote_init):
    """regression test for error occuring if no secrets were added"""
    o2fa, out = main_out(
        ['open2fa', 'list'],
        dir=remote_init.o2fa_dir,
        api_url=_URL,
        uuid=remote_init.o2fa_uuid.uuid,
    )
    print(out, o2fa, vars(o2fa))
    for s in o2fa.secrets:
        if s.name:
            assert s.name in out
            assert '...' in out


def test_remote_pull(o2fa_remote):
    """Test pulling the remote capabilities of Open2FA."""
    enc = o2fa_remote.o2fa_uuid.remote.encrypt(_TOTP)
    secname = 'name2'
    fake_totp_data = {'totps': [{'name': secname, 'enc_secret': enc}]}

    class FakeResp:
        data = fake_totp_data

    with patch('open2fa.main.apireq', return_value=FakeResp()) as fake_apireq:
        o2fa, out = main_out(
            ['open2fa', 'remote', 'pull'],
            dir=o2fa_remote.o2fa_dir,
            api_url=_URL,
            uuid=o2fa_remote.o2fa_uuid.uuid,
        )

    assert osp.exists(o2fa.secrets_json_path)
    secjson = open(o2fa.secrets_json_path, 'r').read()
    assert secname in secjson
    assert _TOTP in secjson
    assert _NAME not in secjson


def test_remote_push(o2fa_remote):
    """Test pushing the remote capabilities of Open2FA."""
    o2fa = o2fa_remote
    new_secret = TOTPSecret(_TOTP, 'newsecretname')

    with patch('open2fa.main.apireq') as fake_apireq:
        fake_apireq.return_value.data = {
            'totps': [
                {
                    'name': new_secret.name,
                    'enc_secret': o2fa.encrypt(new_secret.secret),
                }
            ]
        }
        o2fa.remote_push()

    assert fake_apireq.called
    _ret = list(fake_apireq.return_value.data['totps'])
    _retnames = [sec['name'] for sec in _ret] + [
        sec.name for sec in o2fa.secrets
    ]

    for sec in o2fa.secrets:
        assert sec.name in _retnames


def test_remote_push_no_uuid_error():
    """Test pushing the remote capabilities of Open2FA."""
    loc_o2fa = Open2FA('/tmp/%s' % ranstr(10), None, 'http://example')
    loc_o2fa.add_secret(_TOTP, 'name1')
    with pt.raises(EX.NoUUIDError):
        loc_o2fa.remote_push()


def test_handle_remote_init(remote_init):
    """Test the handle_remote_init function."""
    assert remote_init.o2fa_uuid is not None
    assert remote_init.o2fa_api_url == _URL
    assert os.path.exists(os.path.join(remote_init.o2fa_dir, 'open2fa.uuid'))


def test_handle_remote_delete_errors_nosecs():
    """Test the handle_remote_delete function."""
    o2fa = Open2FA('/tmp/%s' % ranstr(10), None, 'http://example')

    with pt.raises(EX.NoUUIDError):
        o2fa.remote_delete()

    o2fa = Open2FA('/tmp/%s' % ranstr(10), str(uuid4()), 'http://example')

    with pt.raises(EX.DelNoNameSec):
        o2fa.remote_delete()


def test_handle_remote_delete_no_sec_found(remote_init: Open2FA):
    """Test the handle_remote_delete function."""
    o2fa = remote_init
    o2fa.add_secret(_TOTP, 'name1')

    with pt.raises(EX.DelNoNameSecFound):
        o2fa.remote_delete('name2')


def test_info_no_dash_s(fake_enc_secrets, randir, ranuuid):
    """Ensure that the -s tip is printed and secs are truncated with info"""
    o2fa = Open2FA(randir, ranuuid, _URL)
    with patch('open2fa.main.Open2FA.remote_pull') as fake_remote_pull:
        fake_remote_pull.return_value = fake_enc_secrets
        with patch('open2fa.main.apireq') as fake_apireq:
            op2fa, out = main_out(
                ['open2fa', 'info'],
                dir=o2fa.o2fa_dir,
                api_url=_URL,
                uuid=str(o2fa.o2fa_uuid.uuid),
            )

        for substr in [' -s ', '...', _URL, str(randir), 'UUID', 'Secret']:
            assert substr in out


def test_info_dash_s(fake_enc_secrets, randir, ranuuid):
    """Ensure that the -s tip is not printed and secs are not truncated with info"""

    o2fa = Open2FA(randir, ranuuid, _URL)

    with patch('open2fa.main.Open2FA.remote_pull') as fake_remote_pull:
        fake_remote_pull.return_value = fake_enc_secrets

        op2fa, out = main_out(
            ['open2fa', 'info', '-s'],
            dir=o2fa.o2fa_dir,
            api_url=_URL,
            uuid=o2fa.o2fa_uuid.uuid,
        )
    assert '...' not in out
    assert op2fa.o2fa_api_url in out
    assert str(op2fa.o2fa_uuid.uuid) in out
    assert MSGS.INFO_SEC_TIP not in out
    assert str(op2fa.o2fa_uuid.remote.b58) in out


def test_remote_delete(remote_init):
    """Test deleting the remote capabilities of Open2FA."""
    o2fa = remote_init
    o2fa.add_secret(_TOTP, 'name1')

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
                    api_url=_URL,
                    uuid=str(o2fa.o2fa_uuid.uuid),
                    return_open2fa=True,
                )

    assert 'Deleted 1 secret' in fake_output.getvalue()


@pt.mark.parametrize('version_arg', ['-v', '--version'])
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


@patch('open2fa.main.apireq')
def test_new_cli_kwargs(fake_apireq, randir, ranuuid):
    """Test the new cli keyword arguments."""
    fake_apireq.return_value.data = {'totps': []}

    with patch('open2fa.cli.sys.argv', ['open2fa', 'info', '-s']):
        with patch('sys.stdout', new=StringIO()) as fake_output:
            o2fa, out = main_out(
                ['open2fa', 'info', '-s'],
                dir=randir,
                api_url='http://example',
                uuid=ranuuid,
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
        o2fa.add_secret(_TOTP, 'a' * i)

    def _autosize_generate_code(o2fa, **kwargs):
        w, h = kwargs['w'], kwargs['h']
        with patch(
            'os.get_terminal_size', return_value=MagicMock(columns=w, lines=h)
        ):
            new_o2fa, out = main_out(
                ['open2fa', 'g', '-r', '1'],
                dir=o2fa.o2fa_dir,
                api_url='http://example',
                uuid=None,
            )
            out = out.lower()

            for i, line in enumerate(out.splitlines()):
                if line == '':
                    continue
                _s = {
                    line.find(x) for x in ['not shown', '---', 'name', 'aaa']
                }
                assert len(_s) > 1

    for w, h in zip(TEST_WIDTHS, TEST_HEIGHTS):
        _autosize_generate_code(o2fa, w=w, h=h)


_RETDATA = {
    'totps': [
        {'name': 'name1', 'enc_secret': _TOTP},
        {'name': 'name2', 'enc_secret': _TOTP},
        {'name': 'name3', 'enc_secret': _TOTP},
    ]
}


@pt.mark.parametrize(
    'no_save_remote, ret_data, show_secrets',
    [
        (True, _RETDATA, False),
        (False, _RETDATA, False),
        (True, {'totps': []}, False),
        (False, {'totps': []}, False),
        (True, _RETDATA, True),
    ],
)
def test_remote_list_pull(
    no_save_remote, ret_data, show_secrets, randir, ranuuid
):
    o2fa = Open2FA(randir, ranuuid, 'http://example')
    o2fa.add_secret(_TOTP, 'name1')

    with patch('open2fa.main.apireq') as fake_apireq:
        for i, data in enumerate(ret_data['totps']):
            ret_data['totps'][i]['enc_secret'] = o2fa.o2fa_uuid.remote.encrypt(
                _TOTP
            )

        fake_apireq.return_value.data = ret_data
        with patch('open2fa.main.Open2FA.write_secrets') as fake_write_secrets:
            remote_secs = o2fa.remote_pull(no_save_remote=no_save_remote)
            remote_names = {sec.name for sec in remote_secs}

    if no_save_remote:
        assert not fake_write_secrets.called
        assert len(remote_secs) == len(ret_data['totps'])
        assert len(o2fa.secrets) == 1
    else:
        assert fake_write_secrets.called
        assert len(remote_secs) == len(ret_data['totps'])
        if ret_data['totps']:
            assert len(o2fa.secrets) == len(ret_data['totps'])
        else:
            assert len(o2fa.secrets) == 1

    with patch('open2fa.main.apireq') as fake_apireq:
        fake_apireq.return_value.data = ret_data
        new_o2fa, out = main_out(
            ['open2fa', 'remote', 'list'] + (['-s'] if show_secrets else []),
            dir=o2fa.o2fa_dir,
            api_url='http://example',
            uuid=str(o2fa.o2fa_uuid.uuid),
        )

    for sec in ret_data['totps']:
        if sec and sec['name']:
            assert sec['name'] in out

        if show_secrets:
            assert _TOTP in out
        else:
            assert '...' in out
