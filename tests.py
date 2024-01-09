import os
import os.path as osp
import random as RAN
import shutil
import string as STR
import re
import subprocess as SUB
import sys
from glob import glob
from io import StringIO
from unittest.mock import patch
import logging
import pytest

logger = logging.getLogger(__name__)
TESTKEY = 'JBSWY3DPEHPK3PXP'


def _ranstr(n: int) -> str:
    """Generate a random string of length n."""
    return ''.join(RAN.choice(STR.ascii_letters) for _ in range(n))


@pytest.fixture(scope='module', autouse=True)
def setenv():
    """Set the OPEN2FA_KEYDIR environment variable."""
    os.environ['OPEN2FA_KEYDIR'] = '/tmp/' + _ranstr(10)
    yield
    del os.environ['OPEN2FA_KEYDIR']


def test_add_key():
    """Test adding a key."""
    sys.argv = ['open2fa', 'add', 'test', TESTKEY]
    with patch('sys.stdout', new=StringIO()) as fake_out:
        from open2fa.cli import main

        main()
    assert 'Added key' in fake_out.getvalue()


def test_key_delete():
    """Test deleting a key."""
    from open2fa.cli import main

    orgname = _ranstr(10)
    sys.argv = ['open2fa', 'add', orgname, TESTKEY]
    main()
    sys.argv = ['open2fa', 'delete', orgname]
    with patch('sys.stdout', new=StringIO()) as fake_out:
        main()
    assert 'Deleted key' in fake_out.getvalue()
    assert not osp.isfile(
        osp.join(os.environ['OPEN2FA_KEYDIR'], orgname + '.key')
    )


def test_key_list():
    """Test listing keys."""
    from open2fa.cli import main

    orgname = _ranstr(10)
    sys.argv = ['open2fa', 'add', orgname, TESTKEY]
    main()
    sys.argv = ['open2fa', 'list']

    with patch('sys.stdout', new=StringIO()) as fake_out:
        main()
    assert orgname.lower() in fake_out.getvalue()


def test_add_already_exists():
    """Test adding a key that already exists."""
    from open2fa.cli import main

    orgname = _ranstr(10)
    sys.argv = ['open2fa', 'add', orgname, TESTKEY]
    main()
    sys.argv = ['open2fa', 'add', orgname, TESTKEY]
    with patch('sys.stdout', new=StringIO()) as fake_out:
        with patch('builtins.input', return_value='y') as fake_input:
            main()
    assert 'Added key' in fake_out.getvalue()

    with patch('sys.stdout', new=StringIO()) as fake_out:
        with patch('builtins.input', return_value='n') as fake_input:
            with patch('open2fa.cli_utils.add_secret_key') as fake_add:
                main()


# Additional tests to increase coverage
def test_invalid_arguments():
    """Test the CLI with invalid arguments."""
    sys.argv = ['open2fa', 'invalid', 'argument']
    with pytest.raises(SystemExit):
        from open2fa.cli import main

        main()


def test_generate_command():
    """Test generating a TOTP code."""
    org_name = 'testorg'
    sys.argv = ['open2fa', 'add', org_name, 'JBSWY3DPEHPK3PXP']
    from open2fa.cli import main

    with patch('builtins.input', return_value='y') as fake_input:
        main()
    sys.argv = ['open2fa', 'generate', org_name, '-r', '1']
    with patch('sys.stdout', new=StringIO()) as fake_out:
        main()
        print(fake_out.getvalue(), '@' * 100)


def test_list_specific_org():
    """Test listing keys for a specific organization."""
    org_name = 'testorg'
    sys.argv = ['open2fa', 'list', org_name]
    from open2fa.cli import main

    with patch('sys.stdout', new=StringIO()) as fake_out:
        main()
    assert org_name in fake_out.getvalue()


# Fixing the tests
def test_no_keys_to_list():
    """Test listing keys when no keys are present."""
    sys.argv = ['open2fa', 'list']
    from open2fa.cli import main

    for delfile in glob(osp.join(os.environ['OPEN2FA_KEYDIR'], '*.key')):
        logger.info(f"Deleting {delfile}")
        os.remove(delfile)

    with patch('sys.stdout', new=StringIO()) as fake_out:
        with patch('sys.exit') as fake_exit:
            main()
    assert fake_exit.called
    assert 'No keys found' in fake_out.getvalue()
