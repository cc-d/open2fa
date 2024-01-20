import logging
import os
import os.path as osp
import random as RAN
import re
import shutil
import string as STR
import subprocess as SUB
import sys
from glob import glob
from io import StringIO
from unittest.mock import patch

import pytest

from open2fa.cli_config import MSGS
from open2fa.cli_utils import Open2FA, Open2faKey
from open2fa.utils import generate_totp_token
from open2fa.common import enc_totp_secret, dec_totp_secret

logger = logging.getLogger(__name__)

TEST_UID = '4a26e0f1d58048c188324c29ae463101'
TEST_ORG = 'Test Org'
TEST_TOTP = 'JBSWY3DPEHPK3PXP'
TEST_ENC_SEC = 'gAAAAABlq_ia8qJoDt5weWB_BKoOOrhh-FNQHwyVnV0reVIKGH74chN_PCkdWz3MR_TFOzsBqRGCvcpvHf8-f5lNZwkJxwf83_z8hBgQNoDJdiPXUj427jo='
TEST_SEC = 'JBSWY3DPEHPK3PXP'


def _ranstr(n: int) -> str:
    """Generate a random string of length n."""
    return ''.join(RAN.choice(STR.ascii_letters) for _ in range(n))


@pytest.fixture(scope='function', autouse=True)
def setenv():
    """Set the OPEN2FA_KEYDIR environment variable."""
    os.environ['OPEN2FA_KEYDIR'] = '/tmp/' + _ranstr(10)
    yield
    del os.environ['OPEN2FA_KEYDIR']


def test_add_key():
    """Test adding a key."""
    from open2fa.cli import main

    sys.argv = ['open2fa', 'add', 'test', TEST_SEC]

    with patch('sys.stdout', new=StringIO()) as fake_out:
        with patch('builtins.input', return_value='y') as fake_input:
            main()

    assert 'Added key' in fake_out.getvalue()


def test_key_delete():
    """Test deleting a key."""
    from open2fa.cli import main

    orgname = _ranstr(10)
    sys.argv = ['open2fa', 'add', orgname, TEST_SEC]
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
    sys.argv = ['open2fa', 'add', orgname, TEST_SEC]
    main()
    sys.argv = ['open2fa', 'list']

    with patch('sys.stdout', new=StringIO()) as fake_out:
        main()
    assert orgname in fake_out.getvalue()


def test_add_already_exists():
    """Test adding a key that already exists."""
    from open2fa.cli import main

    orgname = _ranstr(10)
    sys.argv = ['open2fa', 'add', orgname, TEST_SEC]
    main()
    sys.argv = ['open2fa', 'add', orgname, TEST_SEC]
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


# common.py
def test_enc_dec_totp_secret():
    """Test encrypting and decrypting a TOTP secret."""
    enc = enc_totp_secret(TEST_SEC, TEST_UID)
    dec = dec_totp_secret(enc, TEST_UID)
    assert dec == TEST_SEC


def test_config_uid():
    """Test the OPEN2FA_ID config variable."""
    with patch('open2fa.config.OPEN2FA_ID', None):
        with pytest.raises(Exception):
            from open2fa.common import _ensure_fernet

            _ensure_fernet()
