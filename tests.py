import pytest
from io import StringIO
from unittest.mock import patch
import sys
import os
from open2fa.main import Open2FA

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
        main()

    # Return values that might be useful for the test
    yield TEST_NAME, TEST_TOTP, os.environ['OPEN2FA_DIR']

    # Here you can add steps to delete the secret if necessary
    sys.argv = ['open2fa', 'delete', TEST_NAME]
    with patch('sys.stdout', new=StringIO()) as fake_delete:
        with patch('builtins.input', return_value='y') as fake_input:
            main()
    del os.environ['OPEN2FA_DIR']


def test_generate_key(add_secret):
    """Test generating a TOTP code for the added secret."""
    from open2fa.cli import main

    # Use the added secret to generate a code
    sys.argv = ['open2fa', 'generate', '-r', '1']
    with patch('sys.stdout', new=StringIO()) as fake_generate:
        main()

    # Assertions about the generated code can go here
    # For example, check if the output contains expected elements of a TOTP code
    assert "Code" in fake_generate.getvalue()


def test_wrap_delete():
    def test_delete_secret(add_secret):
        pass

    test_delete_secret(add_secret)
    from open2fa.cli import main

    sys.argv = ['open2fa', 'list']
    with patch('sys.stdout', new=StringIO()) as fake_list:
        main()
    assert TEST_NAME not in fake_list.getvalue()
