import os
from pathlib import Path

OPEN2FA_DIR = str(os.environ.get('OPEN2FA_DIR', Path.home() / '.open2fa'))
OPEN2FA_UUID_PATH = os.path.join(OPEN2FA_DIR, 'open2fa.uuid')


OPEN2FA_UUID = os.environ.get('OPEN2FA_UUID', None)
if OPEN2FA_UUID is None and os.path.exists(
    os.path.join(OPEN2FA_DIR, 'open2fa.uuid')
):
    # read from file if filepath set
    with open(os.path.join(OPEN2FA_DIR, 'open2fa.uuid'), 'r') as f:
        OPEN2FA_UUID = f.read().strip()

OPEN2FA_API_URL = os.environ.get(
    'OPEN2FA_API_URL', 'https://open2fa.liberfy.ai/api/v1'
)

# octal directory permissions
OPEN2FA_DIR_PERMS = 0o700

OPEN2FA_KEY_PERMS = 0o600

INTERVAL = 30
