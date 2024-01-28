import os
from pathlib import Path

OPEN2FA_DIR = os.environ.get('OPEN2FA_DIR', Path.home() / '.open2fa')


OPEN2FA_ID = os.environ.get('OPEN2FA_ID', None)
if OPEN2FA_ID is None and os.path.exists(
    os.path.join(OPEN2FA_DIR, 'open2fa.id')
):
    # read from file if filepath set
    with open(os.path.join(OPEN2FA_DIR, 'open2fa.id'), 'r') as f:
        OPEN2FA_ID = f.read().strip()

OPEN2FA_API_URL = os.environ.get(
    'OPEN2FA_API_URL', 'https://open2fa.liberfy.ai/api/v1'
)

# octal directory permissions
OPEN2FA_DIR_PERMS = 0o700

OPEN2FA_KEY_PERMS = 0o600

INTERVAL = 30
