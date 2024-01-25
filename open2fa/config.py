import os
from pathlib import Path

OPEN2FA_KEYDIR = os.environ.get('OPEN2FA_KEYDIR', Path.home() / '.open2fa')


OPEN2FA_ID = None
if os.environ.get('OPEN2FA_ID', None):
    OPEN2FA_ID = os.environ.get('OPEN2FA_ID')
    if os.path.exists(OPEN2FA_ID):
        # read from file if filepath set
        with open(OPEN2FA_ID, 'r') as f:
            OPEN2FA_ID = f.read().strip()
elif os.path.exists(os.path.join(OPEN2FA_KEYDIR, 'open2fa.id')):
    # read from file if filepath set
    with open(os.path.join(OPEN2FA_KEYDIR, 'open2fa.id'), 'r') as f:
        OPEN2FA_ID = f.read().strip()

OPEN2FA_API_URL = os.environ.get(
    'OPEN2FA_API_URL', 'https://open2fa.liberfy.ai/api/v1'
)

# octal directory permissions
OPEN2FA_KEYDIR_PERMS = 0o700

OPEN2FA_KEY_PERMS = 0o600

INTERVAL = 30
