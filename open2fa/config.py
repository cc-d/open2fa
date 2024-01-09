import os
from pathlib import Path

OPEN2FA_KEYDIR = os.environ.get('OPEN2FA_KEYDIR', Path.home() / '.open2fa')

# octal directory permissions
OPEN2FA_KEYDIR_PERMS = 0o700

INTERVAL = 30
