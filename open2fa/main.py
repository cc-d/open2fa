from . import config
from .common import O2FAUUID, RemoteSecret, TOTPSecret
from .totp import TOTP2FACode, generate_totp_2fa_code
from .cli_utils import (
    ensure_open2fa_dir,
    ensure_secrets_json,
    read_secrets_json,
)
import typing as TYPE
import json


class Open2FA:
    def __init__(self, remote_sync: bool = False):
        """Create a new Open2FA object."""
