import uuid
from hashlib import blake2s
from typing import Optional as Opt
import base64 as b64

from cryptography.fernet import Fernet

from open2fa import config
from logfunc import logf


def _ensure_fernet(uid: Opt[str] = None) -> Fernet:
    if uid is None:
        if config.OPEN2FA_ID is None:
            raise Exception(
                'OPEN2FA_ID is not set. Add to env var or .open2fa/open2fa.id'
            )
        uid = config.OPEN2FA_ID.replace('-', '')
    b64key = b64.b64encode(uid.encode('utf-8'))
    return Fernet(b64key)


def enc_totp_secret(secret: str | bytes, uid: Opt[str] = None) -> str:
    """encrypts a totp secret using the OPEN2FA_ID"""
    if isinstance(secret, bytes):
        secret = secret.decode('utf-8')
    f = _ensure_fernet(uid)

    return f.encrypt(secret.encode('utf-8')).decode('utf-8')


def dec_totp_secret(secret: str | bytes, uid: Opt[str] = None) -> str:
    """decrypts a totp secret using the OPEN2FA_ID"""
    if isinstance(secret, bytes):
        secret = secret.decode('utf-8')

    f = _ensure_fernet(uid)

    return f.decrypt(secret.encode('utf-8')).decode('utf-8')


def gen_user_hash(uid: str) -> str:
    """for a given dashless uuid, return a 128-bit (16 bytes) blake2s hash"""
    return blake2s(uid.encode('utf-8'), digest_size=16).hexdigest()


def gen_uuid() -> str:
    """returns a uuid4 str without dashes"""
    return str(uuid.uuid4()).replace('-', '')
