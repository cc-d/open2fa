import uuid
from hashlib import blake2s

from cryptography.fernet import Fernet

from open2fa import config


def enc_totp_secret(secret: str) -> str:
    if config.OPEN2FA_ID is None:
        raise Exception(
            'OPEN2FA_ID is not set. Add to env var or .open2fa/open2fa.id'
        )

    f = Fernet(config.OPEN2FA_ID.replace('-', ''))

    return f.encrypt(secret.encode('utf-8')).decode('utf-8')


def dec_totp_secret(secret: str | bytes) -> str:
    if config.OPEN2FA_ID is None:
        raise Exception(
            'OPEN2FA_ID is not set. Add to env var or .open2fa/open2fa.id'
        )
    if isinstance(secret, bytes):
        secret = secret.decode('utf-8')

    f = Fernet(config.OPEN2FA_ID.replace('-', ''))

    return f.decrypt(secret.encode('utf-8')).decode('utf-8')


def gen_user_hash(uid: str) -> str:
    """for a given dashless uuid, return a 128-bit (16 bytes) blake2s hash"""
    return blake2s(uid.encode('utf-8'), digest_size=16).hexdigest()


def gen_uuid() -> str:
    """returns a uuid4 str without dashes"""
    return str(uuid.uuid4()).replace('-', '')
