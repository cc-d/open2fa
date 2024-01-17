import uuid
from hashlib import sha256

from cryptography.fernet import Fernet

from open2fa import config


def enc_secret(secret: str) -> str:
    if config.OPEN2FA_ID is None:
        raise Exception(
            'OPEN2FA_ID is not set. Add to env var or .open2fa/open2fa.id'
        )

    f = Fernet(config.OPEN2FA_ID)

    return f.encrypt(secret.encode('utf-8')).decode('utf-8')


def dec_secret(secret: str | bytes) -> str:
    if config.OPEN2FA_ID is None:
        raise Exception(
            'OPEN2FA_ID is not set. Add to env var or .open2fa/open2fa.id'
        )
    if isinstance(secret, bytes):
        secret = secret.decode('utf-8')

    f = Fernet(config.OPEN2FA_ID)

    return f.decrypt(secret.encode('utf-8')).decode('utf-8')


def get_user_hash(user: str) -> str:
    return sha256(user.encode('utf-8')).hexdigest()


def gen_uuid() -> str:
    return str(uuid.uuid4())
