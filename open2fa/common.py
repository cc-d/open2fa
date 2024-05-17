import base64 as b64
import os
import os.path as osp
import typing as TYPE
from hashlib import sha256
from time import time
from uuid import UUID, uuid4
from functools import wraps

from base58 import b58decode, b58encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from pyshared import default_repr

from .totp import TOTP2FACode, generate_totp_2fa_code
from .utils import sec_trunc


class RemoteSecret:
    secret: bytes
    iv: bytes
    b58: str

    def __init__(self, sha256_hash_bytes: bytes, iv=b'0123456789abcdef'):
        """Create a new O2FASecret objet.
        ~sha256_hash_bytes (bytes): the last 16 bytes of the sha256 hash of
            the open2fa uuid
        ~iv (bytes): the initialization vector to use for encryption
            Default: b'0123456789abcdef'
        -> O2FASecret: the new O2FASecret object
        """
        self.secret = sha256_hash_bytes
        self.b58 = b58encode(self.secret).decode()
        self.iv = iv

    def __repr__(self) -> str:
        return default_repr(self)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt the plaintext using the secret and iv.
        ~plaintext (str): the plaintext to encrypt
        -> str: the encrypted ciphertext
        """
        cipher = Cipher(
            algorithms.AES(self.secret),
            modes.CBC(self.iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        padder = PKCS7(128).padder()
        padded_plaintext = (
            padder.update(plaintext.encode()) + padder.finalize()
        )
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return b58encode(ciphertext).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt the ciphertext using the secret and iv.
        ~ciphertext (str): the ciphertext to decrypt
        -> str: the decrypted plaintext
        """
        cipher = Cipher(
            algorithms.AES(self.secret),
            modes.CBC(self.iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        unpadder = PKCS7(128).unpadder()
        padded_plaintext = (
            decryptor.update(b58decode(ciphertext)) + decryptor.finalize()
        )
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()


class O2FAUUID:
    uuid: UUID
    o2fa_id: str
    remote: RemoteSecret

    def __init__(self, uuid: TYPE.Union[str, UUID, bytes]):
        """Create a new O2FAUUID object."""
        # standardize the uuid input
        if isinstance(uuid, str):
            uuid = UUID(uuid)

        if isinstance(uuid, UUID):
            uuid = uuid.bytes

        # generate the secret
        self.uuid = UUID(bytes=uuid)
        self.sha256 = sha256(self.uuid.bytes).digest()
        self.o2fa_id = b58encode(self.sha256[:16]).decode()
        self.remote = RemoteSecret(self.sha256[16:])

    def __repr__(self) -> str:
        return default_repr(
            self, repr_format='<{obj_name} {attributes}>', join_attrs_on=' '
        )

    def __len__(self) -> int:
        return len(self.uuid.bytes)


class TOTPSecret:
    secret: str
    name: str
    code: TOTP2FACode

    def __init__(self, secret: str, name: str):
        self.secret = secret
        self.name = name
        self.code = generate_totp_2fa_code(self.secret)

    def generate_code(self) -> TYPE.Union[TOTP2FACode, None]:
        """Returns 2FA code if new code avaliable else None"""
        prev_code = self.code
        self.code = generate_totp_2fa_code(self.secret)
        if self.code.code != prev_code.code:
            return self.code

    def __repr__(self) -> str:
        return default_repr(
            self, repr_format='<{obj_name} {attributes}>', join_attrs_on=' '
        )

    def json(self) -> dict:
        return {'secret': self.secret, 'name': self.name}

    def enc_json(self, enc_func: TYPE.Callable[[str], str]) -> dict:
        """Returns as open2fa server expected json payload format"""
        return {'name': self.name, 'enc_secret': enc_func(self.secret)}

    def __getitem__(self, key: str) -> str:
        return getattr(self, key)
