import typing as TYPE
from uuid import uuid4, UUID
from hashlib import sha256
from _hashlib import HASH
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

from base58 import b58encode, b58decode
import base64 as b64
import os
import os.path as osp
from pyshared import default_repr


class O2FASecret:
    secret: bytes
    iv: bytes

    def __init__(self, sha256_hash_bytes: bytes, iv=b'0123456789abcdef'):
        """Create a new O2FASecret objet.
        Args:
            sha256_hash_bytes (bytes): the last 16 bytes of the sha256 hash of
                the o2fa uuid
            iv (bytes): the initialization vector
                Default: b'0123456789abcdef'
        Returns:
            O2FASecret: the new O2FASecret object
        """
        self.secret = sha256_hash_bytes
        self.iv = iv

    def __repr__(self) -> str:
        return "O2FASecret(secret=b'{}', iv={})".format(
            b58encode(self.secret).decode(), self.iv
        )

    def encrypt(self, plaintext: str) -> str:
        """Encrypt the plaintext using the secret and iv.
        Args:
            plaintext (str): the plaintext to encrypt
        Returns:
            str: the encrypted ciphertext
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
        return b64.b64encode(ciphertext).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt the ciphertext using the secret and iv.
        Args:
            ciphertext (str): the ciphertext to decrypt
        Returns:
            str: the decrypted plaintext
        """
        cipher = Cipher(
            algorithms.AES(self.secret),
            modes.CBC(self.iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        unpadder = PKCS7(128).unpadder()
        padded_plaintext = (
            decryptor.update(b64.b64decode(ciphertext.encode()))
            + decryptor.finalize()
        )
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()


class O2FAUUID:
    uuid: UUID
    o2fa_id: str
    secret: O2FASecret

    def __init__(self, uuid: UUID | str | bytes):
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
        self.secret = O2FASecret(self.sha256[16:])

    def __repr__(self) -> str:
        return "O2FAUUID(uuid={}, o2fa_id=b'{}', secret={})".format(
            repr(self.uuid), self.o2fa_id, self.secret
        )
