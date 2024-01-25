import base64
import base64 as b64
import hashlib
import hmac
import os
import struct
import time
import uuid
from functools import wraps
from hashlib import sha256
from pathlib import Path
from typing import Optional as Opt

import base58
from base58 import b58decode as b58dec
from base58 import b58encode as b58enc
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from logfunc import logf

from open2fa import config


def generate_totp_token(secret: str, interval_length: int = 30) -> str:
    """
    Generate a TOTP token using the provided secret key.
    Args:
        secret (str): The base32 encoded secret key.
        interval_length (int): The time step in seconds. Default is 30 seconds.
    Returns:
        str: A 6-digit TOTP token.
    """

    # Decode the base32 encoded secret key. Casefold=True allows for
    # lowercase alphabet in the key.
    key = base64.b32decode(secret, casefold=True)

    # Calculate the number of intervals that have passed since Unix epoch.
    # Time is divided by interval_length to find the current interval.
    interval = int(time.time()) // interval_length

    # Convert the interval into 8-byte big-endian format.
    msg = struct.pack(">Q", interval)

    # Create an HMAC-SHA1 hash of the interval, using the secret key.
    hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()

    # Extracts the last 4 bits of the HMAC output to use as an offset.
    o = hmac_digest[19] & 15

    # Use the offset to extract a 4-byte dynamic binary
    # code from the HMAC result. The '& 0x7FFFFFFF' is applied
    # to mask off the high bit of the extracted value.
    code = struct.unpack(">I", hmac_digest[o : o + 4])[0] & 0x7FFFFFFF

    # The dynamic binary code is then reduced to a 6-digit code and returned.
    return str(code % 10**6).zfill(6)


@logf()
def enc_totp_secret(secret: str | bytes, uid: str):
    """encrypts a totp secret using the OPEN2FA_ID"""
    if isinstance(secret, bytes):
        secret = secret.decode('utf-8')

    return aes_encrypt(secret, uid)


@logf()
def dec_totp_secret(secret: str | bytes, uid: str):
    """decrypts a totp secret using the OPEN2FA_ID"""
    if isinstance(secret, bytes):
        secret = secret.decode('utf-8')

    return aes_decrypt(secret, uid)


@logf(level='warning')
def gen_user_hash(b58_uid: str) -> str:
    """for a uid str, return 32char trunc sha256 hash that is b58 encoded"""
    return sha256(b58_uid.encode('utf-8')).hexdigest()[:32]


@logf(level='warning')
def gen_uuid() -> str:
    """returns the base58-encoded uuid"""
    return b58enc(uuid.uuid4().bytes).decode()


@logf()
def aes_encrypt(data: str, enc_key: bytes) -> str:
    enc_key_bytes = base58.b58decode(enc_key)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(enc_key_bytes), modes.ECB(), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    enc_data = encryptor.update(padded_data) + encryptor.finalize()

    enc_data = base58.b58encode(enc_data).decode()
    return enc_data


@logf()
def aes_decrypt(enc_data: str, enc_key: bytes) -> str:
    enc_key_bytes = base58.b58decode(enc_key)

    enc_data = base58.b58decode(enc_data)

    cipher = Cipher(
        algorithms.AES(enc_key_bytes), modes.ECB(), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(enc_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()
