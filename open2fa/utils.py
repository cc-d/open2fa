import base64
import hashlib
import hmac
import struct
import time
from functools import wraps
from typing import Optional
from pathlib import Path


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
