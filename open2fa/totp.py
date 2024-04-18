import base64 as b64
import hashlib
import hmac
import os
import struct
import time

from pyshared import default_repr


class TOTP2FACode:
    code: str
    generated_at: float
    cur_interval: int
    next_interval_in: float
    interval_length: int
    next_code_at: float

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self) -> str:
        return default_repr(self)


def generate_totp_2fa_code(
    secret: str, interval_length: int = 30
) -> TOTP2FACode:
    """Generate a TOTP token using the provided secret key.
    ~secret (str): The base32 encoded secret key.
    ~interval_length (int): The time step in seconds. Default is 30 seconds.
    -> TOTP2FACode: the generated code object as well as other info
    """

    # Decode the base32 encoded secret key. Casefold=True allows for
    # lowercase alphabet in the key.
    key = b64.b32decode(secret, casefold=True)

    # Calculate the number of intervals that have passed since Unix epoch.
    # Time is divided by interval_length to find the current interval.
    cur_time = time.time()
    interval = int(cur_time) // interval_length

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
    code = str(code % 10**6).zfill(6)

    # calculate the time at which the next code will be generated
    next_code_at = (interval + 1) * interval_length

    return TOTP2FACode(
        code=code,
        generated_at=cur_time,
        cur_interval=interval,
        next_interval_in=interval_length - (cur_time % interval_length),
        interval_length=interval_length,
        next_code_at=next_code_at,
    )
