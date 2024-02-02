from pyshared import truncstr


def sec_trunc(secret: str) -> str:
    """Returns secret like a...b"""
    return truncstr(secret, start_chars=1, end_chars=1)
