import json
from typing import Optional as Opt

import requests as req
from logfunc import logf
from pyshared import truncstr, default_repr

from . import ex as EX
from .config import OPEN2FA_API_URL, OPEN2FA_UUID


def sec_trunc(secret: str) -> str:
    """Returns secret like a...b"""
    return truncstr(secret, start_chars=1, end_chars=1)


class ApiResponse:
    @logf()
    def __init__(self, response: req.Response):
        self.response = response
        if response.status_code == 200:
            self.data = response.json()
        self.text = response.text
        self.status_code = response.status_code
        print(self)

    def __repr__(self):
        return default_repr(
            self, repr_format='<{obj_name} {attributes}>', join_attrs_on=' '
        )


@logf()
def apireq(
    method: str,
    endpoint: str,
    data: Opt[dict] = None,
    headers: Opt[dict] = None,
    api_url: str = OPEN2FA_API_URL,
) -> ApiResponse:
    """Make a request to the Open2FA API.
    Args:
        method (str): the HTTP method
        endpoint (str): the API endpoint
        data (dict, optional): the request data
        headers (dict, optional): the request headers
        api_url (str): the API URL
            Default: OPEN2FA_API_URL
    Returns:
        requests.Response: the response object
    """
    if OPEN2FA_UUID is None and headers is None:
        raise EX.NoUUIDError()

    headers = headers or {'X-User-Hash': OPEN2FA_UUID}
    resp = ApiResponse(
        req.request(
            method, f'{api_url}/{endpoint}', json=data, headers=headers
        )
    )
    if resp.status_code != 200:
        raise EX.RemoteError('{} {}'.format(resp.status_code, resp.text))
    return resp


def input_confirm(prompt: str) -> bool:
    """Prompt user for confirmation."""
    return input(prompt).lower().strip().startswith('y')
