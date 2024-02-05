class SecretExistsError(ValueError):
    def __init__(self, message: str = 'Secret already exists'):
        super().__init__(message)


class NoUUIDError(ValueError):
    def __init__(
        self,
        message: str = (
            'No O2FAUUID found. Run `open2fa remote init` or '
            'create .open2fa/open2fa.uuid / set OPEN2FA_UUID'
        ),
    ):
        super().__init__(message)


class RemoteError(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class DelNoNameSec(Exception):
    def __init__(self, message: str = 'No secret or name provided'):
        super().__init__(message)


class DelNoNameSecFound(Exception):
    def __init__(self, message: str = 'No secret found for that name/secret'):
        super().__init__(message)
