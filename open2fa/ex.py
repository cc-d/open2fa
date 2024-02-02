class SecretExistsError(ValueError):
    def __init__(self, message: str = 'Secret already exists'):
        super().__init__(message)
