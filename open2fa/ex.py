class NoKeyFoundError(FileNotFoundError):
    def __init__(self, org_name: str):
        self.org_name = org_name
        super().__init__(
            f"No key found for organization '{org_name}'. "
            "Use the 'add' command (cli.py add) to add a new org key."
        )
