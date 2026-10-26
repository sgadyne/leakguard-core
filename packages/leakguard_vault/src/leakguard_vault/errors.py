"""Stable errors deliberately exclude paths, passphrases and source values."""


class VaultError(RuntimeError):
    def __init__(self, code: str = "vault-failed") -> None:
        self.code = code
        super().__init__(code)
