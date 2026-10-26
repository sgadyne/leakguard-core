"""Stable, value-free adapter errors."""


class HostError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
