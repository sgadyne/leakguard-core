"""Errors contain only fixed public codes, never upstream exception text."""
class BrokerError(Exception):
    def __init__(self, code="request-denied", status=403):
        self.code = code
        self.status = status
        super().__init__(code)
