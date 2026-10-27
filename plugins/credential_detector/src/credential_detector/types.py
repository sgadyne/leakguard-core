"""Value-free locations in the original input, in Unicode codepoints."""
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CredentialSpan:
    rule: str
    start: int
    end: int
