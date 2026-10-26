"""Portable custom recognizers registered with Presidio's native API."""
from collections.abc import Mapping
import re

from presidio_analyzer import Pattern, PatternRecognizer


def build_recognizers(options: Mapping[str, object]):
    """Return Presidio EntityRecognizer objects for explicit adapter registration."""
    if type(options) is not dict or set(options) - {"prefix"}:
        raise ValueError("invalid firm recognizer options")
    prefix = options.get("prefix", "FIRM-DEMO")
    if type(prefix) is not str or not re.fullmatch(r"[A-Z][A-Z0-9-]{2,31}", prefix):
        raise ValueError("invalid firm recognizer options")
    pattern = Pattern(
        name="synthetic firm account identifier",
        regex=rf"\b{re.escape(prefix)}-[A-Z0-9]{{8}}\b",
        score=0.8,
    )
    return [
        PatternRecognizer(
            name="SyntheticFirmAccountRecognizer",
            supported_entity="FIRM_ACCOUNT_ID",
            supported_language="en",
            patterns=[pattern],
            context=["account", "member", "customer"],
        )
    ]
