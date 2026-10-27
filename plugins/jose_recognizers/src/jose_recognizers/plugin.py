"""Explicit Presidio factory for the optional JOSE recognizer package."""
from presidio_analyzer import EntityRecognizer

from .recognizer import JOSECompactRecognizer


def build_recognizers(options: dict[str, object]) -> list[EntityRecognizer]:
    """Return a recognizer for explicit registration by the Presidio adapter."""
    if type(options) is not dict or options:
        raise ValueError("invalid JOSE recognizer options")
    return [JOSECompactRecognizer()]
