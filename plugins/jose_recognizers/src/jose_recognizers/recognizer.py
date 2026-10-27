"""Presidio-native wrapper around the bounded compact JOSE scanner."""
from __future__ import annotations

from presidio_analyzer import EntityRecognizer, RecognizerResult

from .scanner import JWE_ENTITY, JWS_ENTITY, UNVERIFIED_ENTITY, scan_compact_tokens


class JOSECompactRecognizer(EntityRecognizer):
    """Report compact format candidates as structural labels only."""

    def __init__(self):
        super().__init__(
            supported_entities=[JWE_ENTITY, JWS_ENTITY, UNVERIFIED_ENTITY],
            name="LeakGuardJOSECompactRecognizer",
            supported_language="en",
        )

    def analyze(self, text, entities, nlp_artifacts=None):
        del nlp_artifacts
        requested = set(entities or self.supported_entities)
        if not requested.intersection(self.supported_entities):
            return []
        return [
            RecognizerResult(
                entity_type=match.entity_type,
                start=match.start,
                end=match.end,
                score=match.score,
            )
            for match in scan_compact_tokens(text)
            if match.entity_type in requested
        ]
