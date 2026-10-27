"""Adapter between detector implementations and eval-only raw candidates."""
from __future__ import annotations

from dataclasses import dataclass
import importlib
from collections.abc import Mapping
from typing import Any


@dataclass(frozen=True)
class Candidate:
    start: int | None
    end: int | None
    score: float | None
    severity: str | None
    rule: str | None
    entity: str | None


def _value(item: Any, name: str, default=None):
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _normalize(item: Any) -> Candidate:
    if isinstance(item, Candidate):
        return item
    analysis = _value(item, "analysis")
    if analysis is None:
        analysis = {}
    start = _value(analysis, "start")
    end = _value(analysis, "end")
    score = _value(analysis, "score")
    entity = _value(analysis, "entity_type") or _value(analysis, "entity")
    if isinstance(analysis, Mapping):
        start = analysis.get("start", start)
        end = analysis.get("end", end)
        score = analysis.get("score", score)
        entity = analysis.get("entity_type", analysis.get("entity", entity))
    if start is not None and (type(start) is not int or start < 0):
        start = None
    if end is not None and (type(end) is not int or end < 0):
        end = None
    if type(score) not in {int, float} or not 0 <= float(score) <= 1:
        score = None
    else:
        score = float(score)
    severity = _value(item, "severity")
    if severity not in {"block", "review", "info", None}:
        severity = None
    rule = _value(item, "rule")
    return Candidate(start, end, score, severity, rule if isinstance(rule, str) else None,
                     entity if isinstance(entity, str) else None)


class DetectorAdapter:
    """Load a configured detector factory and request unfiltered candidates.

    Profile schema is deliberately small and eval-only:
      {"factory": "package.module:Factory", "options": {...},
       "review_score_threshold": 0.35, "block_score_threshold": 0.80}

    A PresidioDetector profile must configure `score-threshold` as "0" so the
    detector's production threshold cannot discard scores before evaluation.
    The tool never accesses private recognizer patterns or regexes.
    """

    def __init__(self, profile: Mapping[str, Any]):
        if not isinstance(profile, Mapping) or set(profile) - {
            "factory", "options", "review_score_threshold", "block_score_threshold",
            "name", "production_score_threshold", "production_block_entities",
        }:
            raise ValueError("profile-invalid")
        factory_path = profile.get("factory")
        if type(factory_path) is not str or factory_path.count(":") != 1:
            raise ValueError("profile-invalid")
        module_name, factory_name = factory_path.split(":", 1)
        if not module_name or not factory_name:
            raise ValueError("profile-invalid")
        options = profile.get("options", {})
        if type(options) is not dict:
            raise ValueError("profile-invalid")
        if factory_name == "PresidioDetector" and options.get("score-threshold") != "0":
            raise ValueError("raw-candidates-require-zero-score-threshold")
        module = importlib.import_module(module_name)
        factory = getattr(module, factory_name)
        self.detector = factory(options)
        self.name = profile.get("name", factory_path)
        self.review_threshold = self._threshold(profile.get("review_score_threshold", 0.35))
        self.block_threshold = self._threshold(profile.get("block_score_threshold", 0.80))
        if self.block_threshold < self.review_threshold:
            raise ValueError("profile-invalid")

    @staticmethod
    def _threshold(value):
        if type(value) not in {int, float} or not 0 <= float(value) <= 1:
            raise ValueError("profile-invalid")
        return float(value)

    def detect(self, text: str, context) -> list[Candidate]:
        result = self.detector.detect(text, context)
        return [_normalize(item) for item in result]

    def close(self):
        close = getattr(self.detector, "close", None)
        if callable(close):
            close()
