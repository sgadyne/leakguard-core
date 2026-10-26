"""LeakGuard adapter for Microsoft Presidio's AnalyzerEngine.

One plugin instance builds one AnalyzerEngine. The core session worker keeps that
instance for multiple parts so spaCy and recognizer state are reused.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from bisect import bisect_right
from decimal import Decimal, InvalidOperation
import hashlib
import importlib
from importlib import metadata, util
from itertools import islice
import json
import math
import re
from typing import Any

from presidio_detector import __version__
from leakguard_core.plugins import (
    AnalysisMetadata,
    DistributionSpec,
    NewFinding,
    OptionSchema,
    OptionSpec,
    PluginManifest,
    RuleSpec,
)


API_VERSION = 2
ANALYZER_ID = "presidio"
ANALYZER_VERSION = "2.2.365"
STATIC_RULE_ID = "presidio-entity"
DEFAULT_ENTITIES = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
    "IP_ADDRESS",
)
_TOKEN = re.compile(r"[A-Z][A-Z0-9_]{0,79}\Z")
_LANGUAGE = re.compile(r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}\Z")
_MODEL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_FACTORY = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*):([A-Za-z_][A-Za-z0-9_]*)\Z")
_NER_MODES = ("required", "pattern-only")
_OPTION_FIELDS = (
    OptionSpec("entities", "list", default=list(DEFAULT_ENTITIES), max_length=64),
    OptionSpec("language", "string", default="en", max_length=16),
    OptionSpec("score-threshold", "string", default="0.35", max_length=16),
    OptionSpec("ner-mode", "enum", default="pattern-only", choices=_NER_MODES),
    OptionSpec("model-name", "string", default="en_core_web_sm", max_length=128),
    OptionSpec("block-entities", "list", default=[], max_length=64),
    OptionSpec("recognizer-modules", "list", default=[], max_length=16),
    OptionSpec("recognizer-options", "string", default="{}", max_length=32768),
)

MANIFEST = PluginManifest(
    id="presidio-detector",
    implementation_version=__version__,
    kind="detector",
    rules=(RuleSpec(id=STATIC_RULE_ID, minimum_severity="review"),),
    formats=("text",),
    part_kinds=("text",),
    options_schema=OptionSchema(fields=_OPTION_FIELDS),
    dependencies=(
        DistributionSpec(name="presidio-analyzer"),
    ),
    deterministic=True,
    external_state="none",
    requires_core=(0, 0),
    worker_lifetime="session",
    result_schema=2,
)


class PresidioConfigurationError(ValueError):
    """Safe configuration error; messages never include the input being scanned."""


def _parse_threshold(value: object) -> float:
    if type(value) is not str or len(value) > 16:
        raise PresidioConfigurationError("invalid score threshold")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError):
        raise PresidioConfigurationError("invalid score threshold") from None
    if not parsed.is_finite() or parsed < 0 or parsed > 1:
        raise PresidioConfigurationError("invalid score threshold")
    return float(parsed)


def _json_object(value: str) -> dict[str, Any]:
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    def reject_constant(_value):
        raise ValueError

    try:
        parsed = json.loads(value, object_pairs_hook=unique, parse_constant=reject_constant)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise PresidioConfigurationError("invalid recognizer options") from None
    if type(parsed) is not dict:
        raise PresidioConfigurationError("invalid recognizer options")
    return parsed


def _validate_options(options: Mapping[str, object]) -> dict[str, Any]:
    if type(options) is not dict:
        raise PresidioConfigurationError("invalid detector options")
    allowed = {spec.name for spec in _OPTION_FIELDS}
    if set(options) - allowed:
        raise PresidioConfigurationError("invalid detector options")
    entities = options.get("entities", list(DEFAULT_ENTITIES))
    if type(entities) is not list or not entities or len(entities) > 64:
        raise PresidioConfigurationError("invalid entity list")
    if any(type(entity) is not str or not _TOKEN.fullmatch(entity) for entity in entities):
        raise PresidioConfigurationError("invalid entity list")
    if len(set(entities)) != len(entities):
        raise PresidioConfigurationError("invalid entity list")

    language = options.get("language", "en")
    if type(language) is not str or not _LANGUAGE.fullmatch(language):
        raise PresidioConfigurationError("invalid language")
    ner_mode = options.get("ner-mode", "pattern-only")
    if type(ner_mode) is not str or ner_mode not in _NER_MODES:
        raise PresidioConfigurationError("invalid NER mode")
    model_name = options.get("model-name", "en_core_web_sm")
    if type(model_name) is not str or not _MODEL_NAME.fullmatch(model_name):
        raise PresidioConfigurationError("invalid model name")
    block_entities = options.get("block-entities", [])
    if type(block_entities) is not list or len(block_entities) > 64:
        raise PresidioConfigurationError("invalid severity policy")
    if any(type(entity) is not str or not _TOKEN.fullmatch(entity) for entity in block_entities):
        raise PresidioConfigurationError("invalid severity policy")
    if len(set(block_entities)) != len(block_entities) or not set(block_entities) <= set(entities):
        raise PresidioConfigurationError("invalid severity policy")
    modules = options.get("recognizer-modules", [])
    if type(modules) is not list or len(modules) > 16:
        raise PresidioConfigurationError("invalid recognizer modules")
    if any(type(module) is not str or not _FACTORY.fullmatch(module) for module in modules):
        raise PresidioConfigurationError("invalid recognizer modules")
    if len(set(modules)) != len(modules):
        raise PresidioConfigurationError("invalid recognizer modules")
    recognizer_options = options.get("recognizer-options", "{}")
    if type(recognizer_options) is not str or len(recognizer_options) > 32768:
        raise PresidioConfigurationError("invalid recognizer options")
    custom_options = _json_object(recognizer_options)
    if set(custom_options) - set(modules):
        raise PresidioConfigurationError("invalid recognizer options")
    if any(type(value) is not dict for value in custom_options.values()):
        raise PresidioConfigurationError("invalid recognizer options")
    return {
        "entities": tuple(entities),
        "language": language,
        "score_threshold": _parse_threshold(options.get("score-threshold", "0.35")),
        "ner_mode": ner_mode,
        "model_name": model_name,
        "block_entities": frozenset(block_entities),
        "recognizer_modules": tuple(modules),
        "recognizer_options": custom_options,
    }


def _model_identity(model_name: str, ner_mode: str) -> str:
    if ner_mode == "pattern-only":
        return "no-op-nlp"
    distribution_name = model_name.replace("_", "-")
    try:
        model_version = metadata.version(distribution_name)
    except metadata.PackageNotFoundError:
        raise ModuleNotFoundError("configured Presidio NER model is unavailable") from None
    return f"{model_name}:{model_version}"


def _load_custom_recognizers(config: dict[str, Any], language: str, entities: tuple[str, ...]):
    from presidio_analyzer import EntityRecognizer

    recognizers = []
    for module_spec in config["recognizer_modules"]:
        match = _FACTORY.fullmatch(module_spec)
        if match is None:
            raise PresidioConfigurationError("invalid recognizer module")
        module = importlib.import_module(match.group(1))
        factory = getattr(module, match.group(2), None)
        if not callable(factory):
            raise PresidioConfigurationError("invalid recognizer module")
        module_options = dict(config["recognizer_options"].get(module_spec, {}))
        try:
            produced = factory(module_options)
            if isinstance(produced, EntityRecognizer):
                values = [produced]
            else:
                if isinstance(produced, (str, bytes, Mapping)):
                    raise TypeError
                values = list(islice(iter(produced), 101))
        except Exception:
            raise PresidioConfigurationError("custom recognizer factory failed") from None
        if len(values) > 100 or any(not isinstance(item, EntityRecognizer) for item in values):
            raise PresidioConfigurationError("custom recognizer factory returned an invalid recognizer")
        for recognizer in values:
            supported_languages = (getattr(recognizer, "supported_language", None),)
            supported_entities = getattr(recognizer, "supported_entities", ())
            if language not in supported_languages or not supported_entities or not set(supported_entities) <= set(entities):
                raise PresidioConfigurationError("custom recognizer capabilities do not match detector options")
            recognizers.append(recognizer)
    return recognizers


def _build_analyzer(config: dict[str, Any]):
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    language = config["language"]
    if config["ner_mode"] == "required":
        # Do not download or substitute a model at runtime. Analyzer construction
        # is the preflight: failure is reported as an unavailable dependency.
        if util.find_spec(config["model_name"]) is None:
            raise ModuleNotFoundError("configured Presidio NER model is unavailable")
        nlp_configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": language, "model_name": config["model_name"]}],
        }
    else:
        nlp_configuration = {
            "nlp_engine_name": "no_op",
            "models": [{"lang_code": language, "model_name": "no_op"}],
        }
    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_configuration).create_engine()
    if config["ner_mode"] == "required":
        loaded_model = getattr(nlp_engine, "nlp", {}).get(language)
        model_language = getattr(loaded_model, "lang", None)
        if model_language != language.split("-", 1)[0]:
            raise PresidioConfigurationError("configured Presidio model does not support language")
    registry = RecognizerRegistry(supported_languages=[language])
    registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=[language])
    custom = _load_custom_recognizers(config, language, config["entities"])
    for recognizer in custom:
        registry.add_recognizer(recognizer)
    if not set(config["entities"]) <= set(registry.get_supported_entities()):
        raise PresidioConfigurationError("configured entities are not supported by the selected recognizers")
    analyzer = AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
        supported_languages=[language],
        default_score_threshold=0.0,
    )
    return analyzer, len(custom)


class PresidioDetector:
    """One configured AnalyzerEngine reused across all session requests."""

    def __init__(self, options: Mapping[str, object]):
        self._config = _validate_options(options)
        try:
            installed_analyzer_version = metadata.version("presidio-analyzer")
        except metadata.PackageNotFoundError:
            raise ModuleNotFoundError("Presidio Analyzer dependency is unavailable") from None
        if installed_analyzer_version != ANALYZER_VERSION:
            raise ModuleNotFoundError("unsupported Presidio Analyzer version")
        self._model_id = _model_identity(self._config["model_name"], self._config["ner_mode"])
        self._analyzer, self._custom_recognizer_count = _build_analyzer(self._config)
        self._calls = 0
        self._closed = False
        identity_material = {
            "adapter": __version__,
            "analyzer": ANALYZER_VERSION,
            "model": self._model_id,
            "language": self._config["language"],
            "entities": sorted(self._config["entities"]),
            "score_threshold": str(self._config["score_threshold"]),
            "block_entities": sorted(self._config["block_entities"]),
            "recognizer_modules": list(self._config["recognizer_modules"]),
            "recognizer_options": self._config["recognizer_options"],
        }
        self._identity = hashlib.sha256(
            json.dumps(identity_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def detect(self, text: str, context) -> Iterable[NewFinding]:
        del context
        if self._closed or self._analyzer is None:
            raise RuntimeError("Presidio session is closed")
        self._calls += 1
        results = self._analyzer.analyze(
            text=text,
            entities=list(self._config["entities"]),
            language=self._config["language"],
            score_threshold=self._config["score_threshold"],
        )
        newline_positions = [index for index, char in enumerate(text) if char == "\n"]
        deduplicated = {}
        for result in results:
            entity_type = result.entity_type
            start = result.start
            end = result.end
            score = float(result.score)
            if (
                type(entity_type) is not str
                or not _TOKEN.fullmatch(entity_type)
                or type(start) is not int
                or type(end) is not int
                or not 0 <= start < end <= len(text)
                or not math.isfinite(score)
                or not 0 <= score <= 1
            ):
                continue
            key = (entity_type, start, end)
            previous = deduplicated.get(key)
            if previous is None or score > previous:
                deduplicated[key] = score
        for (entity_type, start, end), score in sorted(deduplicated.items(), key=lambda item: (item[0][1], item[0][2], item[0][0])):
            line = bisect_right(newline_positions, start) + 1
            severity = "block" if entity_type in self._config["block_entities"] else "review"
            yield NewFinding(
                rule=STATIC_RULE_ID,
                line=line,
                severity=severity,
                analysis=AnalysisMetadata(
                    schema_version=1,
                    start=start,
                    end=end,
                    entity_type=entity_type,
                    score=score,
                    recognizer_id="presidio",
                    analyzer_id=ANALYZER_ID,
                    analyzer_version=ANALYZER_VERSION,
                    model_id=self._model_id,
                ),
            )

    def capabilities(self) -> dict[str, object]:
        """Safe effective capabilities; no source text or recognizer patterns."""
        return {
            "analyzer": ANALYZER_ID,
            "analyzer_version": ANALYZER_VERSION,
            "language": self._config["language"],
            "entities": sorted(self._config["entities"]),
            "ner_enabled": self._config["ner_mode"] == "required",
            "model_id": self._model_id,
            "custom_recognizer_count": self._custom_recognizer_count,
        }

    def adapter_identity(self) -> dict[str, str]:
        return {"analyzer": ANALYZER_ID, "identity_sha256": self._identity}

    def close(self) -> None:
        self._closed = True
        self._analyzer = None


def create_plugin(options: Mapping[str, object]) -> PresidioDetector:
    return PresidioDetector(options)
