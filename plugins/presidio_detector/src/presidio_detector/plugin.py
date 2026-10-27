"""LeakGuard adapter for Microsoft Presidio's AnalyzerEngine.

One plugin instance builds one AnalyzerEngine. The core session worker keeps that
instance for multiple parts so spaCy and recognizer state are reused.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from bisect import bisect_left
from decimal import Decimal, InvalidOperation
import hashlib
import importlib
from importlib import metadata, util
from itertools import islice
import json
import math
import os
from pathlib import Path
import re
import stat
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
PRESET_ENTITIES = {
    # The default profile already includes cards and IBANs. Add the weaker
    # domestic bank-number recognizer only when financial coverage is selected.
    "financial": ("US_BANK_NUMBER",),
    "identity": ("US_DRIVER_LICENSE", "US_ITIN", "US_PASSPORT"),
    "healthcare": ("MEDICAL_LICENSE", "UK_NHS"),
}
_CONTEXT_WINDOW_CHARS = 96
_CONTEXT_SCORE_BONUS = 0.35
_CONTEXT_MODES = ("local", "none")
_CONTEXT_ENHANCED_METADATA_KEY = "is_score_enhanced_by_context"
_TOKEN = re.compile(r"[A-Z][A-Z0-9_]{0,79}\Z")
_WORD = re.compile(r"[^\W_]+", re.UNICODE)
_LANGUAGE = re.compile(r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}\Z")
_MODEL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_MODEL_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FACTORY = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*):([A-Za-z_][A-Za-z0-9_]*)\Z")
_NER_MODES = ("required", "pattern-only")
_OPTION_FIELDS = (
    OptionSpec("entities", "list", default=list(DEFAULT_ENTITIES), max_length=64),
    OptionSpec("presets", "list", default=[], max_length=len(PRESET_ENTITIES)),
    OptionSpec("language", "string", default="en", max_length=16),
    OptionSpec("score-threshold", "string", default="0.35", max_length=16),
    OptionSpec("context-mode", "enum", default="local", choices=_CONTEXT_MODES),
    OptionSpec("ner-mode", "enum", default="pattern-only", choices=_NER_MODES),
    OptionSpec("model-name", "string", default="en_core_web_sm", max_length=64),
    OptionSpec("model-sha256", "string", default="", max_length=64),
    OptionSpec("block-entities", "list", default=[], max_length=64),
    OptionSpec("recognizer-modules", "list", default=[], max_length=16),
    OptionSpec("recognizer-options", "string", default="{}", max_length=32768),
)

MANIFEST = PluginManifest(
    id="presidio-detector",
    implementation_version=__version__,
    kind="detector",
    rules=(RuleSpec(id=STATIC_RULE_ID, minimum_severity="review"),),
    formats=("text", "pdf-text", "office-word", "office-sheet", "office-slides", "outlook-msg"),
    part_kinds=(),
    options_schema=OptionSchema(fields=_OPTION_FIELDS),
    dependencies=(
        DistributionSpec(name="presidio-analyzer"),
        DistributionSpec(name="tldextract"),
    ),
    deterministic=True,
    external_state="none",
    requires_core=(0, 0),
    worker_lifetime="session",
    result_schema=2,
)


class PresidioConfigurationError(ValueError):
    """Safe configuration error; messages never include the input being scanned."""


def _offline_email_recognizer(base_recognizer, suffix_extractor):
    from presidio_analyzer.predefined_recognizers.generic.email_recognizer import EmailRecognizer

    class OfflineEmailRecognizer(EmailRecognizer):
        def __init__(self):
            self._offline_suffix_extractor = suffix_extractor
            super().__init__(
                patterns=base_recognizer.patterns,
                context=base_recognizer.context,
                supported_language=base_recognizer.supported_language,
                supported_entity=base_recognizer.supported_entities[0],
                name=base_recognizer.name,
            )

        def validate_result(self, pattern_text: str):
            result = self._offline_suffix_extractor(pattern_text)
            return result.fqdn != ""

    return OfflineEmailRecognizer()


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
    presets = options.get("presets", [])
    if (type(presets) is not list or len(presets) > len(PRESET_ENTITIES)
            or any(type(preset) is not str or preset not in PRESET_ENTITIES for preset in presets)
            or len(set(presets)) != len(presets)):
        raise PresidioConfigurationError("invalid recognizer presets")
    selected_entities = list(entities)
    selected_entity_set = set(selected_entities)
    for preset in presets:
        for entity in PRESET_ENTITIES[preset]:
            if entity not in selected_entity_set:
                selected_entities.append(entity)
                selected_entity_set.add(entity)
    if len(selected_entities) > 64:
        raise PresidioConfigurationError("invalid entity list")

    language = options.get("language", "en")
    if type(language) is not str or not _LANGUAGE.fullmatch(language):
        raise PresidioConfigurationError("invalid language")
    ner_mode = options.get("ner-mode", "pattern-only")
    if type(ner_mode) is not str or ner_mode not in _NER_MODES:
        raise PresidioConfigurationError("invalid NER mode")
    context_mode = options.get("context-mode", "local")
    if type(context_mode) is not str or context_mode not in _CONTEXT_MODES:
        raise PresidioConfigurationError("invalid context mode")
    model_name = options.get("model-name", "en_core_web_sm")
    if type(model_name) is not str or len(model_name) > 64 or not _MODEL_NAME.fullmatch(model_name):
        raise PresidioConfigurationError("invalid model name")
    model_sha256 = options.get("model-sha256", "")
    if type(model_sha256) is not str or (ner_mode == "required" and not _MODEL_SHA256.fullmatch(model_sha256)):
        raise PresidioConfigurationError("required NER needs an expected model SHA-256")
    if ner_mode == "pattern-only" and model_sha256:
        raise PresidioConfigurationError("pattern-only mode does not accept a model identity")
    block_entities = options.get("block-entities", [])
    if type(block_entities) is not list or len(block_entities) > 64:
        raise PresidioConfigurationError("invalid severity policy")
    if any(type(entity) is not str or not _TOKEN.fullmatch(entity) for entity in block_entities):
        raise PresidioConfigurationError("invalid severity policy")
    if len(set(block_entities)) != len(block_entities) or not set(block_entities) <= set(selected_entities):
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
        "entities": tuple(selected_entities),
        "presets": tuple(presets),
        "language": language,
        "score_threshold": _parse_threshold(options.get("score-threshold", "0.35")),
        "context_mode": context_mode,
        "ner_mode": ner_mode,
        "model_name": model_name,
        "model_sha256": model_sha256,
        "block_entities": frozenset(block_entities),
        "recognizer_modules": tuple(modules),
        "recognizer_options": custom_options,
    }


def _hash_model_distribution(model_name: str) -> tuple[str, str]:
    """Hash a stable, bounded manifest of an installed model distribution."""
    maximum_bytes = 512 * 1024 * 1024
    chunk_bytes = 1024 * 1024
    try:
        distribution = metadata.distribution(model_name.replace("_", "-"))
        model_version = distribution.version
        entries = distribution.files
        if not entries:
            raise ValueError
        root = Path(distribution.locate_file("")).resolve(strict=True)
        members = []
        total_bytes = 0
        for entry in sorted(entries, key=lambda item: str(item)):
            relative = Path(str(entry))
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError
            if "__pycache__" in relative.parts or relative.suffix == ".pyc":
                continue
            target = root / relative
            parent = root
            for part in relative.parts[:-1]:
                parent = parent / part
                if stat.S_ISLNK(parent.lstat().st_mode):
                    raise ValueError
            before_path = target.lstat()
            if not stat.S_ISREG(before_path.st_mode):
                raise ValueError
            resolved = target.resolve(strict=True)
            if not resolved.is_relative_to(root):
                raise ValueError
            if total_bytes + before_path.st_size > maximum_bytes:
                raise ValueError
            descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                before_fd = os.fstat(descriptor)
                if (not stat.S_ISREG(before_fd.st_mode)
                        or (before_fd.st_dev, before_fd.st_ino, before_fd.st_size, before_fd.st_mtime_ns)
                        != (before_path.st_dev, before_path.st_ino, before_path.st_size, before_path.st_mtime_ns)):
                    raise ValueError
                digest = hashlib.sha256()
                read_bytes = 0
                while True:
                    chunk = os.read(descriptor, chunk_bytes)
                    if not chunk:
                        break
                    read_bytes += len(chunk)
                    if read_bytes > before_fd.st_size or total_bytes + read_bytes > maximum_bytes:
                        raise ValueError
                    digest.update(chunk)
                after_fd = os.fstat(descriptor)
                if ((before_fd.st_dev, before_fd.st_ino, before_fd.st_size, before_fd.st_mtime_ns)
                        != (after_fd.st_dev, after_fd.st_ino, after_fd.st_size, after_fd.st_mtime_ns)
                        or read_bytes != before_fd.st_size):
                    raise ValueError
            finally:
                os.close(descriptor)
            total_bytes += read_bytes
            members.append((relative.as_posix(), digest.digest()))
        if not members:
            raise ValueError
        manifest_digest = hashlib.sha256()
        for label, digest in members:
            manifest_digest.update(label.encode("utf-8"))
            manifest_digest.update(b"\0")
            manifest_digest.update(digest)
        return model_version, manifest_digest.hexdigest()
    except Exception:
        raise ModuleNotFoundError("configured Presidio NER model is unavailable") from None


def installed_model_sha256(model_name: str) -> str:
    """Return the model distribution identity for an operator-approved model."""
    if type(model_name) is not str or len(model_name) > 64 or not _MODEL_NAME.fullmatch(model_name):
        raise ValueError("invalid model name")
    return _hash_model_distribution(model_name)[1]


def _model_identity(model_name: str, ner_mode: str, expected_sha256: str) -> tuple[str, str | None, str | None]:
    if ner_mode == "pattern-only":
        return "no-op-nlp", None, None
    model_version, actual_sha256 = _hash_model_distribution(model_name)
    if actual_sha256 != expected_sha256:
        raise ModuleNotFoundError("configured Presidio NER model identity mismatch") from None
    return f"{model_name}:{model_version}:{actual_sha256}", model_version, actual_sha256


def _assigned_recognizer_id(namespace: str, module_name: str, recognizer) -> str:
    """Build a deterministic, value-free ID from registration metadata."""
    module_parts = [part for part in module_name.split(".") if part]
    module_token = ".".join(module_parts[-2:])
    class_name = type(recognizer).__name__
    entities = getattr(recognizer, "supported_entities", ())
    raw = ".".join((namespace, module_token, class_name, ",".join(sorted(entities))))
    token = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    identifier = f"presidio-{token}"
    if len(identifier) > 200:
        suffix = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        identifier = f"{identifier[:183]}-{suffix}"
    return identifier


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
            recognizers.append((recognizer, match.group(1)))
    return recognizers


def _build_analyzer(config: dict[str, Any]):
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_analyzer.predefined_recognizers.generic.email_recognizer import EmailRecognizer
    from tldextract import TLDExtract

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
    offline_suffix_extractor = TLDExtract(suffix_list_urls=(), cache_dir=None, fallback_to_snapshot=True)
    for recognizer in tuple(registry.recognizers):
        if isinstance(recognizer, EmailRecognizer) and recognizer.supported_language == language:
            registry.remove_recognizer(recognizer.name, language)
            registry.add_recognizer(_offline_email_recognizer(recognizer, offline_suffix_extractor))
    custom = _load_custom_recognizers(config, language, config["entities"])
    assigned_ids = {}
    custom_origins = {}
    for recognizer, module_name in custom:
        registry.add_recognizer(recognizer)
        custom_origins[getattr(recognizer, "id", None)] = module_name
    if not set(config["entities"]) <= set(registry.get_supported_entities()):
        raise PresidioConfigurationError("configured entities are not supported by the selected recognizers")
    # Keep only recognizers that can contribute to this explicit profile. The
    # AnalyzerEngine still receives the same entity allowlist at call time.
    selected_entities = set(config["entities"])
    # Filter instances directly: Presidio's remove_recognizer removes every
    # recognizer with a matching name/language, which can also remove a firm
    # recognizer when it shares a name with an unselected built-in.
    registry.recognizers = [
        recognizer
        for recognizer in registry.recognizers
        if selected_entities.intersection(getattr(recognizer, "supported_entities", ()))
    ]
    if not selected_entities <= set(registry.get_supported_entities(languages=[language])):
        raise PresidioConfigurationError("configured entities are not supported by the selected recognizers")
    for recognizer in registry.get_recognizers(language=language, entities=list(config["entities"])):
        identifier = getattr(recognizer, "id", None)
        module_name = custom_origins.get(identifier)
        namespace = "firm" if module_name is not None else "builtin"
        source_module = module_name or type(recognizer).__module__
        assigned_ids[identifier] = _assigned_recognizer_id(namespace, source_module, recognizer)
    analyzer = AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
        supported_languages=[language],
        default_score_threshold=0.0,
    )
    context_terms = {}
    for recognizer in registry.get_recognizers(language=language, entities=list(config["entities"])):
        instance_id = getattr(recognizer, "id", None)
        terms = getattr(recognizer, "context", ())
        if type(terms) in (list, tuple, set, frozenset):
            normalized = tuple(
                tokens
                for term in terms
                if type(term) is str and len(term) <= 80
                for tokens in (tuple(word.casefold() for word in _WORD.findall(term)),)
                if tokens
            )
            if normalized:
                context_terms[instance_id] = normalized
    return analyzer, len(custom), assigned_ids, context_terms


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
        self._model_id, expected_model_version, expected_model_sha256 = _model_identity(
            self._config["model_name"], self._config["ner_mode"], self._config["model_sha256"]
        )
        (self._analyzer, self._custom_recognizer_count, self._recognizer_ids,
         self._recognizer_context_terms) = _build_analyzer(self._config)
        if expected_model_sha256 is not None:
            actual_model_version, actual_model_sha256 = _hash_model_distribution(self._config["model_name"])
            if (actual_model_version, actual_model_sha256) != (expected_model_version, expected_model_sha256):
                self._analyzer = None
                raise ModuleNotFoundError("configured Presidio NER model identity changed during load") from None
        self._calls = 0
        self._closed = False
        identity_material = {
            "adapter": __version__,
            "analyzer": ANALYZER_VERSION,
            "model": self._model_id,
            "expected_model_sha256": self._config["model_sha256"],
            "language": self._config["language"],
            "entities": sorted(self._config["entities"]),
            "presets": sorted(self._config["presets"]),
            "score_threshold": str(self._config["score_threshold"]),
            "context_mode": self._config["context_mode"],
            "block_entities": sorted(self._config["block_entities"]),
            "recognizer_modules": list(self._config["recognizer_modules"]),
            "recognizer_options": self._config["recognizer_options"],
        }
        self._identity = hashlib.sha256(
            json.dumps(identity_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def detect(self, text: str, context) -> Iterable[NewFinding]:
        if self._closed or self._analyzer is None:
            raise RuntimeError("Presidio session is closed")
        self._calls += 1
        results = self._analyzer.analyze(
            text=text,
            entities=list(self._config["entities"]),
            language=self._config["language"],
            # Retain Presidio's internal explanation long enough to recognize
            # its own context enhancement before applying the local fallback.
            return_decision_process=True,
            # Keep raw candidates long enough to apply only local, per-span
            # context evidence before enforcing the configured score threshold.
            score_threshold=0.0,
        )
        # Core findings count LF characters only when validating line bounds.
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
            metadata = getattr(result, "recognition_metadata", None)
            instance_id = metadata.get("recognizer_identifier") if type(metadata) is dict else None
            recognizer_id = self._recognizer_ids.get(instance_id, "presidio-unattributed")
            # Presidio 2.2.365 marks recognizer-level boosts in metadata and
            # its analyzer enhancer records the supportive word in the
            # explanation. Do not add this adapter's local fallback twice.
            already_context_enhanced = (
                type(metadata) is dict
                and metadata.get(_CONTEXT_ENHANCED_METADATA_KEY) is True
            )
            explanation = getattr(result, "analysis_explanation", None)
            already_context_enhanced = already_context_enhanced or bool(
                getattr(explanation, "supportive_context_word", "")
            )
            if (self._config["context_mode"] == "local" and not already_context_enhanced
                    and self._has_local_context(text, start, end,
                                                self._recognizer_context_terms.get(instance_id, ()))):
                score = min(1.0, score + _CONTEXT_SCORE_BONUS)
            if score < self._config["score_threshold"]:
                continue
            if previous is None or score > previous[0] or score == previous[0] and recognizer_id < previous[1]:
                deduplicated[key] = (score, recognizer_id)
        for (entity_type, start, end), score in sorted(deduplicated.items(), key=lambda item: (item[0][1], item[0][2], item[0][0])):
            score, recognizer_id = score
            line = bisect_left(newline_positions, start) + 1
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
                    recognizer_id=recognizer_id,
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
            "presets": sorted(self._config["presets"]),
            "ner_enabled": self._config["ner_mode"] == "required",
            "context_mode": self._config["context_mode"],
            "model_id": self._model_id,
            "custom_recognizer_count": self._custom_recognizer_count,
        }

    def adapter_identity(self) -> dict[str, str]:
        return {"analyzer": ANALYZER_ID, "identity_sha256": self._identity}

    def close(self) -> None:
        self._closed = True
        self._analyzer = None

    @staticmethod
    def _has_local_context(text: str, start: int, end: int, terms) -> bool:
        """Match recognizer context terms in a bounded window on this line only."""
        if not terms:
            return False
        left_limit = max(0, start - _CONTEXT_WINDOW_CHARS)
        left_break = max(text.rfind("\n", left_limit, start),
                         text.rfind("\r", left_limit, start))
        left_start = left_break + 1 if left_break >= 0 else left_limit
        right_limit = min(len(text), end + _CONTEXT_WINDOW_CHARS)
        right_breaks = [position for position in (
            text.find("\n", end, right_limit), text.find("\r", end, right_limit)
        ) if position >= 0]
        right_end = min(right_breaks) if right_breaks else right_limit
        left_tokens = [word.casefold() for word in _WORD.findall(text[left_start:start])]
        if (left_start == left_limit and left_start > 0
                and _WORD.fullmatch(text[left_start - 1])
                and _WORD.fullmatch(text[left_start])):
            # The bounded slice begins inside a token; discard its fragment.
            left_tokens = left_tokens[1:]
        right_tokens = [word.casefold() for word in _WORD.findall(text[end:right_end])]
        if (right_end == right_limit and right_end < len(text)
                and _WORD.fullmatch(text[right_end])
                and _WORD.fullmatch(text[right_end - 1])):
            # The bounded slice ends inside a token; discard its fragment.
            right_tokens = right_tokens[:-1]
        for term_tokens in terms:
            width = len(term_tokens)
            if width:
                for local_tokens in (left_tokens, right_tokens):
                    if any(tuple(local_tokens[index:index + width]) == term_tokens
                           for index in range(len(local_tokens) - width + 1)):
                        return True
        return False


def create_plugin(options: Mapping[str, object]) -> PresidioDetector:
    return PresidioDetector(options)
