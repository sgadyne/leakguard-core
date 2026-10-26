"""Synthetic customer identifier and confidentiality-marker checks."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import re

from leakguard_core.plugins import (
    DetectionContext,
    Finding,
    OptionSchema,
    OptionSpec,
    PluginManifest,
    RuleSpec,
)


API_VERSION = 2
RULES = ("firm-customer-number", "firm-confidentiality-marker")
MANIFEST = PluginManifest(
    id="firm-example",
    implementation_version="0.1.0",
    kind="detector",
    rules=tuple(RuleSpec(rule, "review") for rule in RULES),
    formats=("text",),
    part_kinds=("text",),
    options_schema=OptionSchema(fields=(
        OptionSpec("customer-prefix", "string", default="ACME-CUST", max_length=24),
        OptionSpec("promote-rules", "list", default=[], max_length=len(RULES)),
    )),
    dependencies=(),
    deterministic=True,
    external_state="none",
)

_CUSTOMER_FIELD = re.compile(r"(?i)(?:^|[\s{,.])['\"]?customer[_-]?(?:id|number)['\"]?\s*[:=]\s*['\"]?([^\s,;'\"}\]]+)")
_MARKER = re.compile(r"(?i)\bCONFIDENTIAL\b")
_PREFIX = re.compile(r"^[A-Z][A-Z0-9-]{1,23}$")


class FirmDetector:
    def __init__(self, options: Mapping[str, object]):
        prefix = options.get("customer-prefix", "ACME-CUST")
        promoted = options.get("promote-rules", [])
        if (type(prefix) is not str or not _PREFIX.fullmatch(prefix.upper())
                or type(promoted) is not list or any(type(item) is not str for item in promoted)
                or not set(promoted) <= set(RULES)):
            raise ValueError("invalid options")
        self.customer_pattern = re.compile(re.escape(prefix) + r"[-_ ]?\d{4,12}", re.IGNORECASE)
        self.promoted = frozenset(promoted)

    def detect(self, text: str, context: DetectionContext) -> Iterable[Finding]:
        del context
        found: set[tuple[str, int]] = set()
        for number, line in enumerate(text.splitlines(), 1):
            for match in _CUSTOMER_FIELD.finditer(line):
                if self.customer_pattern.fullmatch(match.group(1)):
                    found.add(("firm-customer-number", number))
            if _MARKER.search(line):
                found.add(("firm-confidentiality-marker", number))
        for rule, number in sorted(found, key=lambda item: (item[1], item[0])):
            yield Finding(rule=rule, line=number,
                          severity="block" if rule in self.promoted else "review")


def create_plugin(options: Mapping[str, object]) -> FirmDetector:
    if type(options) is not dict or set(options) - {"customer-prefix", "promote-rules"}:
        raise ValueError("invalid options")
    return FirmDetector(options)
