"""Contextual PII and identifier checks with value-free findings.

Only explicit field labels or a recognized CSV header establish context. This is
an intentionally modest offline rule pack, not a general personal-data parser.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import csv
import io
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

RULE_CATEGORIES = {
    "pii-contact-email": "contact",
    "pii-contact-phone": "contact",
    "pii-contact-address": "contact",
    "pii-financial-card": "financial-identifier",
    "pii-financial-routing": "financial-identifier",
    "pii-financial-iban": "financial-identifier",
    "pii-identifier-employee": "organization-identifier",
    "pii-identifier-customer": "organization-identifier",
    "pii-identifier-account": "organization-identifier",
}

_OPTION_FIELDS = (
    OptionSpec("promote-rules", "list", default=[], max_length=len(RULE_CATEGORIES)),
    OptionSpec("employee-prefix", "string", default="EMP", max_length=16),
    OptionSpec("customer-prefix", "string", default="CUS", max_length=16),
    OptionSpec("account-prefix", "string", default="ACC", max_length=16),
)
MANIFEST = PluginManifest(
    id="sensitive-basics",
    implementation_version="0.1.0",
    kind="detector",
    rules=tuple(RuleSpec(rule, "review") for rule in RULE_CATEGORIES),
    formats=("text",),
    part_kinds=("text",),
    options_schema=OptionSchema(fields=_OPTION_FIELDS),
    dependencies=(),
    deterministic=True,
    external_state="none",
)

_EMAIL = re.compile(r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
_PHONE_CHARS = re.compile(r"^[+()0-9. /-]{7,32}$")
_ADDRESS = re.compile(
    r"(?i)\b\d{1,6}\s+[a-z0-9.'#-]+(?:\s+[a-z0-9.'#-]+){0,5}\s+"
    r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|"
    r"court|ct|way|parkway|pkwy|terrace|ter)\b"
)
_CARD_CHARS = re.compile(r"^[0-9 -]{13,28}$")
_ROUTING = re.compile(r"^\d{9}$")
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
_PREFIX = re.compile(r"^[A-Z][A-Z0-9]{1,15}$")
_FIELD = re.compile(
    r"(?i)(?:[\"']?(?P<key>[a-z][a-z0-9_-]*)[\"']?)\s*[:=]\s*"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^,;\r\n]+)"
)

_FIELD_RULES = {
    "email": ("email", "emailaddress", "contactemail", "customeremail", "employeeemail", "workemail"),
    "phone": ("phone", "phonenumber", "telephone", "mobile", "mobilenumber", "cellphone", "contactphone", "homephone", "workphone"),
    "address": ("address", "streetaddress", "homeaddress", "billingaddress", "shippingaddress", "postaladdress"),
    "card": ("cardnumber", "creditcard", "creditcardnumber", "paymentcard", "pan"),
    "routing": ("routing", "routingnumber", "abarouting", "abaroutingnumber"),
    "iban": ("iban", "internationalbankaccountnumber"),
    "employee": ("employeeid", "employeenumber", "staffid", "workerid"),
    "customer": ("customerid", "customernumber", "clientid", "clientnumber"),
    "account": ("accountid", "accountnumber", "customeraccount"),
}

_CSV_FIELDS = {
    "email": {"email", "emailaddress", "contactemail", "customeremail", "employeeemail"},
    "phone": {"phone", "phonenumber", "telephone", "mobile", "mobilenumber", "cellphone"},
    "address": {"address", "streetaddress", "homeaddress", "billingaddress", "shippingaddress", "postaladdress"},
    "card": {"cardnumber", "creditcardnumber", "paymentcard", "pan"},
    "routing": {"routingnumber", "abarouting", "abaroutingnumber"},
    "iban": {"iban", "internationalbankaccountnumber"},
    "employee": {"employeeid", "employeenumber", "staffid", "workerid"},
    "customer": {"customerid", "customernumber", "clientid", "clientnumber"},
    "account": {"accountid", "accountnumber", "customeraccount"},
}


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _value(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        raw = raw[1:-1]
    return raw.strip()


def _luhn(candidate: str) -> bool:
    digits = [int(char) for char in candidate if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _valid_routing(candidate: str) -> bool:
    if not re.fullmatch(r"\d(?:[ -]?\d){8}", candidate.strip()):
        return False
    digits = re.sub(r"[ -]", "", candidate)
    return bool(_ROUTING.fullmatch(digits)) and sum(
        weight * int(digit)
        for weight, digit in zip((3, 7, 1) * 3, digits)
    ) % 10 == 0


def _valid_iban(candidate: str) -> bool:
    compact = re.sub(r"\s+", "", candidate).upper()
    if not _IBAN.fullmatch(compact):
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for char in rearranged:
        piece = str(ord(char) - 55) if char.isalpha() else char
        for digit in piece:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


class SensitiveBasicsDetector:
    def __init__(self, options: Mapping[str, object]):
        promoted = options.get("promote-rules", [])
        if (type(promoted) is not list or any(type(item) is not str for item in promoted)
                or not set(promoted) <= set(RULE_CATEGORIES)):
            raise ValueError("invalid options")
        self.promoted = frozenset(promoted)
        self.prefixes = {}
        for kind in ("employee", "customer", "account"):
            value = options.get(kind + "-prefix", {"employee": "EMP", "customer": "CUS", "account": "ACC"}[kind])
            if type(value) is not str or not _PREFIX.fullmatch(value.upper()):
                raise ValueError("invalid options")
            self.prefixes[kind] = value.upper()

    def detect(self, text: str, context: DetectionContext) -> Iterable[Finding]:
        del context
        observed: set[tuple[str, int]] = set()
        header: list[str] | None = None
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                header = None
                continue
            fields = [(_normalize(match.group("key")), _value(match.group("value")))
                      for match in _FIELD.finditer(line)]
            recognized = False
            if "," in line:
                try:
                    row = next(csv.reader(io.StringIO(line), strict=True))
                except (csv.Error, StopIteration):
                    row = []
                normalized = [_normalize(item) for item in row]
                has_context = any(item in names for item in normalized for names in _CSV_FIELDS.values())
                if has_context:
                    header = normalized
                    recognized = True
                elif header is not None and len(row) == len(header):
                    recognized = True
                    for index, key in enumerate(header):
                        kind = next((name for name, names in _CSV_FIELDS.items() if key in names), None)
                        if kind is not None:
                            fields.append((kind, row[index].strip()))
            if not recognized and line.strip() and "," in line and header is not None:
                # A malformed or different-width CSV row must not inherit stale context.
                header = None
            for key, value in fields:
                for kind, names in _FIELD_RULES.items():
                    if key not in names and key != kind:
                        continue
                    rule = self._classify(kind, value)
                    if rule is not None:
                        observed.add((rule, line_number))
        for rule, line_number in sorted(observed, key=lambda item: (item[1], item[0])):
            severity = "block" if rule in self.promoted else "review"
            yield Finding(rule=rule, line=line_number, severity=severity)

    def _classify(self, kind: str, value: str) -> str | None:
        if kind == "email" and _EMAIL.fullmatch(value):
            return "pii-contact-email"
        if kind == "phone" and _PHONE_CHARS.fullmatch(value):
            digits = re.sub(r"\D", "", value)
            if 10 <= len(digits) <= 15:
                return "pii-contact-phone"
        if kind == "address" and _ADDRESS.search(value):
            return "pii-contact-address"
        if kind == "card" and _CARD_CHARS.fullmatch(value) and _luhn(value):
            return "pii-financial-card"
        if kind == "routing" and _valid_routing(value):
            return "pii-financial-routing"
        if kind == "iban" and _valid_iban(value):
            return "pii-financial-iban"
        if kind in self.prefixes:
            prefix = re.escape(self.prefixes[kind])
            if re.fullmatch(prefix + r"[-_ ]?[A-Z0-9]{4,16}", value, re.IGNORECASE):
                return "pii-identifier-" + kind
        return None


def create_plugin(options: Mapping[str, object]) -> SensitiveBasicsDetector:
    if type(options) is not dict:
        raise ValueError("invalid options")
    allowed = {field.name for field in _OPTION_FIELDS}
    if set(options) - allowed:
        raise ValueError("invalid options")
    return SensitiveBasicsDetector(options)
