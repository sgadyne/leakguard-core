"""Version 2 corpus with source-derived, genuinely held-out render recipes.

Generators use the JOSE serialization/algorithm specifications and PyCA only.
No detector patterns or findings are imported here. V1 remains in corpus.py and
split_manifest.json as a preserved, explicitly superseded experiment.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import re
import string
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from .corpus import _P256_ORDER, _b64url, _concat_kdf, _derive, _ec_private, _unb64url

CORPUS_VERSION = "jose-synthetic-v2-true-template-2026-10"
DEFAULT_SEED = 20261026
JWE_COUNT = 2_000
JWS_COUNT = 1_000
CLEAN_NEGATIVE_COUNT = 10_000
ADVERSARIAL_COUNT = 120


@dataclass(frozen=True)
class CorpusCase:
    case_id: str
    split: str
    template_family: str
    seed_group: str
    category: str
    mode: str
    text: str
    expected_spans: tuple[tuple[int, int], ...]
    format_outcome: str
    actionability: str
    expected_other_spans: tuple[tuple[int, int, str], ...] = ()
    algorithm: str | None = None
    expected_entity: str | None = "JOSE_COMPACT_JWE"
    adversarial_reason: str | None = None
    development_partition: str | None = None
    logical_path: str = "fixtures/v2/input.txt"
    part_id: str = "text"
    format_id: str = "text"
    negative_kind: str | None = None
    normalized_template: str = ""
    template_fingerprint: str = ""

    def label_dict(self) -> dict[str, Any]:
        exposure = {"exposed": True, "public": False, "unknown": None}[self.actionability]
        spans = [{"start": start, "end": end,
                  "entity_type": self.expected_entity or "JOSE_COMPACT_JWE",
                  "format_positive": self.format_outcome == "positive",
                  "actionable_exposure": exposure}
                 for start, end in self.expected_spans]
        other_spans = [{"start": start, "end": end, "entity_type": entity,
                        "format_positive": True, "actionable_exposure": None}
                       for start, end, entity in self.expected_other_spans]
        return {
            "id": self.case_id,
            "split": self.split,
            "template_family": self.template_family,
            "seed_id": self.seed_group,
            "format_id": self.format_id,
            "slice": [self.mode, self.category, self.algorithm or "unspecified", self.actionability],
            "spans": spans,
            "other_spans": other_spans,
            "negative_kind": self.negative_kind,
            "format_outcome": self.format_outcome,
            "actionability": self.actionability,
            "mode": self.mode,
            "category": self.category,
            "algorithm": self.algorithm,
            "expected_entity": self.expected_entity,
            "expected_spans": [list(span) for span in self.expected_spans],
            "expected_other_spans": [list(span) for span in self.expected_other_spans],
            "development_partition": self.development_partition,
            "logical_path": self.logical_path,
            "part_id": self.part_id,
            "template_fingerprint": self.template_fingerprint,
            "normalized_template": self.normalized_template,
            "adversarial_reason": self.adversarial_reason,
        }


def _case_fingerprint(normalized_template: str) -> str:
    return hashlib.sha256(normalized_template.encode("utf-8")).hexdigest()


class _Pairs(list):
    """JSON object-pair marker used to preserve protected-header member order."""


def _header_shape(raw_header: str) -> str:
    pairs = json.loads(raw_header, object_pairs_hook=_Pairs)

    def normalize(value, key=None):
        if isinstance(value, _Pairs):
            return "{" + ",".join(json.dumps(name, separators=(",", ":")) + ":" + normalize(item, name)
                                 for name, item in value) + "}"
        if isinstance(value, list):
            return "[" + ",".join(normalize(item) for item in value) + "]"
        if key == "kid":
            return "<KID>"
        if key in {"x", "y"}:
            return "<COORDINATE>"
        if key in {"alg", "enc", "typ", "kty", "crv"}:
            return json.dumps(value, separators=(",", ":"))
        if isinstance(value, str):
            return "<STRING>"
        if value is None:
            return "null"
        return type(value).__name__

    return normalize(pairs)


def _seed_root(seed: int) -> bytes:
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    return hashlib.sha256(f"{CORPUS_VERSION}:{seed}:generator-v2".encode("ascii")).digest()


def _make_jwe(seed: bytes, *, algorithm: str, heldout_recipe: bool) -> tuple[str, str]:
    """Create a disposable-key compact JWE with split-specific header grammar."""
    if algorithm not in {"A256KW", "dir", "ECDH-ES"}:
        raise ValueError("unsupported fixture algorithm")
    kid = "fixture-v2-" + hashlib.sha256(seed + b"kid-v2").hexdigest()[:14]
    epk = None
    if algorithm == "A256KW":
        cek = _derive(seed, "jwe-v2/cek", 32)
        encrypted_key = aes_key_wrap(_derive(seed, "jwe-v2/kek", 32), cek)
    elif algorithm == "dir":
        cek = _derive(seed, "jwe-v2/direct-content-encryption-key", 32)
        encrypted_key = b""
    else:
        recipient = _ec_private(seed, "jwe-v2/recipient-p256")
        ephemeral = _ec_private(seed, "jwe-v2/ephemeral-p256")
        numbers = ephemeral.public_key().public_numbers()
        epk = {"kty": "EC", "crv": "P-256",
               "x": _b64url(numbers.x.to_bytes(32, "big")),
               "y": _b64url(numbers.y.to_bytes(32, "big"))}
        cek = _concat_kdf(ephemeral.exchange(ec.ECDH(), recipient.public_key()), "A256GCM", 256)
        encrypted_key = b""

    if heldout_recipe:
        pairs = [("enc", "A256GCM"), ("alg", algorithm), ("epk", epk),
                 ("kid", kid), ("typ", "JWE")]
        pairs = [(key, value) for key, value in pairs if value is not None]
        raw_header = json.dumps(dict(pairs), separators=(",", ":"), ensure_ascii=False)
    else:
        pairs = [("kid", kid), ("typ", "JWE"), ("alg", algorithm), ("enc", "A256GCM"),
                 ("epk", epk)]
        pairs = [(key, value) for key, value in pairs if value is not None]
        raw_header = json.dumps(dict(pairs), indent=1, ensure_ascii=False)
    protected = _b64url(raw_header.encode("utf-8"))
    iv = _derive(seed, "jwe-v2/content-encryption-iv", 12)
    plaintext = json.dumps({"sub": "fixture-v2-" + hashlib.sha256(seed + b"sub").hexdigest()[:18],
                            "scope": "synthetic-evaluation"}, separators=(",", ":")).encode("utf-8")
    sealed = AESGCM(cek).encrypt(iv, plaintext, protected.encode("ascii"))
    token = ".".join((protected, _b64url(encrypted_key), _b64url(iv),
                      _b64url(sealed[:-16]), _b64url(sealed[-16:])))
    return token, raw_header


def _make_jws(seed: bytes, *, heldout_recipe: bool) -> tuple[str, str]:
    kid = "fixture-v2-jws-" + hashlib.sha256(seed + b"jws-kid-v2").hexdigest()[:12]
    if heldout_recipe:
        raw_header = json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid},
                                separators=(",", ":"))
    else:
        raw_header = json.dumps({"kid": kid, "typ": "JWT", "alg": "HS256"}, indent=1)
    protected = _b64url(raw_header.encode("ascii"))
    payload = _b64url(json.dumps({"sub": "fixture-v2-user", "scope": "read", "iat": 1_798_123_456},
                                 separators=(",", ":")).encode("ascii"))
    signing_input = f"{protected}.{payload}"
    signature = hmac.new(_derive(seed, "jws-v2/signing-key", 32),
                         signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + _b64url(signature), raw_header


_POSITIVE_STANDALONE = (
    ("standalone-angle", "<<?TOKEN?>>"),
    ("standalone-square", "[[TOKEN]]"),
    ("standalone-round", "(TOKEN);"),
    ("standalone-guillemets", "«TOKEN»"),
    ("standalone-at-mark", "@@TOKEN@@"),
    ("standalone-slashes", "/TOKEN/"),
    ("standalone-pipe", "|TOKEN|"),
    ("standalone-em-dash", "—TOKEN—"),
)

_POSITIVE_EMBEDDED = (
    ("xml-attribute", "<vault-state credential='TOKEN' />", "exposed"),
    ("toml-session", "session.challenge = \"TOKEN\"", "exposed"),
    ("go-raw-string", "identity := `TOKEN`", "exposed"),
    ("csharp-verbatim", "var identity = @\"TOKEN\";", "exposed"),
    ("python-triple-string", 'session_value = """TOKEN"""', "exposed"),
    ("sql-session-update", "UPDATE runtime_sessions SET opaque_value = 'TOKEN' WHERE slot = 3;", "exposed"),
    ("http-cookie", "Cookie: sid=TOKEN; Path=/; SameSite=Strict\r\n", "exposed"),
    ("http-session-header", "X-Session-Key: TOKEN\r\n", "exposed"),
    ("url-session-path", "https://api.fixture.test/session/TOKEN/refresh", "exposed"),
    ("html-hidden-input", "<input type=hidden name=session_key value=\"TOKEN\">", "exposed"),
    ("markdown-angle-link", "[refresh session](<urn:session:TOKEN>)", "exposed"),
    ("hcl-local", "locals { refresh_ticket = \"TOKEN\" }", "exposed"),
    ("docker-secret-env", "ENV RUNTIME_SECRET \"TOKEN\"", "exposed"),
    ("yaml-block-scalar", "session_ticket: >\n  TOKEN\n", "exposed"),
    ("nginx-header", "proxy_set_header X-Session \"TOKEN\";", "exposed"),
    ("javascript-object", "const runtime = { sessionToken: \"TOKEN\" };", "exposed"),
    ("rust-string", "let session_token = String::from(\"TOKEN\");", "exposed"),
    ("php-variable", "$session = 'TOKEN';", "exposed"),
    ("ruby-q-string", "%q(TOKEN)", "exposed"),
    ("postgres-setting", "SET app.session_token TO 'TOKEN';", "exposed"),
    ("terraform-value", "variable \"session_blob\" { default = \"TOKEN\" }", "exposed"),
    ("xml-element", "<Credential><Value>TOKEN</Value></Credential>", "exposed"),
    ("command-line-option", "runtime-tool --session-ticket TOKEN --refresh", "exposed"),
    ("jvm-property", "-Druntime.session.value=TOKEN", "exposed"),
    ("powershell-scope", "$script:SessionKey = 'TOKEN'", "exposed"),
    ("systemd-property", "Environment=SESSION_CREDENTIAL=TOKEN\n", "exposed"),
    ("lisp-form", "(auth-ticket \"TOKEN\")", "exposed"),
    ("protobuf-text", "session { credential_value: \"TOKEN\" }", "exposed"),
    ("html-data-attribute", "<div data-session-value=\"TOKEN\"></div>", "exposed"),
    ("markdown-fence-example", "~~~jose\nTOKEN\n~~~", "public"),
    ("docbook-example", "<programlisting>JWE compact example: TOKEN</programlisting>", "public"),
    ("c-header-example", "/* serialization example */\n#define SESSION_SAMPLE \"TOKEN\"", "public"),
)

_JWS_STANDALONE = (
    ("jws-angle", "<<TOKEN>>"), ("jws-function", "jws(TOKEN)"),
    ("jws-slashes", "/TOKEN/"), ("jws-square", "[{TOKEN}]"),
    ("jws-at-mark", "@@TOKEN@@"),
)
_JWS_EMBEDDED = (
    ("html-jws-attribute", "<identity ticket=\"TOKEN\" />"),
    ("cookie-jws", "Cookie: auth_ticket=TOKEN; HttpOnly\r\n"),
    ("go-jws-variable", "var signedTicket = \"TOKEN\""),
    ("sql-jws-value", "INSERT INTO auth_log (signed_value) VALUES ('TOKEN');"),
    ("xml-jws-value", "<signed-value>TOKEN</signed-value>"),
    ("toml-jws-value", "auth.signed_ticket = \"TOKEN\""),
    ("powershell-jws", "$signedTicket = 'TOKEN'"),
    ("rust-jws", "let signed_ticket = \"TOKEN\";"),
    ("php-jws", "$signed_ticket = 'TOKEN';"),
    ("nginx-jws", "proxy_set_header X-Signed-Ticket TOKEN;"),
    ("yaml-jws-block", "signed_ticket: >\n  TOKEN\n"),
    ("markdown-jws-fence", "~~~signed-value\nTOKEN\n~~~"),
    ("hcl-jws-field", "locals { signed_ticket = \"TOKEN\" }"),
    ("protobuf-jws", "auth { signed_value: \"TOKEN\" }"),
    ("query-jws", "https://fixture.test/session?assertion=TOKEN&mode=read"),
)


def _partition(split: str, ordinal: int) -> str | None:
    if split == "holdout":
        return None
    return "validation" if ordinal % 4 == 0 else "train"


def _seed_for(root: bytes, group: str) -> bytes:
    return _derive(root, "v2-token-seed/" + group, 32)


def _negative_value(category: str, rng: random.Random, index: int) -> str:
    if category == "digest-lookalike":
        return hashlib.sha384(bytes(rng.randrange(256) for _ in range(48))).hexdigest()
    if category == "opaque-blob":
        return _b64url(bytes(rng.randrange(256) for _ in range(70 + index % 29)))
    if category == "public-key-id":
        return "ssh-ed25519 " + _b64url(bytes(rng.randrange(256) for _ in range(52))) + " eval@fixture"
    if category == "placeholder-ref":
        return rng.choice(("${SESSION_REF}", "vault-ref:demo/runtime/ticket", "<SAMPLE-VALUE>", "CHANGE_THIS"))
    if category == "numeric-identifier":
        return "".join(str(rng.randrange(10)) for _ in range(10 + index % 5))
    if category == "network-label":
        return f"2001:db8:{rng.randrange(0xffff):x}::{rng.randrange(1, 0xffff):x}"
    if category == "release-version":
        return f"v{rng.randrange(1, 9)}.{rng.randrange(100)}.{rng.randrange(1000)}"
    if category == "calendar-label":
        return f"2026-W{rng.randrange(1, 53):02d}-{rng.randrange(1, 8)}"
    if category == "resource-urn":
        return f"urn:fixture:resource:{rng.randrange(1_000_000, 9_999_999)}"
    if category == "build-serial":
        return f"build-{rng.randrange(1_000_000, 9_999_999)}-candidate"
    raise ValueError("unknown v2 negative category")


def _standalone_negative_value(category: str, rng: random.Random, index: int) -> str:
    """Return a type-shaped value for an unwrapped clean-negative recipe."""
    if category == "public-key-id":
        return _b64url(bytes(rng.randrange(256) for _ in range(52)))
    if category == "placeholder-ref":
        return f"runtime/item-{rng.randrange(1_000, 9_999)}"
    if category == "network-label":
        return f"{rng.randrange(0xffff):x}:{rng.randrange(1, 0xffff):x}"
    if category == "release-version":
        return f"{rng.randrange(1, 9)}.{rng.randrange(100)}.{rng.randrange(1000)}"
    if category == "calendar-label":
        return f"2026-W{rng.randrange(1, 53):02d}-{rng.randrange(1, 8)}"
    if category == "resource-urn":
        return str(rng.randrange(1_000_000, 9_999_999))
    if category == "build-serial":
        return f"{rng.randrange(1_000_000, 9_999_999)}-candidate"
    return _negative_value(category, rng, index)


_NEGATIVE_TEMPLATES = {
    "digest-lookalike": (
        ("sha384:VALUE", "standalone"),
        ('artifact_digest = "VALUE" # registry-checksum', "embedded"),
        ('<manifest digest="VALUE" scheme="SHA-384"/>', "embedded"),
        ("SELECT checksum FROM registry WHERE value = 'VALUE';", "embedded"),
        ("build-artifact --digest 'VALUE' --verify", "embedded"),
    ),
    "opaque-blob": (
        ("blob64/VALUE", "standalone"),
        ('archive.payload = "VALUE" # public-fixture', "embedded"),
        ('<attachment encoding="base64url">VALUE</attachment>', "embedded"),
        ("cache record payload := 'VALUE'", "embedded"),
        ("fixture-loader --opaque-data=VALUE", "embedded"),
    ),
    "public-key-id": (
        ("ssh-ed25519 VALUE eval@fixture", "standalone"),
        ('known_hosts_key = "VALUE" # synthetic-public', "embedded"),
        ('<public-key format="ssh">VALUE</public-key>', "embedded"),
        ("ssh-add --public-only 'VALUE'", "embedded"),
        ("authorized_key: VALUE  # fixture", "embedded"),
    ),
    "placeholder-ref": (
        ("vault-ref:demo/VALUE", "standalone"),
        ('secret_source = "VALUE" # pointer-only', "embedded"),
        ('<reference kind="placeholder">VALUE</reference>', "embedded"),
        ("credential_ref := 'VALUE' // no credential material", "embedded"),
        ("runtime-tool --credential-reference VALUE", "embedded"),
    ),
    "numeric-identifier": (
        ("counter#VALUE", "standalone"),
        ('batch_sequence = "VALUE" # counter', "embedded"),
        ('<shipment sequence="VALUE"/>', "embedded"),
        ("SELECT * FROM batches WHERE sequence_id = 'VALUE';", "embedded"),
        ("queue --shard-number VALUE --dry-run", "embedded"),
    ),
    "network-label": (
        ("2001:db8::VALUE", "standalone"),
        ('link_local_address = "VALUE" # documentation-prefix', "embedded"),
        ('<endpoint address="VALUE" scope="TEST-NET"/>', "embedded"),
        ("ip route show table fixture | grep 'VALUE'", "embedded"),
        ("[service.network]\naddress = 'VALUE'", "embedded"),
    ),
    "release-version": (
        ("pkg-VALUE", "standalone"),
        ('package_release = "VALUE" # non-secret metadata', "embedded"),
        ('<artifact version="VALUE" status="published"/>', "embedded"),
        ("SELECT version FROM releases WHERE tag = 'VALUE';", "embedded"),
        ("package-manager show runtime --version VALUE", "embedded"),
    ),
    "calendar-label": (
        ("week-label-VALUE", "standalone"),
        ('calendar_week = "VALUE" # report-period', "embedded"),
        ('<report period="VALUE" category="weekly"/>', "embedded"),
        ("INSERT INTO reports (week_label) VALUES ('VALUE');", "embedded"),
        ("report-runner --week VALUE --preview", "embedded"),
    ),
    "resource-urn": (
        ("urn:fixture:resource:VALUE", "standalone"),
        ('resource_reference = "VALUE" # sample-uri', "embedded"),
        ('<resource ref="VALUE" visibility="public"/>', "embedded"),
        ("SELECT ref FROM demo_catalog WHERE ref = 'VALUE';", "embedded"),
        ("catalog lookup --resource-uri VALUE", "embedded"),
    ),
    "build-serial": (
        ("build-VALUE", "standalone"),
        ('build_serial = "VALUE" # runner-id', "embedded"),
        ('<pipeline run="VALUE" state="complete"/>', "embedded"),
        ("UPDATE build_log SET serial = 'VALUE' WHERE synthetic = TRUE;", "embedded"),
        ("ci-agent --run-id VALUE --status=complete", "embedded"),
    ),
}


def build_cases(seed: int = DEFAULT_SEED) -> list[CorpusCase]:
    """Create 2k JWE, 1k JWS, and 10k all-JOSE-clean grouped examples."""
    root = _seed_root(seed)
    cases: list[CorpusCase] = []
    jwe_index = 0
    algorithm_cycle = ("A256KW", "dir", "ECDH-ES")
    positive_recipes = []
    for index, (name, template) in enumerate(_POSITIVE_STANDALONE):
        split = "holdout" if index >= 6 else "dev"
        positive_recipes.append((f"p2-jwe-{name}", split, "standalone", template, "unknown", index))
    for index, (name, template, action) in enumerate(_POSITIVE_EMBEDDED):
        split = "holdout" if index >= len(_POSITIVE_EMBEDDED) - 6 else "dev"
        positive_recipes.append((f"p2-jwe-{name}", split, "embedded", template, action, len(_POSITIVE_STANDALONE) + index))
    if len(positive_recipes) != 40:
        raise AssertionError("v2 JWE renderer family count changed")
    for family, split, mode, template, action, family_index in positive_recipes:
        algorithm = algorithm_cycle[family_index % len(algorithm_cycle)]
        for item_index in range(50):
            seed_group = f"v2-jwe/{family}/{item_index:03d}"
            token_seed = _seed_for(root, seed_group)
            token, header = _make_jwe(token_seed, algorithm=algorithm, heldout_recipe=split == "holdout")
            wrapper = template.replace("TOKEN", token)
            start = wrapper.index(token)
            end = start + len(token)
            normalized = (template.replace("TOKEN", "<JOSE>")
                          + "\n<PROTECTED-HEADER>" + _header_shape(header))
            cases.append(CorpusCase(
                case_id=f"v2-jwe-{jwe_index:05d}", split=split, template_family=family,
                seed_group=seed_group, category="intact-supported-jwe", mode=mode,
                text=wrapper, expected_spans=((start, end),), format_outcome="positive",
                actionability=action, algorithm=algorithm, expected_entity="JOSE_COMPACT_JWE",
                development_partition=_partition(split, family_index),
                logical_path=f"fixtures/v2/{family}.txt",
                normalized_template=normalized,
                template_fingerprint=_case_fingerprint(normalized)))
            jwe_index += 1
    if jwe_index != JWE_COUNT:
        raise AssertionError("v2 JWE cardinality changed")

    jws_recipes = []
    for index, (name, template) in enumerate(_JWS_STANDALONE):
        split = "holdout" if index == len(_JWS_STANDALONE) - 1 else "dev"
        jws_recipes.append((f"p2-jws-{name}", split, "standalone", template, index))
    for index, (name, template) in enumerate(_JWS_EMBEDDED):
        split = "holdout" if index >= len(_JWS_EMBEDDED) - 3 else "dev"
        jws_recipes.append((f"p2-jws-{name}", split, "embedded", template,
                            len(_JWS_STANDALONE) + index))
    if len(jws_recipes) != 20:
        raise AssertionError("v2 JWS renderer family count changed")
    jws_index = 0
    for family, split, mode, template, family_index in jws_recipes:
        for item_index in range(50):
            seed_group = f"v2-jws/{family}/{item_index:03d}"
            token_seed = _seed_for(root, seed_group)
            token, header = _make_jws(token_seed, heldout_recipe=split == "holdout")
            rendered = template.replace("TOKEN", token)
            start = rendered.index(token)
            end = start + len(token)
            normalized = (template.replace("TOKEN", "<JOSE>")
                          + "\n<PROTECTED-HEADER>" + _header_shape(header))
            cases.append(CorpusCase(
                case_id=f"v2-jws-{jws_index:05d}", split=split, template_family=family,
                seed_group=seed_group, category="three-part-jws", mode=mode, text=rendered,
                expected_spans=(), format_outcome="negative", actionability="unknown",
                expected_other_spans=((start, end, "JOSE_COMPACT_JWS_CANDIDATE"),),
                expected_entity=None, development_partition=_partition(split, family_index),
                logical_path=f"fixtures/v2/{family}.txt", negative_kind="jws-candidate",
                normalized_template=normalized,
                template_fingerprint=_case_fingerprint(normalized)))
            jws_index += 1

    clean_index = 0
    for category, variants in _NEGATIVE_TEMPLATES.items():
        for variant, (template, mode) in enumerate(variants):
            family = f"p2-clean-{category}-r{variant}"
            split = "holdout" if variant == 4 else "dev"
            for item_index in range(200):
                seed_group = f"v2-clean/{family}/{item_index:03d}"
                rng = random.Random(int.from_bytes(_derive(root, seed_group, 8), "big"))
                value = (_standalone_negative_value(category, rng, item_index) if variant == 0
                         else _negative_value(category, rng, item_index))
                text = template.replace("VALUE", value)
                normalized = template.replace("VALUE", "<VALUE>")
                cases.append(CorpusCase(
                    case_id=f"v2-clean-{clean_index:05d}", split=split,
                    template_family=family, seed_group=seed_group, category=category,
                    mode=mode, text=text, expected_spans=(), format_outcome="negative",
                    actionability="unknown", expected_entity=None,
                    development_partition=_partition(split, variant),
                    logical_path=f"fixtures/v2/clean/{family}.txt", negative_kind=category,
                    normalized_template=normalized,
                    template_fingerprint=_case_fingerprint(normalized)))
                clean_index += 1
    if clean_index != CLEAN_NEGATIVE_COUNT:
        raise AssertionError("v2 clean-negative cardinality changed")
    return cases


_ADVERSARIAL_REASONS = (
    "bad-authentication-tag", "duplicate-header-member", "padded-base64url",
    "wrong-algorithm-fields", "invalid-base64url", "extra-segment",
    "truncated-header", "unsupported-algorithm", "oversized-header",
    "wrong-encrypted-key-shape", "empty-ciphertext", "malformed-json",
)


def build_adversarial_cases(seed: int = DEFAULT_SEED) -> list[CorpusCase]:
    """Shared regression inputs. These are never in split confusion metrics."""
    root = _seed_root(seed)
    cases = []
    for index in range(ADVERSARIAL_COUNT):
        reason = _ADVERSARIAL_REASONS[index % len(_ADVERSARIAL_REASONS)]
        seed_group = f"v2-adversarial/{index:03d}"
        token_seed = _seed_for(root, seed_group)
        token, _ = _make_jwe(token_seed, algorithm=("A256KW", "dir", "ECDH-ES")[index % 3],
                             heldout_recipe=True)
        parts = token.split(".")
        if reason == "bad-authentication-tag":
            parts[4] = ("A" if parts[4][0] != "A" else "B") + parts[4][1:]
            prefix, action = "auth.ticket=", "exposed"
        elif reason == "duplicate-header-member":
            parts[0] = _b64url(b'{"enc":"A256GCM","alg":"A256KW","alg":"dir"}')
            prefix, action = "credential-record=", "exposed"
        elif reason == "padded-base64url":
            parts = [part + "=" * (-len(part) % 4) if part else part for part in parts]
            prefix, action = "", "unknown"
        elif reason == "wrong-algorithm-fields":
            parts[0] = _b64url(b'{"enc":"A128GCM","alg":"A256KW","typ":"JWE"}')
            prefix, action = "Cookie: auth_ticket=", "exposed"
        elif reason == "invalid-base64url":
            parts[2] = "*" + parts[2][1:]
            prefix, action = "runtime-ref=", "exposed"
        elif reason == "extra-segment":
            parts.append(_b64url(b"additional-segment"))
            prefix, action = "", "unknown"
        elif reason == "truncated-header":
            parts[0] = parts[0][:8]
            prefix, action = "vault-state=", "exposed"
        elif reason == "unsupported-algorithm":
            parts[0] = _b64url(b'{"enc":"A256GCM","alg":"FUTURE-KW","typ":"JWE"}')
            prefix, action = "X-Session-Key: ", "exposed"
        elif reason == "oversized-header":
            parts[0] = _b64url(json.dumps({"enc": "A256GCM", "alg": "A256KW", "typ": "JWE",
                                          "comment": "x" * 8192}, separators=(",", ":")).encode())
            prefix, action = "session_ticket=", "exposed"
        elif reason == "wrong-encrypted-key-shape":
            parts[1] = ""
            prefix, action = "build-session-ticket=", "exposed"
        elif reason == "empty-ciphertext":
            parts[3] = ""
            prefix, action = "runtime-value=", "exposed"
        else:
            parts[0] = _b64url(b"not-json-v2")
            prefix, action = "identity-record=", "exposed"
        candidate = ".".join(parts)
        text = prefix + candidate
        start, end = len(prefix), len(prefix) + len(candidate)
        normalized = prefix + "<MALFORMED-CANDIDATE>"
        cases.append(CorpusCase(
            case_id=f"v2-adversarial-{index:03d}", split="adversarial",
            template_family=f"v2-adversarial-{reason}", seed_group=seed_group,
            category="malformed-or-unsupported-jose", mode="embedded" if prefix else "standalone",
            text=text, expected_spans=((start, end),), format_outcome="adversarial",
            actionability=action, expected_entity="JOSE_COMPACT_UNVERIFIED",
            adversarial_reason=reason, logical_path="fixtures/v2/regression/adversarial.txt",
            negative_kind=None, normalized_template=normalized,
            template_fingerprint=_case_fingerprint(normalized)))
    return cases


def canonical_label_bytes(cases: list[CorpusCase]) -> bytes:
    return json.dumps([case.label_dict() for case in cases], sort_keys=True,
                      ensure_ascii=True, separators=(",", ":")).encode("ascii")


def fixture_digest(case: CorpusCase) -> str:
    return hashlib.sha256(case.text.encode("utf-8")).hexdigest()


_GENERIC_VALUE = re.compile(r"(?:[A-Za-z0-9_-]{32,}|[0-9a-fA-F]{20,}|\d{4,})")


def v1_normalized_rendering(case) -> str:
    """Normalize V1 generated samples for an actual-surface overlap audit."""
    spans = list(case.expected_spans) + [(start, end) for start, end, _ in case.expected_other_spans]
    if spans:
        text = case.text
        for start, end in sorted(spans, reverse=True):
            text = text[:start] + "<JOSE>" + text[end:]
        start, end = spans[0]
        protected = case.text[start:end].split(".", 1)[0]
        try:
            raw_header = _unb64url(protected).decode("utf-8")
            text += "\n<PROTECTED-HEADER>" + _header_shape(raw_header)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            text += "\n<PROTECTED-HEADER-UNPARSEABLE>"
    else:
        text = _GENERIC_VALUE.sub("<VALUE>", case.text)
    return text
