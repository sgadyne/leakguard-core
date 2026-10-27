"""Spec-derived synthetic cases and labels, independent of detector patterns.

The compact JWE fixtures are encrypted with PyCA cryptography. Keys and
plaintexts are reproducibly derived from disposable public seeds; no real token
or key is read. Labels describe serialization structure and exposure context
separately. Malformed derivatives live in an adversarial set, never among
ordinary negatives.
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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap


CORPUS_VERSION = "jose-synthetic-2026-01"
DEFAULT_SEED = 20261026
POSITIVE_COUNT = 2_000
NEGATIVE_COUNT = 10_000
ADVERSARIAL_COUNT = 120
SPLIT_ORDER = ("train", "validation", "test")
SPLIT_COUNTS = {"train": 1_200, "validation": 400, "test": 400}
_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


@dataclass(frozen=True)
class Case:
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
    logical_path: str = "fixtures/input.txt"
    part_id: str = "text"
    format_id: str = "text"

    def label_dict(self) -> dict[str, Any]:
        exposure = {"exposed": True, "public": False, "unknown": None}[self.actionability]
        spans = [{"start": start, "end": end,
                  "entity_type": self.expected_entity or "JOSE_COMPACT_JWE",
                  "format_positive": self.format_outcome == "positive",
                  "actionable_exposure": exposure}
                 for start, end in self.expected_spans]
        return {
            "id": self.case_id,
            "case_id": self.case_id,
            "split": self.split,
            "development_partition": self.development_partition,
            "template_family": self.template_family,
            "seed_id": self.seed_group,
            "seed_group": self.seed_group,
            "category": self.category,
            "mode": self.mode,
            "expected_spans": [list(span) for span in self.expected_spans],
            "spans": spans,
            "other_spans": [{"start": start, "end": end, "entity_type": entity,
                             "format_positive": True, "actionable_exposure": None}
                            for start, end, entity in self.expected_other_spans],
            "format_outcome": self.format_outcome,
            "actionability": self.actionability,
            "format_id": self.format_id,
            "slice": [self.mode, self.category, self.algorithm or "unspecified", self.actionability],
            "negative_kind": self.category if self.format_outcome == "negative" else None,
            "algorithm": self.algorithm,
            "expected_entity": self.expected_entity,
            "adversarial_reason": self.adversarial_reason,
            "logical_path": self.logical_path,
            "part_id": self.part_id,
            "format_id": self.format_id,
        }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64url(value: str) -> bytes:
    if not value or _B64URL.fullmatch(value) is None or len(value) % 4 == 1:
        raise ValueError("invalid synthetic base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _derive(seed: bytes, label: str, size: int = 32) -> bytes:
    """Domain-separated deterministic key material for disposable fixtures."""
    result = bytearray()
    counter = 1
    while len(result) < size:
        result.extend(hmac.new(seed, label.encode("ascii") + counter.to_bytes(4, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(result[:size])


def _ec_private(seed: bytes, label: str):
    scalar = int.from_bytes(_derive(seed, label), "big") % (_P256_ORDER - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def _length_prefix(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def _concat_kdf(shared: bytes, algorithm_id: str, key_bits: int) -> bytes:
    """RFC 7518 4.6.2 Concat KDF for ECDH-ES direct key agreement."""
    other_info = (
        _length_prefix(algorithm_id.encode("ascii"))
        + _length_prefix(b"")  # PartyUInfo
        + _length_prefix(b"")  # PartyVInfo
        + key_bits.to_bytes(4, "big")
    )
    return hashlib.sha256((1).to_bytes(4, "big") + shared + other_info).digest()[:key_bits // 8]


def make_jwe(seed: bytes, *, algorithm: str = "A256KW", header_variant: int = 0) -> str:
    """Create an intact compact JWE per RFC 7516/7518 with a disposable key."""
    if type(seed) is not bytes or len(seed) < 16:
        raise ValueError("seed must contain at least 128 bits")
    if algorithm not in {"A256KW", "dir", "ECDH-ES"}:
        raise ValueError("unsupported fixture algorithm")

    header: dict[str, Any] = {"alg": algorithm, "enc": "A256GCM"}
    if header_variant % 3 == 1:
        header["kid"] = "synthetic-" + hashlib.sha256(seed).hexdigest()[:12]
    elif header_variant % 3 == 2:
        header["cty"] = "application/json"
        header["kid"] = "synthetic-" + hashlib.sha256(seed).hexdigest()[:12]

    if algorithm == "A256KW":
        cek = _derive(seed, "cek", 32)
        encrypted_key = aes_key_wrap(_derive(seed, "kek", 32), cek)
    elif algorithm == "dir":
        cek = _derive(seed, "direct-content-encryption-key", 32)
        encrypted_key = b""
    else:
        recipient = _ec_private(seed, "recipient-p256")
        ephemeral = _ec_private(seed, "ephemeral-p256")
        peer = recipient.public_key()
        ephemeral_public = ephemeral.public_key().public_numbers()
        header["epk"] = {
            "kty": "EC", "crv": "P-256",
            "x": _b64url(ephemeral_public.x.to_bytes(32, "big")),
            "y": _b64url(ephemeral_public.y.to_bytes(32, "big")),
        }
        cek = _concat_kdf(ephemeral.exchange(ec.ECDH(), peer), "A256GCM", 256)
        encrypted_key = b""

    protected = _b64url(json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
    iv = _derive(seed, "content-encryption-iv", 12)
    plaintext = json.dumps({
        "sub": "synthetic-" + hashlib.sha256(seed + b"subject").hexdigest()[:20],
        "nonce": _b64url(_derive(seed, "plaintext-nonce", 12)),
    }, separators=(",", ":")).encode("ascii")
    sealed = AESGCM(cek).encrypt(iv, plaintext, protected.encode("ascii"))
    ciphertext, tag = sealed[:-16], sealed[-16:]
    return ".".join((protected, _b64url(encrypted_key), _b64url(iv),
                     _b64url(ciphertext), _b64url(tag)))


def _family_split(family_id: str, bucket: str) -> str:
    """Frozen assignment table: family IDs do not cross corpus partitions."""
    # Ten held-out and ten validation families per type, stratified by category.
    # The IDs themselves are recorded in the checked-in split manifest.
    variant = int(family_id.rsplit("-v", 1)[1])
    return "train" if variant <= 3 else "validation" if variant == 4 else "test"


_BARE_FAMILIES = (
    "bare-a256kw-minimal", "bare-a256kw-kid", "bare-a256kw-cty",
    "bare-dir-minimal", "bare-dir-kid", "bare-dir-cty",
    "bare-ecdh-minimal", "bare-ecdh-kid", "bare-ecdh-cty",
    "bare-a256kw-header-order",
)
_EMBED_FAMILIES = tuple(
    f"{context}-v{variant}"
    for context in ("json-secret", "yaml-token", "env-secret", "http-token",
                    "http-bearer", "shell-export", "markdown-public", "log-credential")
    for variant in range(1, 6)
)


def _positive_families() -> list[tuple[str, str]]:
    # Six standalone families train, two validation, two test. The embedded
    # families use the same 24/8/8 stratification. All held-out families and
    # token seed groups are absent from training.
    result = []
    for index, name in enumerate(_BARE_FAMILIES):
        split = "train" if index < 6 else "validation" if index < 8 else "test"
        result.append((name, split))
    for name in _EMBED_FAMILIES:
        result.append((name, _family_split(name, "positive")))
    return result


def _format_positive(family: str, token: str, variant: int) -> tuple[str, tuple[int, int], str, str, str]:
    if family.startswith("bare-"):
        return token, (0, len(token)), "standalone", "unknown", "fixtures/standalone.jwe"
    kind = family.rsplit("-v", 1)[0]
    choice = variant % 5
    wrappers = {
        "json-secret": lambda: (f'{{"{("client_secret", "private_token", "credential", "refresh_token", "key")[choice]}":"{token}"}}', "exposed", "config/credentials.json"),
        "yaml-token": lambda: (f'{("access_token", "session_key", "client_secret", "auth_token", "credential")[choice]}: "{token}"\n', "exposed", "config/credentials.yaml"),
        "env-secret": lambda: (f'{("APP_TOKEN", "CLIENT_SECRET", "AUTH_KEY", "SESSION_TOKEN", "SERVICE_CREDENTIAL")[choice]}={token}\r\n', "exposed", "config/service.env"),
        "http-token": lambda: (f'Authorization: Token {token}\r\n', "exposed", "fixtures/request.http"),
        "http-bearer": lambda: (f'Authorization: Bearer {token}\r\n', "exposed", "fixtures/request.http"),
        "shell-export": lambda: (f'export {("APP_TOKEN", "CLIENT_SECRET", "AUTH_KEY", "SESSION_TOKEN", "SERVICE_CREDENTIAL")[choice]}="{token}"\n', "exposed", "scripts/run.sh"),
        "markdown-public": lambda: (f'Public format example ({("RFC compact form", "parser docs", "sample", "test vector", "serialization example")[choice]}): `{token}`\n', "public", "docs/format.md"),
        "log-credential": lambda: (f'2026-10-26T20:30:{choice:02d}Z auth credential="{token}" status=synthetic\n', "exposed", "logs/auth.log"),
    }
    text, actionability, path = wrappers[kind]()
    start = text.index(token)
    return text, (start, start + len(token)), "embedded", actionability, path


_NEGATIVE_CATEGORIES = (
    "three-part-jws", "digest-version-date", "base64-blobs", "public-key",
    "placeholders-references", "misleading-numeric", "random-five-part",
    "unicode-crlf-quotes", "long-lines-delimiters", "ordinary-structured-data",
)


def _b64_random(rng: random.Random, size: int) -> str:
    return _b64url(bytes(rng.randrange(256) for _ in range(size)))


def _jws(rng: random.Random) -> str:
    header = json.dumps({"alg": "HS256", "kid": "synthetic-public-example"}, separators=(",", ":")).encode()
    payload = json.dumps({"sub": "fixture-user", "scope": "read", "iat": 1_798_000_000}, separators=(",", ":")).encode()
    key = bytes(rng.randrange(256) for _ in range(32))
    body = _b64url(header) + "." + _b64url(payload)
    signature = hmac.new(key, body.encode("ascii"), hashlib.sha256).digest()
    return body + "." + _b64url(signature)


def _synthetic_public_key(seed: int) -> str:
    private = ec.derive_private_key(seed % (_P256_ORDER - 1) + 1, ec.SECP256R1())
    return private.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii").strip()


def _negative_text(category: str, rng: random.Random, index: int, public_key: str) -> str:
    if category == "three-part-jws":
        token = _jws(rng)
        return rng.choice((token, f"Authorization: Bearer {token}", f"jws={token}\n"))
    if category == "digest-version-date":
        digest = hashlib.sha256(bytes(rng.randrange(256) for _ in range(48))).hexdigest()
        return f"sha256:{digest} build=v{rng.randrange(1,9)}.{rng.randrange(100)}.{rng.randrange(1000)} date=2026-{rng.randrange(1,13):02d}-{rng.randrange(1,28):02d}"
    if category == "base64-blobs":
        return rng.choice(("blob=" + _b64_random(rng, 96), "payload=" + _b64_random(rng, 192), "data:application/octet-stream;base64," + base64.b64encode(bytes(rng.randrange(256) for _ in range(72))).decode("ascii")))
    if category == "public-key":
        return f"# synthetic public key, safe to publish\n{public_key}\nserial={index:08d}"
    if category == "placeholders-references":
        return rng.choice(("TOKEN=<REDACTED>", "client_secret=${CLIENT_SECRET}", "password={{ secret }}", "credential=op://demo/app/token", "secret_ref=vault://team/service/item", "token=CHANGE_ME"))
    if category == "misleading-numeric":
        digits = "".join(str(rng.randrange(10)) for _ in range(rng.randrange(9, 20)))
        return rng.choice((f"invoice={digits} version=2.18.4", f"phone=+1-{digits[:3]}-{digits[3:6]}-{digits[6:10]}", f"accounting batch {digits} on 2026-10-26", f"sample_card={digits} (synthetic invalid)"))
    if category == "random-five-part":
        # Five compact-looking fields, but the protected segment is not JOSE
        # JSON and does not encode a supported alg/enc pair.
        return ".".join((_b64_random(rng, 18), _b64_random(rng, 40), _b64_random(rng, 12), _b64_random(rng, 48), _b64_random(rng, 16)))
    if category == "unicode-crlf-quotes":
        return rng.choice((f'“release” = “2.0.{index}” — café\r\n', f"説明: token は設定済み\nrun={index}", f"quoted='Bearer {{redacted}}'\r\n", f"key\u200b={{{{ template }}}}"))
    if category == "long-lines-delimiters":
        padding = "x" * (300 + index % 500)
        return f"row,{index},build-{index % 300},note:{padding},<MASKED>"
    if category == "ordinary-structured-data":
        return rng.choice((json.dumps({"version": f"{index % 10}.4.2", "status": "ok", "ref": f"cfg://demo/{index}"}), f"[release]\nversion={index % 9}.3.{index % 100}\nstatus=ready\n", f"{{\"authorization\":\"Bearer <PLACEHOLDER>\",\"expires\":\"2026-12-01\"}}"))
    raise ValueError("unknown negative category")


def build_cases(seed: int = DEFAULT_SEED) -> list[Case]:
    """Build 2,000 intact-format positives and 10,000 clean format negatives."""
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    root_seed = hashlib.sha256(f"{CORPUS_VERSION}:{seed}".encode("ascii")).digest()
    positives: list[Case] = []
    for family, split in _positive_families():
        for index in range(40):
            seed_group = f"pos/{family}/{index:03d}"
            token_seed = _derive(root_seed, seed_group, 32)
            if family.startswith("bare-"):
                family_alg = "A256KW" if "a256kw" in family else "dir" if "bare-dir" in family else "ECDH-ES"
            else:
                family_alg = ("A256KW", "dir", "ECDH-ES")[index % 3]
            token = make_jwe(token_seed, algorithm=family_alg, header_variant=index)
            text, span, mode, actionability, path = _format_positive(family, token, index)
            public_split = "holdout" if split == "test" else "dev"
            positives.append(Case(
                case_id=f"positive-{len(positives):04d}", split=public_split,
                template_family=family, seed_group=seed_group,
                category="intact-supported-jwe", mode=mode, text=text,
                expected_spans=(span,), format_outcome="positive",
                actionability=actionability, algorithm=family_alg,
                development_partition=None if public_split == "holdout" else split,
                logical_path=path,
            ))
    if len(positives) != POSITIVE_COUNT:
        raise AssertionError("positive corpus cardinality changed")

    public_key = _synthetic_public_key(int.from_bytes(root_seed[:4], "big"))
    negatives: list[Case] = []
    for category in _NEGATIVE_CATEGORIES:
        for variant in range(1, 6):
            family = f"negative-{category}-v{variant}"
            development_partition = "train" if variant <= 3 else "validation" if variant == 4 else None
            split = "dev" if development_partition else "holdout"
            for index in range(200):
                seed_group = f"neg/{family}/{index:03d}"
                rng_seed = int.from_bytes(_derive(root_seed, seed_group, 8), "big")
                rng = random.Random(rng_seed)
                other_spans = ()
                if category == "three-part-jws":
                    token = _jws(rng)
                    wrapper = index % 3
                    if wrapper == 0:
                        text, start = token, 0
                    elif wrapper == 1:
                        prefix = "Authorization: Bearer "
                        text, start = prefix + token, len(prefix)
                    else:
                        prefix = "jws="
                        text, start = prefix + token + "\n", len(prefix)
                    other_spans = ((start, start + len(token), "JOSE_COMPACT_JWS_CANDIDATE"),)
                else:
                    text = _negative_text(category, rng, index, public_key)
                negatives.append(Case(
                    case_id=f"negative-{len(negatives):05d}", split=split,
                    template_family=family, seed_group=seed_group,
                    category=category, mode="embedded" if "=" in text or "\n" in text else "standalone",
                    text=text, expected_spans=(), format_outcome="negative",
                    actionability="unknown", expected_entity=None,
                    expected_other_spans=other_spans,
                    development_partition=development_partition,
                    logical_path=f"fixtures/negative/{category}.txt",
                ))
    if len(negatives) != NEGATIVE_COUNT:
        raise AssertionError("negative corpus cardinality changed")
    return positives + negatives


def build_adversarial_cases(seed: int = DEFAULT_SEED) -> list[Case]:
    """Construct malformed derivatives separately; they are never TN labels."""
    root_seed = hashlib.sha256(f"{CORPUS_VERSION}:{seed}:adversarial".encode("ascii")).digest()
    cases: list[Case] = []
    reasons = ("bad-authentication-tag", "duplicate-header-member", "padded-base64url",
               "wrong-algorithm-fields", "invalid-base64url", "extra-segment",
               "truncated-header", "unsupported-algorithm", "oversized-header",
               "wrong-encrypted-key-shape", "empty-ciphertext", "malformed-json")
    for index in range(ADVERSARIAL_COUNT):
        family_index = index % len(reasons)
        reason = reasons[family_index]
        token_seed = _derive(root_seed, f"adversarial/{index:03d}")
        token = make_jwe(token_seed, algorithm=("A256KW", "dir", "ECDH-ES")[index % 3], header_variant=index)
        parts = token.split(".")
        if reason == "bad-authentication-tag":
            last = "A" if parts[4][0] != "A" else "B"
            parts[4] = last + parts[4][1:]
            text = "CLIENT_SECRET=" + ".".join(parts)
            action = "exposed"
        elif reason == "duplicate-header-member":
            raw = b'{"alg":"A256KW","enc":"A256GCM","alg":"dir"}'
            parts[0] = _b64url(raw)
            text = "credential=" + ".".join(parts)
            action = "exposed"
        elif reason == "padded-base64url":
            parts = [p + "=" * (-len(p) % 4) if p else p for p in parts]
            text = ".".join(parts)
            action = "unknown"
        elif reason == "wrong-algorithm-fields":
            parts[0] = _b64url(b'{"alg":"A256KW","enc":"A128GCM"}')
            text = "Authorization: Bearer " + ".".join(parts)
            action = "exposed"
        elif reason == "invalid-base64url":
            parts[2] = "*" + parts[2][1:]
            text = "token=" + ".".join(parts)
            action = "exposed"
        elif reason == "extra-segment":
            text = ".".join(parts + [_b64url(b"extra")])
            action = "unknown"
        elif reason == "truncated-header":
            parts[0] = parts[0][:7]
            text = "client_secret=" + ".".join(parts)
            action = "exposed"
        elif reason == "unsupported-algorithm":
            parts[0] = _b64url(b'{"alg":"A999KW","enc":"A256GCM"}')
            text = "Authorization: Token " + ".".join(parts)
            action = "exposed"
        elif reason == "oversized-header":
            parts[0] = _b64url(json.dumps({"alg": "A256KW", "enc": "A256GCM", "note": "x" * 8192}, separators=(",", ":")).encode())
            text = "secret=" + ".".join(parts)
            action = "exposed"
        elif reason == "wrong-encrypted-key-shape":
            parts[1] = ""
            text = "key=" + ".".join(parts)
            action = "exposed"
        elif reason == "empty-ciphertext":
            parts[3] = ""
            text = "key=" + ".".join(parts)
            action = "exposed"
        else:
            parts[0] = _b64url(b"not-json")
            text = "credential=" + ".".join(parts)
            action = "exposed"
        # Span covers the malformed compact candidate, not a claimed valid JWE.
        candidate = ".".join(parts)
        start = text.rfind(candidate)
        end = start + len(candidate)
        cases.append(Case(
            case_id=f"adversarial-{index:03d}", split="adversarial",
            template_family=f"adversarial-{reason}", seed_group=f"adv/{index:03d}",
            category="malformed-or-unsupported-jose", mode="embedded" if start else "standalone",
            text=text, expected_spans=((start, end),) if end > start else (),
            format_outcome="adversarial", actionability=action,
            algorithm=None, expected_entity="JOSE_COMPACT_UNVERIFIED", adversarial_reason=reason,
            logical_path="fixtures/adversarial.txt",
        ))
    return cases


def canonical_label_bytes(cases: list[Case]) -> bytes:
    return json.dumps([case.label_dict() for case in cases], sort_keys=True,
                      ensure_ascii=True, separators=(",", ":")).encode("ascii")


def fixture_digest(case: Case) -> str:
    return hashlib.sha256(case.text.encode("utf-8")).hexdigest()
