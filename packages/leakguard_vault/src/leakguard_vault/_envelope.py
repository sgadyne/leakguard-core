"""Versioned AES-GCM envelope with bounded Argon2id key wrapping."""
from __future__ import annotations

import base64
import copy
import json
import secrets
import struct
import uuid

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .errors import VaultError

MAGIC = b"LGVA\x01\x00\r\n"
MAX_HEADER = 8192
MAX_STATE = 64 * 1024 * 1024
MAX_FILE = MAX_STATE + MAX_HEADER + 128
KINDS = {"credentials", "observations", "credentials-backup", "observations-backup"}


def canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise VaultError("vault-data-invalid") from None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def load_json(value: bytes):
    try:
        return json.loads(value, object_pairs_hook=_unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise VaultError("vault-format-invalid") from None


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value, size: int) -> bytes:
    try:
        if type(value) is not str or len(value) > 4 * (size + 2) // 3 + 4:
            raise ValueError()
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) != size:
            raise ValueError()
        return decoded
    except (ValueError, TypeError):
        raise VaultError("vault-format-invalid") from None


def _passphrase(value, *, creating=False) -> bytes:
    if type(value) is not str or not (12 if creating else 1) <= len(value) <= 1024:
        raise VaultError("vault-passphrase-invalid")
    try:
        return value.encode("utf-8")
    except UnicodeError:
        raise VaultError("vault-passphrase-invalid") from None


def _meta(header):
    return {key: header[key] for key in ("version", "kind", "id", "cipher", "kdf")}


def _derive(passphrase: str, kdf: dict) -> bytes:
    try:
        return Argon2id(salt=_unb64(kdf["salt"], 16), length=32, iterations=kdf["iterations"],
                        lanes=kdf["lanes"], memory_cost=kdf["memory_kib"]).derive(_passphrase(passphrase))
    except (UnsupportedAlgorithm, MemoryError):
        raise VaultError("vault-crypto-unavailable") from None


def new_header(kind: str, passphrase: str, *, data_key: bytes | None = None):
    if kind not in KINDS:
        raise VaultError("vault-kind-invalid")
    _passphrase(passphrase, creating=True)
    key = data_key or secrets.token_bytes(32)
    if type(key) is not bytes or len(key) != 32:
        raise VaultError("vault-key-invalid")
    header = {"version": 1, "kind": kind, "id": uuid.uuid4().hex, "cipher": "aes-256-gcm",
              "kdf": {"name": "argon2id", "salt": _b64(secrets.token_bytes(16)),
                      "iterations": 3, "lanes": 4, "memory_kib": 65536}}
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(_derive(passphrase, header["kdf"])).encrypt(nonce, key, b"leakguard:key-wrap:" + canonical(_meta(header)))
    header["key_wrap"] = {"nonce": _b64(nonce), "ciphertext": _b64(wrapped)}
    return header, key


def encode(header: dict, key: bytes, plaintext: bytes):
    if len(plaintext) > MAX_STATE:
        raise VaultError("vault-capacity-limit")
    current = copy.deepcopy(header)
    nonce = secrets.token_bytes(12)
    current["nonce"] = _b64(nonce)
    encoded = canonical(current)
    if len(encoded) > MAX_HEADER:
        raise VaultError("vault-format-invalid")
    prefix = MAGIC + struct.pack(">I", len(encoded)) + encoded
    try:
        return current, prefix + AESGCM(key).encrypt(nonce, plaintext, prefix)
    except (ValueError, TypeError):
        raise VaultError("vault-key-invalid") from None


def parse(value: bytes, expected_kind: str):
    try:
        if type(value) is not bytes or not len(MAGIC) + 4 + 16 <= len(value) <= MAX_FILE or not value.startswith(MAGIC):
            raise ValueError()
        length = struct.unpack(">I", value[len(MAGIC):len(MAGIC) + 4])[0]
        if not 1 <= length <= MAX_HEADER or len(value) < len(MAGIC) + 4 + length + 16:
            raise ValueError()
        end = len(MAGIC) + 4 + length
        header = load_json(value[len(MAGIC) + 4:end])
        fields = {"version", "kind", "id", "cipher", "kdf", "key_wrap", "nonce"}
        if type(header) is not dict or set(header) not in (fields, fields | {"keyring"}):
            raise ValueError()
        if type(header["version"]) is not int or header["version"] != 1 or header["kind"] != expected_kind or header["cipher"] != "aes-256-gcm":
            raise ValueError()
        if type(header["id"]) is not str or len(header["id"]) != 32 or uuid.UUID(hex=header["id"]).hex != header["id"]:
            raise ValueError()
        kdf = header["kdf"]
        if type(kdf) is not dict or set(kdf) != {"name", "salt", "iterations", "lanes", "memory_kib"} or kdf["name"] != "argon2id":
            raise ValueError()
        for name, minimum, maximum in (("iterations", 1, 6), ("lanes", 1, 8), ("memory_kib", 16384, 262144)):
            if type(kdf[name]) is not int or not minimum <= kdf[name] <= maximum:
                raise ValueError()
        _unb64(kdf["salt"], 16)
        wrap = header["key_wrap"]
        if type(wrap) is not dict or set(wrap) != {"nonce", "ciphertext"}:
            raise ValueError()
        _unb64(wrap["nonce"], 12)
        _unb64(wrap["ciphertext"], 48)
        _unb64(header["nonce"], 12)
        if "keyring" in header:
            if expected_kind != "observations" or header["keyring"] != {"service": "leakguard-observations-v1", "account": header["id"]}:
                raise ValueError()
        return header, value[:end], value[end:]
    except (ValueError, TypeError, KeyError, OverflowError, struct.error):
        raise VaultError("vault-format-invalid") from None


def decrypt_with_key(value: bytes, expected_kind: str, key: bytes):
    header, prefix, ciphertext = parse(value, expected_kind)
    try:
        plain = AESGCM(key).decrypt(_unb64(header["nonce"], 12), ciphertext, prefix)
        if len(plain) > MAX_STATE:
            raise VaultError("vault-capacity-limit")
        return header, key, plain
    except (InvalidTag, ValueError, TypeError):
        raise VaultError("vault-authentication-failed") from None


def decrypt(value: bytes, expected_kind: str, passphrase: str):
    header, _, _ = parse(value, expected_kind)
    try:
        key = AESGCM(_derive(passphrase, header["kdf"])).decrypt(
            _unb64(header["key_wrap"]["nonce"], 12), _unb64(header["key_wrap"]["ciphertext"], 48),
            b"leakguard:key-wrap:" + canonical(_meta(header)))
    except InvalidTag:
        raise VaultError("vault-authentication-failed") from None
    return decrypt_with_key(value, expected_kind, key)
