"""Strict, explicit resource loading for version 1 credential alias packs.

Keys are ASCII case-insensitive and only '.', '-' and '_' are removed before
lookup. Collisions, even redundant ones, are rejected across composed packs.
Resources are addressed within an explicit importable package, never discovered.
"""
from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
import json
import re
from types import MappingProxyType
from typing import Mapping

ROLES = frozenset({'password', 'api-key', 'client-secret', 'access-token', 'private-key'})
GROUPS = frozenset({'common', 'cloud', 'developer-ci', 'data-messaging', 'saas-ai', 'key-material'})
MAX_RESOURCE_BYTES = 262_144
MAX_ALIASES = 4096
MAX_PACKS = 32
_KEY = re.compile(r'[A-Za-z][A-Za-z0-9_.-]{0,127}\Z', re.ASCII)
_SLUG = re.compile(r'[a-z0-9]+(?:-[a-z0-9]+)*\Z', re.ASCII)
_COMPONENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z', re.ASCII)


class AliasPackError(ValueError):
    """A resource is invalid or unavailable; messages contain no resource data."""


def normalize_key(key: str) -> str:
    if type(key) is not str or not _KEY.fullmatch(key):
        raise AliasPackError('invalid alias key')
    return key.lower().translate(str.maketrans('', '', '._-'))


@dataclass(frozen=True, slots=True)
class AliasPack:
    pack_ids: tuple[str, ...]
    aliases: Mapping[str, str]


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AliasPackError('duplicate JSON member')
        result[key] = value
    return result


def parse_pack(data: bytes) -> AliasPack:
    """Validate bounded UTF-8 JSON bytes and return an immutable lookup."""
    if type(data) is not bytes or len(data) > MAX_RESOURCE_BYTES:
        raise AliasPackError('invalid alias resource')
    try:
        doc = json.loads(data.decode('utf-8'), object_pairs_hook=_object,
                         parse_constant=lambda _: (_ for _ in ()).throw(AliasPackError('invalid JSON')))
    except (UnicodeError, ValueError, RecursionError):
        raise AliasPackError('invalid alias resource') from None
    if (type(doc) is not dict or set(doc) != {'schema_version', 'pack_id', 'aliases'}
            or type(doc['schema_version']) is not int or doc['schema_version'] != 1
            or type(doc['pack_id']) is not str or len(doc['pack_id']) > 80
            or not _SLUG.fullmatch(doc['pack_id']) or type(doc['aliases']) is not list
            or not 1 <= len(doc['aliases']) <= MAX_ALIASES):
        raise AliasPackError('invalid alias pack')
    entries: dict[str, str] = {}
    for entry in doc['aliases']:
        if (type(entry) is not dict or set(entry) != {'name', 'role', 'group'}
                or type(entry['role']) is not str or entry['role'] not in ROLES
                or type(entry['group']) is not str or entry['group'] not in GROUPS):
            raise AliasPackError('invalid alias entry')
        key = normalize_key(entry['name'])
        if key in entries:
            raise AliasPackError('conflicting alias')
        entries[key] = entry['role']
    return AliasPack((doc['pack_id'],), MappingProxyType(entries))


def merge_packs(*packs: AliasPack) -> AliasPack:
    if not 1 <= len(packs) <= MAX_PACKS:
        raise AliasPackError('invalid pack count')
    ids: list[str] = []
    aliases: dict[str, str] = {}
    for pack in packs:
        if type(pack) is not AliasPack or set(ids).intersection(pack.pack_ids):
            raise AliasPackError('conflicting pack')
        ids.extend(pack.pack_ids)
        if len(ids) > MAX_PACKS or len(aliases) + len(pack.aliases) > MAX_ALIASES:
            raise AliasPackError('pack limit exceeded')
        if aliases.keys() & pack.aliases.keys():
            raise AliasPackError('conflicting alias')
        aliases.update(pack.aliases)
    return AliasPack(tuple(ids), MappingProxyType(aliases))


def load_pack(package: str, resource: str) -> AliasPack:
    """Load one explicitly named resource inside an importable package."""
    if (type(package) is not str or len(package) > 200
            or not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', package, re.ASCII)
            or type(resource) is not str or len(resource) > 128):
        raise AliasPackError('invalid resource address')
    if not _COMPONENT.fullmatch(resource) or not resource.endswith('.json') or resource in {'.', '..'}:
        raise AliasPackError('invalid resource address')
    try:
        target = resources.files(package).joinpath(resource)
        with target.open('rb') as handle:
            data = handle.read(MAX_RESOURCE_BYTES + 1)
    except (OSError, ModuleNotFoundError, ImportError, TypeError, AttributeError, ValueError):
        raise AliasPackError('alias resource unavailable') from None
    return parse_pack(data)


def load_packs(package: str, names: tuple[str, ...]) -> AliasPack:
    if type(names) is not tuple or not 1 <= len(names) <= MAX_PACKS:
        raise AliasPackError('invalid pack count')
    return merge_packs(*(load_pack(package, name) for name in names))
