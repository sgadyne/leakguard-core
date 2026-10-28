"""Metadata-only discovery policy for opaque credential stores."""
from pathlib import PurePath
import re


_FIREFOX_LOGINS = re.compile(r'logins(?:-backup)?\.json(?:\.(?:bak|backup|old|corrupt)(?:-\d+)?)?\Z', re.I)


def protected_store(path: PurePath, *, remote=False) -> bool:
    """Recognize stores without reading them; ordinary logins.json is content.

    Firefox uses a profile directory below Firefox/Profiles on macOS and
    Windows, or .mozilla/firefox on Linux. LibreWolf has equivalent layouts.
    A filename alone cannot establish that a JSON file is a browser store.
    """
    parts = tuple(part.casefold() for part in path.parts)
    if (path.suffix.lower() in {'.lgv', '.lgo', '.lgbak', '.keychain', '.keychain-db', '.kdbx', '.gpg', '.pgp'}
            or path.name in {'Login Data', 'Cookies', 'Trust Tokens', 'key4.db', 'cert9.db'}
            or any(part.endswith('.lgo.parts') for part in parts)):
        return True
    if remote and (path.suffix.lower() == '.kdb' or '.ssh' in parts and path.name.startswith('id_')):
        return True
    if not _FIREFOX_LOGINS.fullmatch(path.name):
        return False
    parents = parts[:-1]
    return (len(parents) >= 3 and parents[-3:-1] in {('firefox', 'profiles'), ('librewolf', 'profiles')}
            or len(parents) >= 3 and parents[-3:-1] == ('.mozilla', 'firefox')
            or len(parents) >= 2 and parents[-2] == '.librewolf')
