"""LeakGuard's small contextual sensitive-information detector."""

from .plugin import API_VERSION, MANIFEST, SensitiveBasicsDetector, create_plugin

__all__ = ["API_VERSION", "MANIFEST", "SensitiveBasicsDetector", "create_plugin"]
