"""Explicitly loaded trusted plugins. No automatic discovery or network installation."""
from dataclasses import dataclass
import importlib
import re

API_VERSION = 1


class PluginError(RuntimeError):
    pass


@dataclass(frozen=True)
class Finding:
    rule: str
    line: int
    severity: str = 'review'


def load(specifications):
    loaded = []
    for spec in specifications:
        try:
            module = importlib.import_module(spec['module'])
            if module.API_VERSION != API_VERSION:
                raise PluginError('Plugin API version mismatch')
            instance = module.create_plugin(dict(spec.get('options', {})))
            if not callable(getattr(instance, 'detect', None)):
                raise PluginError('Plugin must implement detect')
            loaded.append(instance)
        except Exception:
            # Plugin exceptions may contain sensitive input: never echo their text.
            raise PluginError('Configured plugin could not be loaded') from None
    return loaded


def detect(instances, text, path, part):
    for instance in instances:
        try:
            for item in instance.detect(text, path, part):
                if type(item) is not Finding or not re.fullmatch('[a-z][a-z0-9-]{0,79}', item.rule):
                    raise PluginError('Invalid plugin result')
                if type(item.line) is not int or not 1 <= item.line <= text.count('\n') + 1:
                    raise PluginError('Invalid plugin line')
                if item.severity not in {'block', 'review'}:
                    raise PluginError('Plugins cannot waive other findings')
                yield item
        except Exception:
            raise PluginError('Configured plugin failed or returned invalid findings') from None


def extract(instances, data, path):
    for instance in instances:
        method = getattr(instance, 'extract', None)
        if method is None:
            continue
        try:
            result = method(data, path)
            if result is None:
                continue
            parts = []; total = 0
            for name, text in result:
                if not isinstance(name, str) or not isinstance(text, str) or len(name) > 200:
                    raise PluginError('Invalid extraction result')
                total += len(text.encode('utf-8'))
                if total > 12_000_000 or len(parts) >= 1000:
                    raise PluginError('Extraction limit exceeded')
                parts.append((name, text))
            return parts
        except Exception:
            raise PluginError('Configured extractor failed or exceeded limits') from None
    return None
