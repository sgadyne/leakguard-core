"""DetectorV2 wrapper for explicitly bundled credential rules."""
from collections.abc import Mapping
import json

from leakguard_core.models import AnalysisMetadata
from leakguard_core.plugins import DetectionContext, DistributionSpec, NewFinding, OptionSchema, OptionSpec, PluginManifest, RuleSpec

from .aliases import load_packs, parse_pack, merge_packs
from .engine import RULES, scan_fields, scan_contextual
from .http import scan_http

API_VERSION = 2
MANIFEST = PluginManifest(
    id='credential-detector', implementation_version='0.1.0a4', kind='detector',
    rules=tuple(RuleSpec(rule, 'review' if rule == 'credential-http-bearer' else 'block') for rule in (*RULES.values(), 'credential-http-basic', 'credential-http-bearer')),
    formats=(), part_kinds=(), options_schema=OptionSchema((OptionSpec('aliases', 'list', default=[], max_length=128),)),
    dependencies=(DistributionSpec('leakguard-credential-detector'), DistributionSpec('leakguard-core')), deterministic=True, external_state='none', result_schema=2,
)
DEFAULT_RESOURCES = tuple(name + '.json' for name in (
    'common', 'cloud', 'developer-ci', 'data-messaging', 'saas-ai', 'key-material'))


class CredentialDetector:
    def __init__(self, aliases=()):
        self.pack = load_packs('credential_detector.resources', DEFAULT_RESOURCES)
        if aliases:
            entries = []
            for item in aliases:
                if type(item) is not str or item.count(':') != 1:
                    raise ValueError('invalid aliases')
                name, role = item.split(':')
                entries.append({'name': name, 'role': role, 'group': 'common'})
            extra = parse_pack(json.dumps({'schema_version': 1, 'pack_id': 'configured-aliases', 'aliases': entries}).encode())
            self.pack = merge_packs(self.pack, extra)

    def detect(self, text: str, context: DetectionContext):
        spans = sorted((*scan_fields(text, self.pack, logical_path=context.logical_path), *scan_http(text), *scan_contextual(text)), key=lambda s: (s.start, s.end, s.rule))
        # Calculate line numbers in one pass instead of repeatedly scanning input.
        line, position = 1, 0
        for span in spans:
            line += text.count('\n', position, span.start)
            position = span.start
            yield NewFinding(rule=span.rule, line=line, severity=span.severity, analysis=AnalysisMetadata(
                schema_version=1, start=span.start, end=span.end, entity_type=span.rule,
                score=None, recognizer_id=span.rule, analyzer_id='credential-detector',
                analyzer_version='0.1.0a4', model_id='none'))


def create_plugin(options: Mapping[str, object]) -> CredentialDetector:
    if type(options) is not dict or set(options) - {'aliases'}:
        raise ValueError('invalid options')
    aliases = options.get('aliases', [])
    if type(aliases) is not list or len(aliases) > 128:
        raise ValueError('invalid aliases')
    return CredentialDetector(aliases)
