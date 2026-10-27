"""DetectorV2 wrapper for explicitly bundled credential rules."""
from collections.abc import Mapping

from leakguard_core.models import AnalysisMetadata
from leakguard_core.plugins import DetectionContext, DistributionSpec, NewFinding, OptionSchema, PluginManifest, RuleSpec

from .aliases import load_packs
from .engine import RULES, scan_fields
from .http import scan_http

API_VERSION = 2
MANIFEST = PluginManifest(
    id='credential-detector', implementation_version='0.1.0a2', kind='detector',
    rules=tuple(RuleSpec(rule, 'block') for rule in (*RULES.values(), 'credential-http-basic', 'credential-http-bearer')),
    formats=(), part_kinds=(), options_schema=OptionSchema(),
    dependencies=(DistributionSpec('leakguard-credential-detector'), DistributionSpec('leakguard-core')), deterministic=True, external_state='unknown', result_schema=2,
)
DEFAULT_RESOURCES = tuple(name + '.json' for name in (
    'common', 'cloud', 'developer-ci', 'data-messaging', 'saas-ai', 'key-material'))


class CredentialDetector:
    def __init__(self):
        self.pack = load_packs('credential_detector.resources', DEFAULT_RESOURCES)

    def detect(self, text: str, context: DetectionContext):
        del context
        spans = sorted((*scan_fields(text, self.pack), *scan_http(text)), key=lambda s: (s.start, s.end, s.rule))
        # Calculate line numbers in one pass instead of repeatedly scanning input.
        line, position = 1, 0
        for span in spans:
            line += text.count('\n', position, span.start)
            position = span.start
            yield NewFinding(rule=span.rule, line=line, severity='block', analysis=AnalysisMetadata(
                schema_version=1, start=span.start, end=span.end, entity_type=span.rule,
                score=None, recognizer_id=span.rule, analyzer_id='credential-detector',
                analyzer_version='0.1.0a2', model_id='none'))


def create_plugin(options: Mapping[str, object]) -> CredentialDetector:
    if type(options) is not dict or options:
        raise ValueError('invalid options')
    return CredentialDetector()
