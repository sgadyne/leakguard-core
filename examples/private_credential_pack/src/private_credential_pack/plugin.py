"""Private field label using the shared engine and the existing DetectorV2 seam."""
from collections.abc import Mapping

from credential_detector.aliases import load_pack
from credential_detector.engine import scan_fields
from leakguard_core.models import AnalysisMetadata
from leakguard_core.plugins import DistributionSpec, NewFinding, OptionSchema, PluginManifest, RuleSpec

API_VERSION = 2
MANIFEST = PluginManifest(
    id='private-credential-example', implementation_version='0.1.0', kind='detector',
    rules=(RuleSpec('credential-api-key', 'block'),), formats=('text',), part_kinds=('text',),
    options_schema=OptionSchema(), dependencies=(DistributionSpec('leakguard-core'), DistributionSpec('leakguard-credential-detector'),
                  DistributionSpec('leakguard-private-credential-example')),
    deterministic=True, external_state='unknown', result_schema=2,
)


class PrivateCredentialDetector:
    def __init__(self):
        self.pack = load_pack('private_credential_pack', 'aliases.json')

    def detect(self, text, context):
        del context
        line, position = 1, 0
        for span in scan_fields(text, self.pack):
            line += text.count('\n', position, span.start)
            position = span.start
            yield NewFinding(rule=span.rule, line=line, severity='block', analysis=AnalysisMetadata(
                schema_version=1, start=span.start, end=span.end, entity_type=span.rule,
                score=None, recognizer_id=span.rule, analyzer_id='private-credential-example',
                analyzer_version='0.1.0', model_id='none'))


def create_plugin(options: Mapping[str, object]) -> PrivateCredentialDetector:
    if type(options) is not dict or options:
        raise ValueError('invalid options')
    return PrivateCredentialDetector()
