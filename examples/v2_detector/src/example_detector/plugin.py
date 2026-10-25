"""Example DetectorV2 package. The marker is deliberately synthetic."""
from collections.abc import Iterable, Mapping

from leakguard_core.plugins import (
    API_VERSION,
    DetectionContext,
    Finding,
    OptionSchema,
    PluginManifest,
    RuleSpec,
)


API_VERSION = 2
MANIFEST = PluginManifest(
    id="example-firm-marker",
    implementation_version="1.0.0",
    kind="detector",
    rules=(RuleSpec(id="example-firm-marker", minimum_severity="review"),),
    formats=("text",),
    part_kinds=("text",),
    options_schema=OptionSchema(fields=()),
    dependencies=(),
    deterministic=True,
    external_state="none",
)


class ExampleDetector:
    def detect(self, text: str, context: DetectionContext) -> Iterable[Finding]:
        del context
        for line_number, line in enumerate(text.splitlines(), start=1):
            if "FIRM-DEMO-MARKER" in line:
                yield Finding(rule="example-firm-marker", line=line_number, severity="review")


def create_plugin(options: Mapping[str, object]) -> ExampleDetector:
    if options:
        raise ValueError("example detector accepts no options")
    return ExampleDetector()
