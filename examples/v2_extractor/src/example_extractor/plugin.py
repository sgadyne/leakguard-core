"""Example ExtractorV2 package; its wire format is intentionally tiny."""
from collections.abc import Mapping

from leakguard_core.extraction import Extraction, ExtractedPart, ExtractionContext
from leakguard_core.plugins import API_VERSION, OptionSchema, PluginManifest


API_VERSION = 2
MANIFEST = PluginManifest(
    id="example-demo-note",
    implementation_version="1.0.0",
    kind="extractor",
    rules=(),
    formats=("demo-note",),
    part_kinds=("note",),
    options_schema=OptionSchema(fields=()),
    dependencies=(),
    deterministic=True,
    external_state="none",
)


class ExampleExtractor:
    def extract(self, data: bytes, context: ExtractionContext) -> Extraction:
        del context
        prefix = b"LGNOTE\n"
        if not data.startswith(prefix):
            return Extraction(disposition="unsupported", parts=())
        try:
            text = data[len(prefix):].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return Extraction(disposition="no-text", parts=())
        return Extraction(
            disposition="extracted",
            parts=(ExtractedPart(kind="note", ordinal=1, text=text),),
        )


def create_plugin(options: Mapping[str, object]) -> ExampleExtractor:
    if options:
        raise ValueError("example extractor accepts no options")
    return ExampleExtractor()
