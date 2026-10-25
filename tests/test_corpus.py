"""Deterministic synthetic corpus coverage for maintained text surfaces."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import random
import sys
import tempfile
import unittest
import zipfile
import ast

from leakguard_core import engine, models
from leakguard_core.extraction import extract
from leakguard_core import backends, finding_details, plugins


SEED = int(os.environ.get("LEAKGUARD_CORPUS_SEED", "20261025"))
CATALOG_PATH = Path(__file__).with_name("fixtures") / "corpus_catalog.json"
_CATALOG_DOC = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
CASE_CATALOG = tuple(_CATALOG_DOC["cases"])


def _pdf_with_text(text: str) -> bytes:
    try:
        from pypdf import PdfWriter
        from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject
    except ImportError:
        raise unittest.SkipTest("optional pypdf is unavailable")
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = writer._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"),
    }))
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font}),
    })
    stream = DecodedStreamObject()
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream.set_data(("BT /F1 12 Tf 72 720 Td (" + escaped + ") Tj ET").encode("ascii"))
    page[NameObject("/Contents")] = writer._add_object(stream)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def _directory_entry(name: str, object_type: int, *, left=0xFFFFFFFF,
                     right=0xFFFFFFFF, child=0xFFFFFFFF,
                     start=0xFFFFFFFE, size=0) -> bytes:
    entry = bytearray(128)
    encoded = (name + "\0").encode("utf-16le")
    if len(encoded) > 64:
        raise ValueError("CFB name too long")
    entry[:len(encoded)] = encoded
    entry[64:66] = len(encoded).to_bytes(2, "little")
    entry[66] = object_type
    entry[67] = 1  # black node in the directory red-black tree
    entry[68:72] = left.to_bytes(4, "little")
    entry[72:76] = right.to_bytes(4, "little")
    entry[76:80] = child.to_bytes(4, "little")
    entry[116:120] = start.to_bytes(4, "little")
    entry[120:128] = size.to_bytes(8, "little")
    return bytes(entry)


def _cfb_with_streams(streams: tuple[tuple[str, bytes], ...]) -> bytes:
    """Build a small CFB v3 file with regular-sector streams (no mini-FAT)."""
    sector_size = 512
    if any(len(data) < 4096 for _name, data in streams):
        raise ValueError("fixture streams must use regular CFB sectors")
    directory_sector = 1
    next_sector = 2
    chains = []
    for _name, data in streams:
        count = (len(data) + sector_size - 1) // sector_size
        chains.append((next_sector, count))
        next_sector += count
    sector_count = next_sector
    if sector_count > 127:
        raise ValueError("fixture exceeds one FAT sector")

    directory = bytearray(sector_size)
    root_child = 1 if streams else 0xFFFFFFFF
    directory[:128] = _directory_entry("Root Entry", 5, child=root_child)
    for index, ((name, data), (start, count)) in enumerate(zip(streams, chains), start=1):
        right = index + 1 if index < len(streams) else 0xFFFFFFFF
        directory[index * 128:(index + 1) * 128] = _directory_entry(
            name, 2, right=right, start=start, size=len(data),
        )

    fat = [0xFFFFFFFF] * 128
    fat[0] = 0xFFFFFFFD  # FAT sector
    fat[directory_sector] = 0xFFFFFFFE
    stream_sectors = []
    for start, count in chains:
        for offset in range(count):
            sector_id = start + offset
            fat[sector_id] = sector_id + 1 if offset + 1 < count else 0xFFFFFFFE
            stream_sectors.append(sector_id)
    fat_sector = b"".join(value.to_bytes(4, "little") for value in fat)

    header = bytearray(512)
    header[:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    header[24:26] = (0x003E).to_bytes(2, "little")
    header[26:28] = (3).to_bytes(2, "little")
    header[28:30] = (0xFFFE).to_bytes(2, "little")
    header[30:32] = (9).to_bytes(2, "little")
    header[32:34] = (6).to_bytes(2, "little")
    header[40:44] = (0).to_bytes(4, "little")  # v3 directory sector count
    header[44:48] = (1).to_bytes(4, "little")  # FAT sector count
    header[48:52] = directory_sector.to_bytes(4, "little")
    header[56:60] = (4096).to_bytes(4, "little")
    header[60:64] = (0xFFFFFFFE).to_bytes(4, "little")
    header[64:68] = (0).to_bytes(4, "little")
    header[68:72] = (0xFFFFFFFE).to_bytes(4, "little")
    header[72:76] = (0).to_bytes(4, "little")
    header[76:80] = (0).to_bytes(4, "little")
    header[76:80] = (0).to_bytes(4, "little")
    for index in range(109):
        offset = 76 + index * 4
        header[offset:offset + 4] = (0 if index == 0 else 0xFFFFFFFF).to_bytes(4, "little")

    payloads = [data.ljust(((len(data) + sector_size - 1) // sector_size) * sector_size, b"\0")
                for _name, data in streams]
    return bytes(header) + fat_sector + bytes(directory) + b"".join(payloads)


def _msg_fixture(*, subject_text="synthetic subject", body_text="first body line\nsecond body line") -> bytes:
    subject = (subject_text + " " + "s" * 4100).encode("cp1252")
    body = (body_text + "\n" + "b" * 2050).encode("utf-16le") + b"\0\0"
    return _cfb_with_streams((
        ("__substg1.0_0037001E", subject),
        ("__substg1.0_1000001F", body),
    ))


class DeterministicCorpusTests(unittest.TestCase):
    def test_seeded_label_manifest_is_repeatable(self):
        def manifest(seed):
            rng = random.Random(seed)
            labels = ["multiline", "utf16", "unusual-extension", "duplicate-json", "ast-proof", "plugin-collision"]
            return [(label, hashlib.sha256(bytes(rng.randrange(256) for _ in range(32))).hexdigest())
                    for label in labels]
        self.assertEqual(manifest(SEED), manifest(SEED))
        self.assertNotEqual(manifest(SEED), manifest(SEED + 1))

    def test_catalog_has_at_least_32_static_cases_and_marks_uncovered_formats(self):
        self.assertGreaterEqual(len(CASE_CATALOG), 32)
        self.assertEqual(len({item["case_id"] for item in CASE_CATALOG}), len(CASE_CATALOG))
        uncovered = {item["case_id"] for item in CASE_CATALOG if item["state"] == "uncovered"}
        self.assertEqual(uncovered, {"office-sheet-uncovered", "office-slides-uncovered"})

    def test_actual_labeled_cases_emit_case_level_counts_without_fixture_text(self):
        summary = run_labeled_corpus(SEED, engine.EXE)
        self.assertEqual(summary["counts"]["labeled_cases"], len(CASE_CATALOG))
        self.assertEqual(summary["counts"]["uncovered"], 2)
        self.assertEqual(summary["counts"]["failed"], 0, summary)
        self.assertEqual(set(summary["by_category"]), {item["category"] for item in CASE_CATALOG})
        encoded = json.dumps(summary, sort_keys=True)
        self.assertNotIn("SyntheticOnly~", encoded)
        self.assertIn("true_positive", summary["detector_metrics"])

    def test_pdf_fixture_is_parsed_as_a_real_text_document(self):
        payload = _pdf_with_text("Synthetic PDF marker line")
        self.assertTrue(payload.startswith(b"%PDF-"))
        result = extract(payload, "opaque-extension.data", timeout=5)
        self.assertEqual(result.format_id, "pdf-text")
        self.assertEqual(result.disposition, "extracted")
        self.assertEqual([part.part_id for part in result.parts], ["pdf-page-1"])
        self.assertIn("Synthetic PDF marker line", result.parts[0].text)

    @unittest.skipUnless(importlib.util.find_spec("olefile"), "optional olefile is unavailable")
    def test_msg_fixture_parses_real_compound_streams_and_cp1252(self):
        payload = _msg_fixture()
        result = extract(payload, "mail.msg", timeout=5)
        self.assertEqual(result.format_id, "outlook-msg")
        self.assertEqual(result.disposition, "extracted")
        parts = {part.part_id: part.text for part in result.parts}
        self.assertIn("msg-subject-1", parts)
        self.assertIn("msg-body-1", parts)
        self.assertTrue(parts["msg-subject-1"].startswith("synthetic subject "))
        self.assertTrue(parts["msg-body-1"].startswith("first body line\nsecond body line\n"))

    @unittest.skipUnless(importlib.util.find_spec("olefile"), "optional olefile is unavailable")
    def test_unknown_compound_document_remains_an_explicit_omission(self):
        payload = _cfb_with_streams(())
        self.assertTrue(payload.startswith(bytes.fromhex("D0CF11E0A1B11AE1")))
        result = extract(payload, "unlabelled.bin", timeout=5)
        self.assertEqual((result.disposition, result.issues), ("unsupported", ("unsupported-format",)))

    def test_multiline_parts_preserve_boundaries_and_static_labels(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("word/document.xml", "<d><p>prefix BEGIN</p><p>first line</p></d>")
            archive.writestr("word/comments1.xml", "<c><p>SECRET suffix</p><p>last line</p></c>")
        result = extract(buffer.getvalue(), "odd name/é\nrenamed.document", timeout=5)
        self.assertEqual(result.disposition, "extracted")
        self.assertEqual([part.part_id for part in result.parts], ["office-word-1", "office-word-2"])
        self.assertEqual(result.parts[0].text, "prefix BEGIN\nfirst line")
        self.assertEqual(result.parts[1].text, "SECRET suffix\nlast line")


class PluginCollisionTests(unittest.TestCase):
    def test_colliding_plugin_rules_cannot_downgrade_a_block_finding(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-plugin-collision-") as temporary:
            root = Path(temporary)
            files = {
                "collision_block.py": '''from leakguard_core.plugins import Finding, PluginManifest, RuleSpec\nAPI_VERSION=2\nMANIFEST=PluginManifest(id="collision-block", implementation_version="1", kind="detector", rules=(RuleSpec("shared-finding", "block"),), formats=("text",), part_kinds=("text",))\nclass Detector:\n def detect(self,text,context): return [Finding("shared-finding",1,"block")]\ndef create_plugin(options): return Detector()\n''',
                "collision_review.py": '''from leakguard_core.plugins import Finding, PluginManifest, RuleSpec\nAPI_VERSION=2\nMANIFEST=PluginManifest(id="collision-review", implementation_version="1", kind="detector", rules=(RuleSpec("shared-finding", "review"),), formats=("text",), part_kinds=("text",))\nclass Detector:\n def detect(self,text,context): return [Finding("shared-finding",1,"review")]\ndef create_plugin(options): return Detector()\n''',
            }
            for name, content in files.items():
                (root / name).write_text(content, encoding="utf-8")
            sys.path.insert(0, temporary)
            service = None
            try:
                service = engine.ScanService({
                    "gitleaks_executable": str(engine.EXE),
                    "gitleaks_config": str(engine.RULES),
                    "plugins": [
                        {"module": "collision_block", "options": {}},
                        {"module": "collision_review", "options": {}},
                    ],
                })
                report = service.scan(
                    [models.BytesInput(b"ordinary fixture", "collision.txt")],
                    policy=models.ScanPolicy.inventory(),
                    limits=models.ScanLimits(20, 4), use_cache=False,
                )
            finally:
                if service is not None:
                    service.close()
                sys.path.remove(temporary)
        findings = [finding for result in report.results for finding in result.findings]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "shared-finding")
        self.assertEqual(findings[0].severity, models.FindingSeverity.BLOCK)


def _seeded_secret(seed: int) -> str:
    return "SyntheticOnly~" + hashlib.sha256(str(seed).encode("ascii")).hexdigest()[:32]


def _line_number(text: str, value: str) -> int:
    return text[:text.index(value)].count("\n") + 1


def _docx_parts(members) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in members:
            archive.writestr(name, "<d><p>" + text + "</p></d>")
    return buffer.getvalue()


def run_labeled_corpus(seed: int, gitleaks: str | os.PathLike[str]) -> dict:
    """Execute each declared fixture and return only closed labels/counts/hashes."""
    catalog = {item["case_id"]: item for item in CASE_CATALOG}
    secret = _seeded_secret(seed)
    results = {}

    def put(case_id, actual, *, coverage="complete", digest_input=b""):
        item = catalog[case_id]
        if item["state"] == "uncovered":
            results[case_id] = {"actual": "uncovered", "coverage": "uncovered",
                                "status": "uncovered", "artifact_sha256": None}
            return
        expected = item["expected"]
        passed = expected == actual
        results[case_id] = {"actual": actual, "coverage": coverage,
                            "status": "passed" if passed else "failed",
                            "artifact_sha256": hashlib.sha256(digest_input).hexdigest()}

    # Exact placeholders and intentionally weak values are separate labeled
    # detector cases; line mapping lets one bounded backend request exercise them.
    client_placeholders = (
        "your-client-secret", "example-client-secret", "placeholder-value",
        "test-secret-placeholder", "YOUR-CLIENT-SECRET", "Example-Client-Secret",
        "PLACEHOLDER-VALUE", "TEST-SECRET-PLACEHOLDER",
    )
    password_placeholders = (
        "${password}", "%password%", "<password>", "<redacted>",
        "placeholder-value", "your-password",
    )
    weak_client = ("short", "1234567890123456789", "tiny-value")
    weak_password = ("short", "1234567", "x")
    detector_cases = []
    for index, value in enumerate(client_placeholders, 1):
        case_id = f"placeholder-client-secret-{index:02d}"
        detector_cases.append((case_id, f'client_secret = "{value}"', "none"))
    for index, value in enumerate(password_placeholders, 1):
        case_id = f"placeholder-password-{index:02d}"
        detector_cases.append((case_id, f'password = "{value}"', "none"))
    for index, value in enumerate(weak_client, 1):
        case_id = f"weak-client-secret-{index:02d}"
        detector_cases.append((case_id, f'client_secret = "{value}"', "none"))
    for index, value in enumerate(weak_password, 1):
        case_id = f"weak-password-{index:02d}"
        detector_cases.append((case_id, f'password = "{value}"', "none"))
    detector_cases.extend((
        ("literal-client-secret-positive-01", f'client_secret = "{secret}"', "finding"),
        ("literal-password-positive-01", f'password = "{secret}"', "finding"),
    ))
    detector_text = "\n".join(row[1] for row in detector_cases)
    findings = backends.detect(detector_text, binary=gitleaks,
                               rules=Path(__file__).parents[1] / "src" / "leakguard_core" / "rules.toml",
                               timeout=15)
    found_lines = {item.start_line for item in findings}
    for line, (case_id, value, _expected) in enumerate(detector_cases, 1):
        put(case_id, "finding" if line in found_lines else "none", digest_input=value.encode("utf-8"))

    # Version-bound provider and function-AST proofs; wrong hashes, absent
    # source, changed source and duplicate JSON keys always remain heuristic.
    source = b"def Token():\n    return 'synthetic'\n"
    source_hash = hashlib.sha256(source).hexdigest()
    provider_rows = (
        ("provider-hash-valid", {"source_fingerprints": {"module.py": source_hash}}, source),
        ("provider-hash-wrong", {"source_fingerprints": {"module.py": "0" * 64}}, source),
        ("provider-hash-missing-source", {"source_fingerprints": {"module.py": source_hash}}, None),
    )
    for case_id, value, referenced in provider_rows:
        text = json.dumps(value, indent=2)
        marker = source_hash if case_id != "provider-hash-wrong" else "0" * 64
        line = _line_number(text, marker)
        finding = {"path": "origins.json", "line": line, "end_line": line,
                   "rule": "generic-api-key", "severity": "block"}
        reader = lambda _name, referenced=referenced: referenced
        result = finding_details.describe(finding, text.encode("utf-8"), reader)
        actual = "verified-file" if result.get("classification") == "verified-file-sha256" else "heuristic"
        put(case_id, actual, digest_input=text.encode("utf-8"))

    tree = ast.parse(source)
    ast_hash = hashlib.sha256(ast.dump(tree.body[0]).encode()).hexdigest()
    changed_source = b"def Token():\n    return 'changed'\n"
    for case_id, digest, referenced in (
        ("ast-hash-valid", ast_hash, source),
        ("ast-hash-wrong", "0" * 64, source),
        ("ast-source-changed", ast_hash, changed_source),
    ):
        text = json.dumps({"scope.py": {"function_ast_sha256": {"Token": digest}}}, indent=2)
        line = _line_number(text, digest)
        finding = {"path": "origins.json", "line": line, "end_line": line,
                   "rule": "generic-api-key", "severity": "block"}
        result = finding_details.describe(finding, text.encode("utf-8"),
                                          lambda _name, referenced=referenced: referenced)
        actual = "verified-ast" if result.get("classification") == "verified-function-ast-sha256" else "heuristic"
        put(case_id, actual, digest_input=text.encode("utf-8"))

    for case_id, text, marker in (
        ("duplicate-json-key", '{"source_fingerprints":{"module.py":"' + source_hash + '","module.py":"' + source_hash + '"}}', source_hash),
        ("duplicate-json-proof-key", '{"scope.py":{"function_ast_sha256":{"Token":"' + ast_hash + '","Token":"' + ast_hash + '"}}}', ast_hash),
    ):
        line = _line_number(text, marker)
        finding = {"path": "origins.json", "line": line, "end_line": line,
                   "rule": "generic-api-key", "severity": "block"}
        result = finding_details.describe(finding, text.encode("utf-8"), lambda _name: source)
        actual = "verified-ast" if result.get("classification") == "verified-function-ast-sha256" else "heuristic"
        put(case_id, actual, digest_input=text.encode("utf-8"))

    def extract_case(case_id, data, path):
        if (case_id.startswith("pdf-") and importlib.util.find_spec("pypdf") is None
                or (case_id.startswith("msg-") or case_id == "unsupported-compound")
                and importlib.util.find_spec("olefile") is None):
            results[case_id] = {"actual": "uncovered", "coverage": "uncovered",
                                "status": "uncovered", "artifact_sha256": hashlib.sha256(data).hexdigest()}
            return
        result = extract(data, path, timeout=15)
        digest = hashlib.sha256(data).hexdigest()
        if result.disposition == "extracted":
            detected = any(backends.detect(part.text, binary=gitleaks,
                                           rules=Path(__file__).parents[1] / "src" / "leakguard_core" / "rules.toml",
                                           timeout=15) for part in result.parts)
            actual = "finding" if detected else "none"
            coverage = "complete"
        elif result.disposition in {"unsupported", "no-text", "encrypted"}:
            actual, coverage = "omission", "omitted"
        else:
            actual, coverage = "incomplete", "incomplete"
        put(case_id, actual, coverage=coverage, digest_input=data)

    extract_case("utf16-text-positive", b"\xff\xfe" + f'client_secret = "{secret}"'.encode("utf-16le"), "input.txt")
    extract_case("unusual-extension-positive", f'client_secret = "{secret}"'.encode(), "input.odd")
    office_document = _docx_parts((("word/document.xml", f'client_secret = "{secret}"'),))
    office_comment = _docx_parts((("word/document.xml", "ordinary document text"),
                                  ("word/comments1.xml", f'client_secret = "{secret}"')))
    malformed = io.BytesIO()
    with zipfile.ZipFile(malformed, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
    extract_case("office-word-document", office_document, "fixture.docx")
    extract_case("office-word-comments", office_comment, "fixture.docx")
    extract_case("office-word-malformed", malformed.getvalue(), "fixture.docx")

    try:
        pdf_text = _pdf_with_text(f'client_secret = "{secret}"')
        from pypdf import PdfWriter
        empty_writer = PdfWriter(); empty_writer.add_blank_page(width=612, height=792)
        pdf_empty_buffer = io.BytesIO(); empty_writer.write(pdf_empty_buffer)
        extract_case("pdf-text-positive", pdf_text, "fixture.pdf")
        extract_case("pdf-image-only", pdf_empty_buffer.getvalue(), "fixture.pdf")
    except (ImportError, unittest.SkipTest):
        for case_id in ("pdf-text-positive", "pdf-image-only"):
            results[case_id] = {"actual": "uncovered", "coverage": "uncovered",
                                "status": "uncovered", "artifact_sha256": None}
    msg_subject = f'client_secret = "{secret}"'
    msg_body = f'client_secret = "{secret}"'
    try:
        extract_case("msg-subject-positive", _msg_fixture(subject_text=msg_subject), "fixture.msg")
        extract_case("msg-body-positive", _msg_fixture(body_text=msg_body), "fixture.msg")
        extract_case("unsupported-compound", _cfb_with_streams(()), "unlabelled.bin")
    except ImportError:
        for case_id in ("msg-subject-positive", "msg-body-positive", "unsupported-compound"):
            results[case_id] = {"actual": "uncovered", "coverage": "uncovered",
                                "status": "uncovered", "artifact_sha256": None}

    parts = (
        ("part-boundary-first", (("word/document.xml", f'client_secret = "{secret}"'),), "finding"),
        ("part-boundary-second", (("word/document.xml", "ordinary text"),
                                   ("word/comments1.xml", f'client_secret = "{secret}"')), "finding"),
        ("part-boundary-no-cross-match", (("word/document.xml", 'client_secret = "SyntheticOnly~'),
                                          ("word/comments1.xml", 'CorpusSecretTail"')), "none"),
    )
    for case_id, members, _expected in parts:
        extract_case(case_id, _docx_parts(members), "odd name/é\nfixture.document")

    # Each declaration executes in a supervised worker. The pairwise collision
    # then verifies that merge arbitration keeps the stronger block severity.
    policy_id = None
    runtime_id = None
    with tempfile.TemporaryDirectory(prefix="leakguard-corpus-plugin-") as temporary:
        root = Path(temporary)
        definitions = {
            "corpus_block.py": '''from leakguard_core.plugins import Finding, PluginManifest, RuleSpec\nAPI_VERSION=2\nMANIFEST=PluginManifest(id="corpus-block",implementation_version="1",kind="detector",rules=(RuleSpec("shared-marker","block"),),formats=("text",),part_kinds=("text",))\nclass Detector:\n def detect(self,text,context): return [Finding("shared-marker",1,"block")]\ndef create_plugin(options): return Detector()\n''',
            "corpus_review.py": '''from leakguard_core.plugins import Finding, PluginManifest, RuleSpec\nAPI_VERSION=2\nMANIFEST=PluginManifest(id="corpus-review",implementation_version="1",kind="detector",rules=(RuleSpec("shared-marker","review"),),formats=("text",),part_kinds=("text",))\nclass Detector:\n def detect(self,text,context): return [Finding("shared-marker",1,"review")]\ndef create_plugin(options): return Detector()\n''',
        }
        for name, source_text in definitions.items():
            (root / name).write_text(source_text, encoding="utf-8")
        sys.path.insert(0, temporary)
        try:
            loaded = [plugins.load([{"module": module, "options": {}}])[0]
                      for module in ("corpus_block", "corpus_review")]
            for case_id, handle, expected in zip(
                ("plugin-collision-block", "plugin-collision-review"), loaded, ("block", "review")
            ):
                observed = tuple(plugins.detect([handle], "fixture", "fixture.txt", "text", timeout=15))
                actual = observed[0].severity if observed else "none"
                put(case_id, actual, digest_input=definitions["corpus_block.py" if expected == "block" else "corpus_review.py"].encode())
            service = engine.ScanService({
                "gitleaks_executable": str(gitleaks),
                "gitleaks_config": str(Path(__file__).parents[1] / "src" / "leakguard_core" / "rules.toml"),
                "plugins": [{"module": "corpus_block", "options": {}},
                            {"module": "corpus_review", "options": {}}],
            })
            try:
                report = service.scan([models.BytesInput(b"fixture", "collision.txt")],
                                      policy=models.ScanPolicy.inventory(),
                                      limits=models.ScanLimits(30, 2), use_cache=False)
                policy_id = report.policy_id
                runtime_id = report.results[0].identity.runtime_id if report.results else None
                merged = [finding for result in report.results for finding in result.findings]
                if len(merged) != 1 or merged[0].severity is not models.FindingSeverity.BLOCK:
                    results["plugin-collision-block"]["status"] = "failed"
                    results["plugin-collision-review"]["status"] = "failed"
            finally:
                service.close()
        finally:
            sys.path.remove(temporary)

    for item in CASE_CATALOG:
        if item["state"] == "uncovered":
            put(item["case_id"], "uncovered", coverage="uncovered")
    for item in CASE_CATALOG:
        if item["case_id"] not in results:
            put(item["case_id"], "uncovered", coverage="uncovered")

    counts = {"labeled_cases": len(CASE_CATALOG), "covered": 0, "uncovered": 0, "failed": 0,
              "true_positive": 0, "false_positive": 0, "false_negative": 0, "true_negative": 0}
    by_category = {}
    for item in CASE_CATALOG:
        case_id, category = item["case_id"], item["category"]
        result = results[case_id]
        bucket = by_category.setdefault(category, {"cases": 0, "covered": 0, "uncovered": 0, "failed": 0})
        bucket["cases"] += 1
        if result["status"] == "uncovered":
            counts["uncovered"] += 1; bucket["uncovered"] += 1
            continue
        counts["covered"] += 1; bucket["covered"] += 1
        if result["status"] == "failed":
            counts["failed"] += 1; bucket["failed"] += 1
        if item["kind"] in {"detector", "extractor"} and item["expected"] in {"finding", "none"}:
            expected_positive = item["expected"] == "finding"
            actual_positive = result["actual"] == "finding"
            key = ("true_positive" if expected_positive else "false_positive") if actual_positive else ("false_negative" if expected_positive else "true_negative")
            counts[key] += 1
    return {"seed": seed, "policy_id": policy_id, "runtime_id": runtime_id,
            "counts": counts, "detector_metrics": {
                key: counts[key] for key in ("true_positive", "false_positive", "false_negative", "true_negative")
            }, "by_category": by_category,
            "cases": [{"case_id": item["case_id"], "category": item["category"],
                       **results[item["case_id"]]} for item in CASE_CATALOG]}


if __name__ == "__main__":
    unittest.main(verbosity=2)
