"""Deterministic synthetic corpus coverage for maintained text surfaces."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import random
import re
import sys
import tempfile
import unittest
import zipfile
import ast
from xml.sax.saxutils import escape

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
    import hashlib
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
    from pypdf.generic import ArrayObject, ByteStringObject
    identifier = ByteStringObject(hashlib.sha256(text.encode("utf-8")).digest()[:16])
    writer._ID = ArrayObject((identifier, identifier))
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def _docx_payload(members) -> bytes:
    """Build an Office-shaped ZIP with fixed metadata and stable member order."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, text in members:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            info.compress_type = zipfile.ZIP_STORED
            if name == "[Content_Types].xml":
                xml = "<Types>" + text + "</Types>"
            else:
                paragraphs = text.split("</p><p>")
                xml = "<d>" + "".join(
                    "<p><r><t>" + escape(paragraph) + "</t></r></p>"
                    for paragraph in paragraphs
                ) + "</d>"
            archive.writestr(info, xml)
    return buffer.getvalue()


def _ooxml_payload(members) -> bytes:
    """Build deterministic Office packages with package relationships and XML parts."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, xml in members:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, xml)
    return buffer.getvalue()


def _xlsx_fixture(cells: tuple[tuple[str, ...], ...]) -> bytes:
    cell_xml = []
    for index, fragments in enumerate(cells, 1):
        runs = "".join("<r><t xml:space=\"preserve\">" + escape(fragment) + "</t></r>"
                       for fragment in fragments)
        cell_xml.append(f'<c r="{chr(64 + index)}1" t="inlineStr"><is>{runs}</is></c>')
    worksheet = (
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row r="1">' + "".join(cell_xml) + '</row></sheetData></worksheet>'
    )
    content_types = (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    root_relationships = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    workbook = (
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Synthetic" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    workbook_relationships = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '</Relationships>'
    )
    return _ooxml_payload((
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", root_relationships),
        ("xl/workbook.xml", workbook),
        ("xl/_rels/workbook.xml.rels", workbook_relationships),
        ("xl/worksheets/sheet1.xml", worksheet),
    ))


def _pptx_fixture(paragraphs: tuple[tuple[str, ...], ...]) -> bytes:
    paragraph_xml = []
    for fragments in paragraphs:
        runs = "".join(
            '<a:r><a:rPr lang="en-US"/><a:t xml:space="preserve">'
            + escape(fragment) + '</a:t></a:r>' for fragment in fragments
        )
        paragraph_xml.append('<a:p>' + runs + '<a:endParaRPr lang="en-US"/></a:p>')
    slide = (
        '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<p:cSld><p:spTree><p:nvGrpSpPr/><p:grpSpPr/>'
        '<p:sp><p:nvSpPr><p:cNvPr id="2" name="Text"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>'
        '<p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/>' + "".join(paragraph_xml)
        + '</p:txBody></p:sp></p:spTree></p:cSld></p:sld>'
    )
    content_types = (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
        '<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        '</Types>'
    )
    root_relationships = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>'
        '</Relationships>'
    )
    presentation = (
        '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>'
    )
    presentation_relationships = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>'
        '</Relationships>'
    )
    return _ooxml_payload((
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", root_relationships),
        ("ppt/presentation.xml", presentation),
        ("ppt/_rels/presentation.xml.rels", presentation_relationships),
        ("ppt/slides/slide1.xml", slide),
    ))


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

    def test_catalog_is_versioned_and_every_declared_case_has_a_fixture(self):
        self.assertGreaterEqual(len(CASE_CATALOG), 32)
        self.assertEqual(len({item["case_id"] for item in CASE_CATALOG}), len(CASE_CATALOG))
        uncovered = {item["case_id"] for item in CASE_CATALOG if item["state"] == "uncovered"}
        self.assertEqual(uncovered, set())
        self.assertEqual(_CATALOG_DOC["schema_version"], 3)
        for item in CASE_CATALOG:
            if item["expected"] == "finding":
                self.assertRegex(item.get("expected_rule", ""), r"\A[a-z0-9][a-z0-9_-]{0,79}\Z")
        self.assertEqual(_CATALOG_DOC["seed"], SEED)

    def test_actual_labeled_cases_emit_case_level_counts_without_fixture_text(self):
        summary = run_labeled_corpus(SEED, engine.EXE)
        expected_uncovered = set()
        expected_metric_eligible = 35
        expected_metric_not_scored = 13
        if importlib.util.find_spec("pypdf") is None:
            expected_uncovered.update({"pdf-text-positive", "pdf-image-only"})
            expected_metric_eligible -= 1
            expected_metric_not_scored -= 1
        if importlib.util.find_spec("olefile") is None:
            expected_uncovered.update({"msg-subject-positive", "msg-body-positive", "unsupported-compound"})
            expected_metric_eligible -= 2
            expected_metric_not_scored -= 1
        self.assertEqual(summary["counts"]["labeled_cases"], len(CASE_CATALOG))
        self.assertEqual({item["case_id"] for item in summary["cases"]
                          if item["status"] == "uncovered"}, expected_uncovered)
        self.assertEqual(summary["counts"]["uncovered"], len(expected_uncovered))
        self.assertEqual(summary["counts"]["failed"], 0, summary)
        self.assertEqual(set(summary["by_category"]), {item["category"] for item in CASE_CATALOG})
        encoded = json.dumps(summary, sort_keys=True)
        self.assertNotIn("SyntheticOnly~", encoded)
        self.assertIn("true_positive", summary["detector_metrics"])
        self.assertEqual(summary["counts"]["metric_eligible_cases"], expected_metric_eligible)
        self.assertEqual(summary["counts"]["metric_not_scored_cases"], expected_metric_not_scored)
        metric_names = ("true_positive", "false_positive", "false_negative", "true_negative")
        for metric in metric_names:
            self.assertEqual(
                sum(summary["by_category"][category][metric]
                    for category in summary["by_category"]),
                summary["detector_metrics"][metric],
            )
        for bucket in summary["by_category"].values():
            self.assertEqual(sum(bucket[metric] for metric in metric_names), bucket["metric_eligible"])
        self.assertEqual(sum(summary["detector_metrics"][metric] for metric in metric_names),
                         expected_metric_eligible)
        self.assertEqual(
            summary["detector_metrics"]["by_rule"]["github-pat"],
            {"true_positive": 1, "false_positive": 0, "false_negative": 0},
        )
        provider = next(item for item in summary["cases"]
                        if item["case_id"] == "provider-github-token-positive")
        self.assertEqual(provider["rules"], ["github-pat"])
        self.assertNotIn("ghp_", encoded)

    def test_same_seed_artifact_manifest_is_stable_across_wall_clock_ticks(self):
        import time
        first = run_labeled_corpus(SEED, engine.EXE)
        time.sleep(2.1)
        second = run_labeled_corpus(SEED, engine.EXE)
        first_hashes = {item["case_id"]: item["artifact_sha256"] for item in first["cases"]}
        second_hashes = {item["case_id"]: item["artifact_sha256"] for item in second["cases"]}
        self.assertEqual(first_hashes, second_hashes)
        self.assertEqual(first["by_category"], second["by_category"])

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
        payload = _docx_payload((
            ("word/document.xml", "prefix BEGIN</p><p>first line"),
            ("word/comments1.xml", "SECRET suffix</p><p>last line"),
        ))
        result = extract(payload, "odd name/é\nrenamed.document", timeout=5)
        self.assertEqual(result.disposition, "extracted")
        self.assertEqual([part.part_id for part in result.parts], ["office-word-1", "office-word-2"])
        self.assertEqual(result.parts[0].text, "prefix BEGIN\nfirst line")
        self.assertEqual(result.parts[1].text, "SECRET suffix\nlast line")

    def test_spreadsheet_and_slides_join_formatting_runs_but_preserve_boundaries(self):
        secret = _seeded_secret(SEED)
        text = f'client_secret = "{secret}"'
        split = len("client_se")
        sheet = extract(_xlsx_fixture(((text[:split], text[split:]),)), "fixture.xlsx", timeout=10)
        self.assertEqual((sheet.format_id, sheet.disposition), ("office-sheet", "extracted"))
        self.assertEqual(len(sheet.parts), 1)
        self.assertIn(text, sheet.parts[0].text)
        self.assertTrue(backends.detect(sheet.parts[0].text, binary=engine.EXE,
                                        rules=engine.RULES, timeout=15))

        slides = extract(_pptx_fixture(((text[:split], text[split:]),)), "fixture.pptx", timeout=10)
        self.assertEqual((slides.format_id, slides.disposition), ("office-slides", "extracted"))
        self.assertEqual(len(slides.parts), 1)
        self.assertIn(text, slides.parts[0].text)
        self.assertTrue(backends.detect(slides.parts[0].text, binary=engine.EXE,
                                        rules=engine.RULES, timeout=15))

        cross_cell = _xlsx_fixture((('client_secret = "SyntheticOnly~',), ('CorpusSecretTail"',)))
        cell_result = extract(cross_cell, "fixture.xlsx", timeout=10)
        self.assertEqual(cell_result.disposition, "extracted")
        self.assertFalse(any(backends.detect(part.text, binary=engine.EXE,
                                             rules=engine.RULES, timeout=15)
                             for part in cell_result.parts))

        cross_paragraph = _pptx_fixture((('client_secret = "SyntheticOnly~',), ('CorpusSecretTail"',)))
        paragraph_result = extract(cross_paragraph, "fixture.pptx", timeout=10)
        self.assertEqual(paragraph_result.disposition, "extracted")
        self.assertFalse(any(backends.detect(part.text, binary=engine.EXE,
                                             rules=engine.RULES, timeout=15)
                             for part in paragraph_result.parts))


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
    return _docx_payload(members)


def run_labeled_corpus(seed: int, gitleaks: str | os.PathLike[str]) -> dict:
    """Execute each declared fixture and return only closed labels/counts/hashes."""
    catalog = {item["case_id"]: item for item in CASE_CATALOG}
    secret = _seeded_secret(seed)
    provider_token = "ghp_" + hashlib.sha256(
        f"LeakGuard synthetic provider token {seed}".encode("ascii")).hexdigest()[:36]
    results = {}

    def put(case_id, actual, *, coverage="complete", digest_input=b"", rules=()):
        item = catalog[case_id]
        if any(type(rule) is not str or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", rule) is None
               for rule in rules):
            raise ValueError("invalid static detector rule id")
        rule_names = sorted(set(rules))
        if item["state"] == "uncovered":
            results[case_id] = {"actual": "uncovered", "coverage": "uncovered",
                                "status": "uncovered", "artifact_sha256": None, "rules": []}
            return
        expected = item["expected"]
        expected_rule = item.get("expected_rule")
        if (expected == "finding" and expected_rule is not None
                and (type(expected_rule) is not str
                     or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", expected_rule) is None)):
            raise ValueError("invalid expected detector rule id")
        rule_matches = expected != "finding" or expected_rule is None or expected_rule in rule_names
        passed = expected == actual and rule_matches
        results[case_id] = {"actual": actual, "coverage": coverage,
                            "status": "passed" if passed else "failed",
                            "artifact_sha256": hashlib.sha256(digest_input).hexdigest(),
                            "rules": rule_names}

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
        detector_cases.append((case_id, f'client_secret = "{value}"', "finding"))
    for index, value in enumerate(weak_password, 1):
        case_id = f"weak-password-{index:02d}"
        detector_cases.append((case_id, f'password = "{value}"', "finding"))
    detector_cases.extend((
        ("literal-client-secret-positive-01", f'client_secret = "{secret}"', "finding"),
        ("literal-password-positive-01", f'password = "{secret}"', "finding"),
        ("provider-github-token-positive", f'github_token = "{provider_token}"', "finding"),
    ))
    detector_text = "\n".join(row[1] for row in detector_cases)
    findings = backends.detect(detector_text, binary=gitleaks,
                               rules=engine.RULES,
                               timeout=15)
    found_rules_by_line = {}
    for finding in findings:
        found_rules_by_line.setdefault(finding.start_line, set()).add(finding.rule)
    for line, (case_id, value, _expected) in enumerate(detector_cases, 1):
        observed_rules = found_rules_by_line.get(line, set())
        put(case_id, "finding" if observed_rules else "none",
            digest_input=value.encode("utf-8"), rules=observed_rules)

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
                                "status": "uncovered", "artifact_sha256": hashlib.sha256(data).hexdigest(),
                                "rules": []}
            return
        result = extract(data, path, timeout=15)
        digest = hashlib.sha256(data).hexdigest()
        detected_rules = set()
        if result.disposition == "extracted":
            for part in result.parts:
                detected_rules.update(finding.rule for finding in backends.detect(
                    part.text, binary=gitleaks, rules=engine.RULES, timeout=15))
            actual = "finding" if detected_rules else "none"
            coverage = "complete"
        elif result.disposition in {"unsupported", "no-text", "encrypted"}:
            actual, coverage = "omission", "omitted"
        else:
            actual, coverage = "incomplete", "incomplete"
        put(case_id, actual, coverage=coverage, digest_input=data,
            rules=detected_rules if result.disposition == "extracted" else ())

    extract_case("utf16-text-positive", b"\xff\xfe" + f'client_secret = "{secret}"'.encode("utf-16le"), "input.txt")
    extract_case("unusual-extension-positive", f'client_secret = "{secret}"'.encode(), "input.odd")
    office_document = _docx_parts((("word/document.xml", f'client_secret = "{secret}"'),))
    office_comment = _docx_parts((("word/document.xml", "ordinary document text"),
                                  ("word/comments1.xml", f'client_secret = "{secret}"')))
    malformed = io.BytesIO()
    malformed.write(_docx_payload((("[Content_Types].xml", "</Types"),)))
    extract_case("office-word-document", office_document, "fixture.docx")
    extract_case("office-word-comments", office_comment, "fixture.docx")
    extract_case("office-word-malformed", malformed.getvalue(), "fixture.docx")
    sheet_text = f'client_secret = "{secret}"'
    sheet_split = len("client_se")
    extract_case("office-sheet-positive",
                 _xlsx_fixture(((sheet_text[:sheet_split], sheet_text[sheet_split:]),)),
                 "fixture.xlsx")
    extract_case("office-slides-positive",
                 _pptx_fixture(((sheet_text[:sheet_split], sheet_text[sheet_split:]),)),
                 "fixture.pptx")

    try:
        pdf_text = _pdf_with_text(f'client_secret = "{secret}"')
        from pypdf import PdfWriter
        pdf_empty_buffer = io.BytesIO(); pdf_empty_buffer.write(_pdf_with_text(""))
        extract_case("pdf-text-positive", pdf_text, "fixture.pdf")
        extract_case("pdf-image-only", pdf_empty_buffer.getvalue(), "fixture.pdf")
    except (ImportError, unittest.SkipTest):
        for case_id in ("pdf-text-positive", "pdf-image-only"):
            results[case_id] = {"actual": "uncovered", "coverage": "uncovered",
                                "status": "uncovered", "artifact_sha256": None, "rules": []}
    msg_subject = f'client_secret = "{secret}"'
    msg_body = f'client_secret = "{secret}"'
    try:
        extract_case("msg-subject-positive", _msg_fixture(subject_text=msg_subject), "fixture.msg")
        extract_case("msg-body-positive", _msg_fixture(body_text=msg_body), "fixture.msg")
        extract_case("unsupported-compound", _cfb_with_streams(()), "unlabelled.bin")
    except ImportError:
        for case_id in ("msg-subject-positive", "msg-body-positive", "unsupported-compound"):
            results[case_id] = {"actual": "uncovered", "coverage": "uncovered",
                                "status": "uncovered", "artifact_sha256": None, "rules": []}

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
                    "gitleaks_config": str(engine.RULES),
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
              "metric_eligible_cases": 0, "metric_not_scored_cases": 0,
              "true_positive": 0, "false_positive": 0, "false_negative": 0, "true_negative": 0}
    metric_names = ("true_positive", "false_positive", "false_negative", "true_negative")
    by_category = {}
    by_rule = {}
    for item in CASE_CATALOG:
        case_id, category = item["case_id"], item["category"]
        result = results[case_id]
        bucket = by_category.setdefault(category, {"cases": 0, "covered": 0, "uncovered": 0,
                                                    "failed": 0, "metric_eligible": 0,
                                                    "metric_not_scored": 0,
                                                    "true_positive": 0, "false_positive": 0,
                                                    "false_negative": 0, "true_negative": 0})
        bucket["cases"] += 1
        if result["status"] == "uncovered":
            counts["uncovered"] += 1; bucket["uncovered"] += 1
            continue
        counts["covered"] += 1; bucket["covered"] += 1
        if result["status"] == "failed":
            counts["failed"] += 1; bucket["failed"] += 1
        if item["expected"] in {"finding", "none"}:
            counts["metric_eligible_cases"] += 1
            bucket["metric_eligible"] += 1
            expected_positive = item["expected"] == "finding"
            actual_positive = result["actual"] == "finding"
            key = ("true_positive" if expected_positive else "false_positive") if actual_positive else ("false_negative" if expected_positive else "true_negative")
            counts[key] += 1
            bucket[key] += 1
            if expected_positive:
                expected_rule = item.get("expected_rule")
                if not expected_rule:
                    raise ValueError("finding label lacks expected detector rule")
                rule_counts = by_rule.setdefault(expected_rule, {
                    "true_positive": 0, "false_positive": 0, "false_negative": 0,
                })
                if expected_rule in result["rules"]:
                    rule_counts["true_positive"] += 1
                else:
                    rule_counts["false_negative"] += 1
                for observed_rule in set(result["rules"]) - {expected_rule}:
                    by_rule.setdefault(observed_rule, {
                        "true_positive": 0, "false_positive": 0, "false_negative": 0,
                    })["false_positive"] += 1
            else:
                for observed_rule in result["rules"]:
                    by_rule.setdefault(observed_rule, {
                        "true_positive": 0, "false_positive": 0, "false_negative": 0,
                    })["false_positive"] += 1
        else:
            counts["metric_not_scored_cases"] += 1
            bucket["metric_not_scored"] += 1
    return {"seed": seed, "policy_id": policy_id, "runtime_id": runtime_id,
            "counts": counts, "detector_metrics": {
                **{key: counts[key] for key in metric_names},
                "by_rule": by_rule,
            }, "by_category": by_category,
            "cases": [{"case_id": item["case_id"], "category": item["category"],
                       **results[item["case_id"]]} for item in CASE_CATALOG]}


if __name__ == "__main__":
    unittest.main(verbosity=2)
