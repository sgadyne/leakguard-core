"""Deterministic synthetic corpus coverage for maintained text surfaces."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import random
import sys
import tempfile
import unittest
import zipfile

from leakguard_core import engine, models
from leakguard_core.extraction import extract


SEED = int(os.environ.get("LEAKGUARD_CORPUS_SEED", "20261025"))


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


def _msg_fixture() -> bytes:
    subject = ("synthetic subject " + "s" * 4100).encode("cp1252")
    body = ("first body line\nsecond body line\n" + "b" * 2050).encode("utf-16le") + b"\0\0"
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
