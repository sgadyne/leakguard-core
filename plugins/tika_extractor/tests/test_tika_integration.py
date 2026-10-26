"""Small synthetic gate for the pinned local Tika service."""
from __future__ import annotations

import io
import os
from pathlib import Path
import unittest
import zipfile

from leakguard_core.extraction import ExtractionContext, ExtractionLimits
from leakguard_tika_extractor.plugin import (
    TIKA_ARCHIVE_SHA512,
    TikaExtractor,
)


def _pdf_with_text(text: str) -> bytes:
    content = ("BT /F1 12 Tf 72 720 Td (" + text + ") Tj ET\n").encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n"
        + content + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Title (PRIVATE SYNTHETIC METADATA TITLE) "
        b"/Producer (PRIVATE SYNTHETIC PRODUCER) >>",
    ]
    result = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for ordinal, body in enumerate(objects, 1):
        offsets.append(len(result))
        result.extend(f"{ordinal} 0 obj\n".encode("ascii"))
        result.extend(body)
        result.extend(b"\nendobj\n")
    xref = len(result)
    result.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    result.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    result.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R /Info 6 0 R >>\n"
        f"startxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return bytes(result)


def _docx(document_xml: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>",
        )
        archive.writestr(
            "_rels/.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>',
        )
        archive.writestr("word/document.xml", document_xml)
        archive.writestr(
            "docProps/core.xml",
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            "<dc:title>PRIVATE SYNTHETIC METADATA TITLE</dc:title>"
            "</cp:coreProperties>",
        )
        archive.writestr("private-member-name.xml", "PRIVATE SYNTHETIC MEMBER TEXT")
    return output.getvalue()


class TikaIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        artifact = os.environ.get("LEAKGUARD_TIKA_ARCHIVE")
        java = os.environ.get("LEAKGUARD_TIKA_JAVA")
        if not artifact or not java:
            raise unittest.SkipTest("set LEAKGUARD_TIKA_ARCHIVE and LEAKGUARD_TIKA_JAVA")
        cls.extractor = TikaExtractor({
            "artifact-path": str(Path(artifact).resolve()),
            "artifact-sha512": TIKA_ARCHIVE_SHA512,
            "java-path": str(Path(java).resolve()),
        })
        if not cls.extractor.capabilities()["ready"]:
            cls.extractor.close()
            raise unittest.SkipTest("pinned local Tika runtime is unavailable")
        cls._server = cls.extractor._server
        if cls._server is None:
            raise AssertionError("server did not start")
        cls._server_pid = cls._server.pid

    @classmethod
    def tearDownClass(cls):
        extractor = getattr(cls, "extractor", None)
        if extractor is not None:
            extractor.close()
        process = getattr(cls, "_server", None)
        if process is not None:
            if process.poll() is None:
                raise AssertionError("owned Tika server remained after close")

    def test_pdf_and_ooxml_use_one_warm_service_and_hide_metadata(self):
        limits = ExtractionLimits()
        pdf = self.extractor.extract(
            _pdf_with_text("LeakGuard synthetic Tika PDF text."),
            ExtractionContext("synthetic.pdf", "pdf-text", limits),
        )
        docx = self.extractor.extract(
            _docx(
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                "<w:body><w:p><w:r><w:t>LeakGuard synthetic Tika OOXML text.</w:t></w:r></w:p>"
                "<w:sectPr/></w:body></w:document>"
            ),
            ExtractionContext("synthetic.docx", "office-word", limits),
        )
        self.assertEqual(pdf.disposition, "extracted")
        self.assertEqual(docx.disposition, "extracted")
        self.assertEqual([(part.kind, part.ordinal) for part in pdf.parts], [("body", 1)])
        self.assertEqual([(part.kind, part.ordinal) for part in docx.parts], [("body", 1)])
        self.assertIn("synthetic Tika PDF text", pdf.parts[0].text)
        self.assertIn("synthetic Tika OOXML text", docx.parts[0].text)
        for result in (pdf, docx):
            self.assertNotIn("PRIVATE SYNTHETIC METADATA TITLE", result.parts[0].text)
            self.assertNotIn("PRIVATE SYNTHETIC PRODUCER", result.parts[0].text)
            self.assertNotIn("private-member-name.xml", result.parts[0].text)
        self.assertEqual(self.extractor._server.pid, self._server_pid)
        self.assertEqual(self.extractor.identity()["tika_archive_sha512"], TIKA_ARCHIVE_SHA512)

    def test_malformed_ooxml_is_an_explicit_parse_failure(self):
        result = self.extractor.extract(
            _docx('<w:document><broken>'),
            ExtractionContext("synthetic.docx", "office-word", ExtractionLimits()),
        )
        self.assertNotEqual(result.disposition, "extracted")
        self.assertIn("extract-failed", result.issues)
        self.assertEqual(self.extractor._server.pid, self._server_pid)

    def test_output_byte_limit_discards_partial_result(self):
        result = self.extractor.extract(
            _pdf_with_text("LeakGuard synthetic Tika output-limit control."),
            ExtractionContext("synthetic.pdf", "pdf-text", ExtractionLimits(max_text_bytes=16)),
        )
        self.assertEqual(result.disposition, "no-text")
        self.assertEqual(result.issues, ("extract-output-limit",))
        self.assertEqual(result.parts, ())

    def test_archive_identity_mismatch_fails_closed_in_preflight(self):
        unavailable = TikaExtractor({
            "artifact-path": os.environ["LEAKGUARD_TIKA_ARCHIVE"],
            "artifact-sha512": "0" * 128,
            "java-path": os.environ["LEAKGUARD_TIKA_JAVA"],
        })
        try:
            self.assertFalse(unavailable.capabilities()["ready"])
            result = unavailable.extract(
                _pdf_with_text("LeakGuard synthetic preflight control."),
                ExtractionContext("synthetic.pdf", "pdf-text", ExtractionLimits()),
            )
            self.assertEqual(result.disposition, "no-text")
            self.assertEqual(result.issues, ("dependency-unavailable",))
        finally:
            unavailable.close()

    def test_encrypted_pdf_is_not_reported_as_no_text_or_clean(self):
        try:
            from pypdf import PdfWriter
        except ImportError:
            self.skipTest("pypdf is needed only to synthesize this encrypted control")
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        writer.encrypt(user_password="synthetic-password", owner_password="synthetic-owner")
        encrypted = io.BytesIO()
        writer.write(encrypted)
        result = self.extractor.extract(
            encrypted.getvalue(),
            ExtractionContext("synthetic.pdf", "pdf-text", ExtractionLimits()),
        )
        self.assertEqual(result.disposition, "encrypted")
        self.assertEqual(result.issues, ("encrypted",))


if __name__ == "__main__":
    unittest.main()
