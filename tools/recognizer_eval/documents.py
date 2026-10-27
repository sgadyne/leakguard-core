"""Small deterministic PDF/DOCX/XLSX extraction gate and omission accounting."""
from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass
from xml.sax.saxutils import escape

from .corpus import DEFAULT_SEED, _derive, make_jwe


@dataclass(frozen=True)
class DocumentCase:
    case_id: str
    format_id: str
    logical_path: str
    data: bytes
    format_outcome: str
    actionability: str
    token: str | None
    category: str


def _zip(members: list[tuple[str, str]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, content.encode("utf-8"))
    return buffer.getvalue()


def _docx(text: str) -> bytes:
    content_types = (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>')
    document = (
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t xml:space="preserve">' + escape(text) +
        '</w:t></w:r></w:p></w:body></w:document>')
    rels = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '</Relationships>')
    return _zip([("[Content_Types].xml", content_types), ("_rels/.rels", rels),
                 ("word/document.xml", document)])


def _xlsx(text: str) -> bytes:
    content_types = (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>')
    workbook = (
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Credentials" sheetId="1" r:id="rId1"/></sheets></workbook>')
    rels = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '</Relationships>')
    sheet = (
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t xml:space="preserve">'
        + escape(text) + '</t></is></c></row></sheetData></worksheet>')
    return _zip([("[Content_Types].xml", content_types), ("xl/workbook.xml", workbook),
                 ("xl/_rels/workbook.xml.rels", rels), ("xl/worksheets/sheet1.xml", sheet)])


def _pdf(text: str) -> bytes:
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 9 Tf 30 740 Td ({safe}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = bytearray(b"%PDF-1.4\n% synthetic evaluation fixture\n")
    offsets = [0]
    for number, body in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii")); output.extend(body); output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
    return bytes(output)


def build_document_cases(seed: int = DEFAULT_SEED, *, token_factory=None) -> list[DocumentCase]:
    """Build a shared 72-file regression gate; not an independent holdout sample."""
    root = _derive(f"document-eval-{seed}".encode("ascii"), "seed")
    result = []
    builders = {"docx": _docx, "pdf": _pdf, "xlsx": _xlsx}
    for format_name, format_id in (("docx", "office-word"), ("pdf", "pdf-text"), ("xlsx", "office-sheet")):
        for index in range(12):
            token_seed = _derive(root, f"positive/{format_name}/{index}")
            algorithm = ("A256KW", "dir", "ECDH-ES")[index % 3]
            token = (token_factory(token_seed, algorithm=algorithm) if token_factory else
                     make_jwe(token_seed, algorithm=algorithm, header_variant=index))
            content = f"Authorization: Bearer {token}\nstatus=synthetic"
            result.append(DocumentCase(
                case_id=f"doc-positive-{format_name}-{index:02d}", format_id=format_id,
                logical_path=f"fixtures/{format_name}/positive-{index:02d}.{format_name}",
                data=builders[format_name](content), format_outcome="positive",
                actionability="exposed", token=token, category="intact-supported-jwe"))
        for index in range(12):
            if index % 2:
                content = f"Public sample: {_derive(root, f'negative/{format_name}/{index}', 24).hex()}\nrelease=2.4.{index}"
            else:
                content = f"Authorization: Bearer <PLACEHOLDER>\nsha256:{_derive(root, f'negative/{format_name}/{index}', 32).hex()}"
            result.append(DocumentCase(
                case_id=f"doc-negative-{format_name}-{index:02d}", format_id=format_id,
                logical_path=f"fixtures/{format_name}/negative-{index:02d}.{format_name}",
                data=builders[format_name](content), format_outcome="negative",
                actionability="unknown", token=None, category="safe-document-lookalike"))
    return result


def evaluate_document_cases(detector, cases, *, extractor=None, limits=None) -> dict:
    """Return file metrics; extraction omission/error is never a true negative."""
    from leakguard_core.extraction import extract
    from leakguard_core.plugins import DetectionContext
    from .adapter import _normalize

    extraction = extractor or extract
    review_threshold = getattr(detector, "review_threshold", 0.35)
    rows = []
    tp = fp = tn = fn = 0
    raw_tp = raw_fp = raw_tn = raw_fn = 0
    omitted_positive = 0
    incomplete_files = 0
    evaluated = 0
    span_tp = span_fp = span_fn = 0
    review_span_tp = review_span_fp = review_span_fn = 0
    for case in cases:
        result = extraction(case.data, case.logical_path, limits=limits)
        extracted = result.disposition == "extracted" and bool(result.parts) and not result.issues
        gold_part_spans = []
        if extracted and case.token:
            for part in result.parts:
                start = part.text.find(case.token)
                if start >= 0:
                    gold_part_spans.append((part.part_id, start, start + len(case.token)))
        has_gold = case.format_outcome == "positive"
        extraction_omission = has_gold and not gold_part_spans
        candidates = []
        detector_errors = []
        if extracted:
            for part in result.parts:
                try:
                    context = DetectionContext(case.logical_path, part.part_id, part.format_id)
                    candidates.extend((part.part_id, _normalize(item)) for item in detector.detector.detect(part.text, context))
                except Exception as error:
                    detector_errors.append(type(error).__name__)
        detector_error = bool(detector_errors)
        jose_candidates = [(part_id, candidate) for part_id, candidate in candidates
                           if candidate.entity in {"JOSE_COMPACT_JWE", "JOSE_COMPACT_UNVERIFIED"}]
        review_candidates = [(part_id, candidate) for part_id, candidate in jose_candidates
                             if (candidate.score is None and candidate.severity in {"review", "block"})
                             or (candidate.score is not None and candidate.score >= review_threshold)]
        raw_candidate_match = any(
            candidate.start is not None and candidate.end is not None
            and any(gold_part_id == candidate_part and start == candidate.start and end == candidate.end
                    for gold_part_id, start, end in gold_part_spans)
            for candidate_part, candidate in jose_candidates)
        candidate_match = any(
            candidate.start is not None and candidate.end is not None
            and any(gold_part_id == candidate_part and start == candidate.start and end == candidate.end
                    for gold_part_id, start, end in gold_part_spans)
            for candidate_part, candidate in review_candidates)
        any_candidate = bool(jose_candidates)
        any_review_candidate = bool(review_candidates)
        if has_gold:
            if not extracted or extraction_omission or detector_error or not candidate_match:
                fn += 1
                if extraction_omission:
                    omitted_positive += 1
            else:
                tp += 1
        elif not extracted or detector_error:
            incomplete_files += 1
        elif any_review_candidate:
            fp += 1
        else:
            tn += 1
        if has_gold:
            if not extracted or extraction_omission or detector_error or not raw_candidate_match:
                raw_fn += 1
            else:
                raw_tp += 1
        elif not extracted or detector_error:
            pass
        elif any_candidate:
            raw_fp += 1
        else:
            raw_tn += 1
        if extracted and not extraction_omission and not detector_error:
            evaluated += 1
        if case.token:
            exact = raw_candidate_match
            review_exact = candidate_match
            predicted_spans = [(part_id, candidate.start, candidate.end) for part_id, candidate in jose_candidates
                               if candidate.start is not None and candidate.end is not None]
            review_predicted_spans = [(part_id, candidate.start, candidate.end)
                                      for part_id, candidate in review_candidates
                                      if candidate.start is not None and candidate.end is not None]
            gold_spans = gold_part_spans
            if exact:
                span_tp += 1
            else:
                span_fn += len(gold_spans) or 1
            span_fp += len(predicted_spans) - int(exact)
            if review_exact:
                review_span_tp += 1
            else:
                review_span_fn += len(gold_spans) or 1
            review_span_fp += len(review_predicted_spans) - int(review_exact)
        else:
            span_fp += sum(candidate.start is not None and candidate.end is not None
                           and 0 <= candidate.start < candidate.end
                           for _, candidate in jose_candidates)
            review_span_fp += sum(candidate.start is not None and candidate.end is not None
                                  and 0 <= candidate.start < candidate.end
                                  for _, candidate in review_candidates)
        rows.append({
            "case_id": case.case_id, "format_id": case.format_id,
            "format_outcome": case.format_outcome, "category": case.category,
            "disposition": result.disposition, "issues": list(result.issues),
            "extracted_parts": len(result.parts), "extraction_omission": extraction_omission,
            "detector_error": detector_error, "candidate_count": len(jose_candidates),
            "review_candidate_count": len(review_candidates),
            "raw_candidate_match": raw_candidate_match,
            "candidate_match": candidate_match,
            "status": "extraction-omission" if extraction_omission else "incomplete" if not extracted or detector_error else "evaluated",
        })
    positive = sum(case.format_outcome == "positive" for case in cases)
    negative = sum(case.format_outcome == "negative" for case in cases)
    return {
        "files": len(cases), "positive_files": positive, "negative_files": negative,
        "evaluated_files": evaluated, "incomplete_files": incomplete_files,
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "raw_candidate_counts": {"tp": raw_tp, "fp": raw_fp, "tn": raw_tn, "fn": raw_fn},
        "metric_operating_points": {
            "counts": "review threshold; extraction/detector omissions remain positive false negatives",
            "raw_candidate_counts": "any returned JOSE target candidate before review threshold",
        },
        "extraction": {"positive_omissions": omitted_positive,
                       "positive_recall": (positive - omitted_positive) / positive if positive else None,
                       "complete_file_rate": evaluated / len(cases) if cases else None,
                       "omissions_are_false_negatives_and_never_true_negatives": True},
        "span_metrics": {"raw_candidates": {"exact": {"tp": span_tp, "fp": span_fp, "fn": span_fn}},
                         "review_threshold_candidates": {"exact": {
                             "tp": review_span_tp, "fp": review_span_fp, "fn": review_span_fn}}},
        "cases": rows,
    }
