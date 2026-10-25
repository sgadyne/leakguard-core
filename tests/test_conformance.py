"""Contract checks for the public redacted result model."""
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import json
import unittest

from leakguard_core import models


class PublicModelConformanceTests(unittest.TestCase):
    def make_report(self):
        started = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
        source = models.SourceRef(
            kind=models.SourceKind.FILESYSTEM,
            path='odd name/é\nsettings.py',
        )
        content = models.ContentIdentity('sha256', 'a' * 64, 32)
        identity = models.RuntimeIdentity(
            policy_id='policy-fixture',
            runtime_id='runtime-fixture',
            context_id='context-fixture',
            cache_eligible=True,
        )
        finding = models.FindingRecord(
            id='finding-fixture',
            source=source,
            part_id='text',
            start_line=2,
            end_line=4,
            rule='literal-client-secret',
            detector_id='gitleaks',
            detector_severity=models.DetectorSeverity.REVIEW,
            severity=models.FindingSeverity.BLOCK,
            classification=models.FindingClassification.HEURISTIC,
            proof_id=None,
        )
        scanned = models.ScanResult(
            source=source,
            content=content,
            identity=identity,
            outcome=models.ScanOutcome.SCANNED,
            coverage=models.CoverageState.COMPLETE,
            findings=(finding,),
            issues=(),
            observed_at=started + timedelta(seconds=1),
            last_executed_at=started + timedelta(seconds=1),
        )
        omitted_source = models.SourceRef(
            kind=models.SourceKind.BYTES,
            path='fixture.bin',
        )
        omission = models.CoverageIssue(
            code=models.ErrorCode.POLICY_OMISSION,
            source=omitted_source,
            required=False,
            omission_id='unsupported-binary',
        )
        reused = models.ScanResult(
            source=omitted_source,
            content=None,
            identity=identity,
            outcome=models.ScanOutcome.REUSED,
            coverage=models.CoverageState.OMITTED,
            findings=(),
            issues=(omission,),
            observed_at=started + timedelta(seconds=2),
            last_verified_at=started + timedelta(seconds=2),
            reused_from='prior-scan-fixture',
        )
        report = models.ScanReport(
            schema_version=1,
            run_id='run-fixture',
            started_at=started,
            finished_at=started + timedelta(seconds=3),
            policy_id='policy-fixture',
            results=(scanned, reused),
            coverage=models.CoverageSummary(
                enumeration_complete=True,
                required_complete=True,
                omission_count=1,
                pending_files=0,
                pending_directories=0,
                cycle_id='cycle-fixture',
            ),
            decision=models.PolicyDecision(
                verdict=models.DecisionVerdict.ALLOW_WITH_OMISSIONS,
                reason_codes=(models.ErrorCode.POLICY_OMISSION,),
                policy_id='policy-fixture',
            ),
        )
        return report, finding

    def test_serializer_is_fixed_redacted_and_preserves_source_identity(self):
        report, finding = self.make_report()
        payload = report.to_dict()
        serialized = report.to_json()
        decoded = json.loads(serialized)

        self.assertEqual(set(payload), {
            'schema_version', 'run_id', 'started_at', 'finished_at', 'policy_id',
            'results', 'coverage', 'decision', 'counts', 'issues',
        })
        self.assertEqual(decoded['results'][0]['source']['path'], 'odd name/é\nsettings.py')
        self.assertEqual(decoded['results'][0]['findings'][0]['start_line'], 2)
        self.assertEqual(decoded['results'][0]['findings'][0]['end_line'], 4)
        self.assertEqual(set(decoded['results'][0]['findings'][0]), {
            'id', 'source', 'part_id', 'start_line', 'end_line', 'rule',
            'detector_id', 'detector_severity', 'severity', 'classification', 'proof_id',
        })
        self.assertEqual(decoded['results'][0]['outcome'], 'scanned')
        self.assertEqual(decoded['results'][1]['outcome'], 'reused')
        self.assertEqual(decoded['results'][1]['issues'][0]['code'], 'policy-omission')
        self.assertEqual(decoded['results'][0]['findings'][0]['severity'], 'block')
        self.assertNotIn('Secret', serialized)
        self.assertNotIn('Match', serialized)
        self.assertNotIn('raw_value_fixture', serialized)
        self.assertEqual(serialized, report.to_json())

        self.assertEqual([item.name for item in fields(finding)], [
            'id', 'source', 'part_id', 'start_line', 'end_line', 'rule',
            'detector_id', 'detector_severity', 'severity', 'classification', 'proof_id',
        ])
        self.assertNotIn('value', finding.__slots__)

    def test_counts_are_derived_from_result_outcomes_and_findings(self):
        report, _ = self.make_report()
        counts = report.counts

        self.assertEqual(counts.results, 2)
        self.assertEqual((counts.scanned, counts.reused, counts.skipped), (1, 1, 0))
        self.assertEqual(counts.findings, 1)
        self.assertEqual(counts.block_findings, 1)
        self.assertEqual(counts.omitted_results, 1)
        self.assertEqual(counts.issues, 1)

    def test_result_contract_rejects_open_severity_and_invalid_ranges(self):
        _, finding = self.make_report()
        with self.assertRaises(TypeError):
            models.FindingRecord(
                id=finding.id,
                source=finding.source,
                part_id=finding.part_id,
                start_line=finding.start_line,
                end_line=finding.end_line,
                rule=finding.rule,
                detector_id=finding.detector_id,
                detector_severity='review',
                severity=models.FindingSeverity.BLOCK,
                classification=models.FindingClassification.HEURISTIC,
            )
        with self.assertRaises(ValueError):
            models.FindingRecord(
                id=finding.id,
                source=finding.source,
                part_id=finding.part_id,
                start_line=4,
                end_line=3,
                rule=finding.rule,
                detector_id=finding.detector_id,
                detector_severity=models.DetectorSeverity.REVIEW,
                severity=models.FindingSeverity.BLOCK,
                classification=models.FindingClassification.HEURISTIC,
            )
        with self.assertRaises(TypeError):
            models.FindingRecord(
                id=finding.id,
                source=finding.source,
                part_id=finding.part_id,
                start_line=1,
                end_line=1,
                rule=finding.rule,
                detector_id=finding.detector_id,
                detector_severity=models.DetectorSeverity.REVIEW,
                severity=models.FindingSeverity.BLOCK,
                classification=models.FindingClassification.HEURISTIC,
                raw_value_fixture='SyntheticOnly~M7kQ2vR9xL4nD8pS6aH3zB5cF1eG',
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)
