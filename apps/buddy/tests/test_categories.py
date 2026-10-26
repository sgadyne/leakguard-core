import base64
import unittest
from types import SimpleNamespace

from leakguard_buddy.backend import _finding_category


class FindingCategoryTests(unittest.TestCase):
    def test_category_is_derived_from_stable_rule_prefixes(self):
        cases = {
            "pii-contact-email": "contact",
            "pii-financial-card": "financial-identifier",
            "pii-identifier-customer": "organization-identifier",
            "firm-customer-number": "firm",
            "literal-password": "credentials",
            "custom-unclassified-rule": "other",
        }
        for rule, category in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(_finding_category(rule), category)

    def test_non_string_rule_is_not_interpreted_as_a_category(self):
        self.assertEqual(_finding_category(None), "other")

    def test_findings_api_filters_by_rule_category_not_legacy_classification(self):
        from leakguard_buddy.backend import BuddyBackend

        finding = {
            "id": "finding-1", "rule": "pii-contact-email",
            "classification": "credential-candidate", "severity": "review",
            "source": {"path": "/synthetic/work.csv"}, "state": "active",
        }
        store = SimpleNamespace(
            query_findings_page=lambda **_kwargs: SimpleNamespace(rows=[finding], next_cursor=None),
            get_annotation=lambda finding_id: {"finding_id": finding_id, "state": "reviewed"},
        )
        host = SimpleNamespace(
            status=lambda: {},
            sources=lambda: [{"id": "source-1", "root": "/synthetic"}],
            jobs=lambda: [],
        )
        backend = object.__new__(BuddyBackend)
        backend._host = host
        backend._observation_store = store

        result = backend.findings({"category": "contact", "annotation": "reviewed", "limit": "10"})
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["category"], "contact")
        self.assertEqual(result["findings"][0]["classification"], "credential-candidate")
        self.assertEqual(result["findings"][0]["source_id"], "source-1")
        self.assertEqual(backend.findings({"category": "credentials"})["findings"], [])

    def test_backup_uses_the_unlocked_credential_session(self):
        from leakguard_buddy.backend import BuddyBackend

        class Session:
            def backup(self, path, passphrase):
                self.passphrase = passphrase
                path.write_bytes(b"encrypted-synthetic-backup")

        session = Session()
        backend = object.__new__(BuddyBackend)
        backend._credential_session = session
        result = backend.credential_backup("backup phrase")
        self.assertEqual(session.passphrase, "backup phrase")
        self.assertEqual(base64.b64decode(result["backup_base64"]), b"encrypted-synthetic-backup")


if __name__ == "__main__":
    unittest.main()
