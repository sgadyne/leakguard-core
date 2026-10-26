import unittest

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


if __name__ == "__main__":
    unittest.main()
