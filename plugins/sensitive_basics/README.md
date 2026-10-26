# LeakGuard Sensitive Basics

This separately installable v2 detector adds a small, offline set of contextual
personal and organizational identifier checks. It is intended for the
`sensitive` and `firm` profiles. Do not enable it in the default `credentials`
profile. Every rule is `review` by default; a firm profile can promote selected
rule IDs with the explicit `promote-rules` option.

Install the wheel from the private release bundle using the per-user
`leakguard-extensions` registry. The registry keeps it disabled until an
operator enables it for a named profile. For a source checkout, build it with
`python -m pip wheel --no-deps --wheel-dir dist .`, then register/enable the
wheel for `sensitive` or `firm` using the CLI options from the installation
guide.

The rules cover labeled email, phone and street-address fields; Luhn-valid card
candidates, ABA routing candidates and mod-97 IBAN candidates; and configurable
employee, customer and account identifier prefixes. Explicit identifier
fields also recognize numeric-only IDs with 4–18 digits, excluding repeated-
digit placeholders and short quantities. Unlabeled values and checksum failures
are controls. CSV rows are checked only when the file has a recognized
contextual header. This is a modest format-level check, not broad document
understanding or a medical/legal classifier.

Rule ID prefixes encode category because the stable v2 result schema contains
only `{rule, line, severity}`. A value-free UI can map `pii-contact-*` to
contact, `pii-financial-*` to financial identifier, and `pii-identifier-*` to
organization identifier; the suffix names the specific check. Findings carry
no match, source text, fingerprint or category value copied from the file. The
labeled examples in `src/sensitive_basics/cases.json` are synthetic and
independently specify the expected rule and severity for each case. Registry
`check` uses that same conformance file.

Example firm option for promoting one identifier rule with the default
prefixes:

```json
{
  "module": "sensitive_basics.plugin",
  "component": "sensitive-basics",
  "options": {
    "promote-rules": ["pii-identifier-employee"]
  }
}
```

Because promotion changes expected severities, install with the matching
independently reviewed `fixtures/cases-promoted.json` sidecar using
`leakguard-extensions install WHEEL --options OPTIONS.json --cases CASES.json`.
Changing any identifier prefix also changes the expected case inputs; provide a
case sidecar with those firm-specific identifiers. Promote only rules that the
organization has reviewed and wants to block. V2 plugins are trusted local code
running with the scanner account's permissions; process supervision is not an
operating-system sandbox.
