# Bundled literal-field alias packs

The six JSON resources in this directory are original LeakGuard-authored data,
licensed under the repository's MIT license. They were selected from common
credential field naming conventions and the project-local
`inputs/credential-taxonomy.md` planning inventory; no third-party scanner
code or rule configuration was copied. Each JSON resource is the exact
shipped source of its corresponding group. The fixture inventory in
`plugins/credential_detector/tests/fixtures/pack-alias-cases.json` records one
synthetic positive and a full-key negative for every entry; tests also check
short literals and reference forms. These names are examples of field labels,
not a provider token-format catalog or claims of complete provider coverage.

There are 32 aliases across six groups: common (8), cloud (4), developer-ci
(5), data-messaging (6), saas-ai (5), and key-material (4). The five roles
map to five rule families; alias counts are not counts of distinct credential
types. See the JSON files for the exact names and role of each. ASCII letter
case is ignored and `_`, `-`, `.` separators are removed for lookup. Each
entry matches a complete key, not a substring. Fields use `:` or `=` with a
nonempty literal; short literals are included. Unquoted `$VAR`, `${VAR}`,
`getenv(...)`, `os.getenv(...)`, and `os.environ[...]` references are excluded;
quoted reference-looking strings are literals. Unquoted null/none/true/false/~, empty values, and pure
`${NAME}`, `{{NAME}}`, and `<NAME>` placeholders (even quoted) are excluded. No network validation or entropy inference is performed.
The key-material group covers only literal values assigned to these names; it
does not parse JWK, WireGuard, PEM containers, nested semantic records, or
binary key stores. Unlabelled arbitrary strings are outside this pack's scope.
An unmatched standalone quote or apostrophe suppresses scanning of the remaining
text on that line; the flat scanner does not parse general source syntax.
