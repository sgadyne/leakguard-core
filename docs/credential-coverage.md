# Credential coverage and qualification

Phase 1 is a bounded, offline credential scan. The explicit credentials profile
is intended to compose Gitleaks, the compact JOSE recognizer and the credential
DetectorV2 plugin. JOSE structural candidates remain review findings; literal
credentials covered by the new contextual rules are blocks. No credential is
validated against a service.

The qualification matrix below describes the **scope to be tested**, not a
claim that an integrated candidate has passed. The exact result belongs in the
acceptance receipt for the tested commit.

| Family | Intended coverage | Qualification controls and limits |
| --- | --- | --- |
| Flat fields | Every alias shipped in each of the common, cloud, developer-ci, data-messaging, saas-ai and key-material groups, mapped to its declared role | Each alias has short literal, quoted literal reference, unquoted reference and complete-key near matches. No fuzzy matching or nested record semantics are claimed. |
| HTTP | Recorded Authorization Basic and Bearer | Each scheme has a literal and near-name/scheme control; Proxy-Authorization is deferred; malformed Base64, missing credentials, reference, original-text offsets and oversized input are checked. No network request or recursive decoding. |
| Connection URLs | postgres, postgresql, mysql, mariadb, mongodb, mongodb+srv, redis, rediss, amqp, amqps | Each spelling has a literal userinfo positive and missing-password/userinfo controls. The rule is lexical, not full URL validation. Gitleaks may decode input before applying rules; encoded material can therefore be detected and some encoded reference forms may produce findings. JDBC and ODBC are outside this phase. |
| Extensions | An explicitly installed private alias wrapper | No automatic discovery or arbitrary path loading; dependency absence must fail closed. |
| Composition | Credentials, JOSE and native backend; firm recognizer factory and options | Effective installed configuration, blocking and review actions, and preserved firm settings must be checked. |
| Privacy and runtime | Synthetic markers, unchanged source files, value-free public findings/logs/store, worker limits | Test with installed CLI, real Git hooks and host. Resource mutation must invalidate reuse or unknown external state must demonstrate nonreuse and disabled continuation. |

Development cases and an independently frozen sealed set are separate. The
sealed fixture bytes are retained by the acceptance owner outside the source
checkout; only their SHA-256 and case categories are recorded. Candidate tuning
against a sealed failure invalidates an untouched-holdout claim unless a new
independent holdout is created. A passing fixture set establishes only the
listed representations, not universal provider coverage or production accuracy.
Native platforms, daemon/enterprise environments and hosted CI require their
own exact-revision evidence.

Unknown plugin state disables cross-slice continuation: an audit must finish in
one bounded slice, or later slices restart rather than certify earlier work.
Flat-field recognition is lexical; an unmatched standalone quote can suppress
later fields on that line. The installed candidate and receipt determine which
representations actually passed.
