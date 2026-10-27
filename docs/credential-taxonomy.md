# Generated credentials: taxonomy and coverage

This is a **prioritized working catalog**, not a measured global frequency
ranking. There is no representative dataset here from which to assert a top 10,
100 or 1,000. The ordering reflects likely exposure and usefulness for this
project: common infrastructure, source control and application secrets first,
then specialized service keys. A *family* may contain many credential versions.
The 222 entries in the upstream Gitleaks 8.30.1 default config are rule IDs, not
222 validated credential types or a measure of prevalence.

The default LeakGuard credential engine extends the **installed Gitleaks binary's**
embedded rules with `src/leakguard_core/rules.toml`. This catalog refers to the
recommended **8.30.1** binary and those stock rules; a different binary or an
operator-supplied `gitleaks_config` changes coverage. A rule listed below is
only a candidate detector: its exact regex, entropy, context, allowlists,
text extraction, boundaries and versions matter. A positive match does not
prove validity, privilege or even that the string is a secret. LeakGuard does
not call providers or validate credentials. Findings are blocking by default.

`Tested` means a synthetic positive went through LeakGuard's actual Gitleaks
adapter in `tests/test_credential_taxonomy.py`; it does not imply exhaustive
coverage. `Rule` means the named rule exists upstream; no end-to-end claim is
made for that family here. All patterns should be tested on the organization's
own labeled, non-sensitive corpus before adjusting blocking policy.

| Priority / family | Representative forms and caveats | Default detector / status |
| --- | --- | --- |
| 1. Literal passwords and passphrases | Generated or human passwords in explicit password, passwd, pwd, passphrase and selected aliases; short values included | `literal-password`; **Tested**. Context required; not a general password recognizer. |
| 2. Client, application and API secrets | Opaque values assigned to selected explicit `client_secret`, `api_secret`, etc. | `literal-client-secret`; **Tested**. Other labels are not guaranteed. |
| 3. Database and broker credentials | Userinfo with password in PostgreSQL, MySQL/MariaDB, MongoDB, Redis and AMQP URLs | `credential-connection-url`; **Tested**, added in core. See restrictions below. |
| 4. Private cryptographic keys | PEM private-key blocks, including RSA, EC, PKCS#8, OpenSSH, and PGP-style private key blocks when matching the upstream expression | `private-key`; **Tested** for a synthetic PKCS#8-shaped block. Binary containers and incomplete PEM blocks are separate gaps. |
| 5. AWS access key IDs | AKIA/ASIA and related identifiers; not themselves the corresponding secret access key | `aws-access-token`; **Tested**. AWS secret values need contextual detection; this is not pair or validity verification. |
| 6. Google Cloud/API keys | `AIza` family; may be restricted or intended for public use | `gcp-api-key`; **Tested**. Treat as a candidate, not proof of secret access. |
| 7. Azure Entra client secrets | A subset of structurally recognizable application secret values | `azure-ad-client-secret`; Rule; other shapes may need contextual assignments. |
| 8. GitHub tokens | Classic PAT, fine-grained PAT, app, OAuth, refresh | `github-pat`, `github-fine-grained-pat`, `github-app-token`, `github-oauth`, `github-refresh-token`; **Tested** classic and fine-grained only. |
| 9. GitLab tokens | PAT, runner, deploy, job and other versioned tokens | `gitlab-pat`, `gitlab-pat-routable`, `gitlab-runner-authentication-token`, `gitlab-deploy-token`, `gitlab-cicd-job-token`; **Tested** legacy PAT only. |
| 10. Slack access tokens and webhooks | Bot/user/app tokens and selected webhook forms | `slack-bot-token`, `slack-user-token`, `slack-app-token`, `slack-webhook-url`; **Tested** bot only. |
| 11. Stripe secret/restricted keys | Live, test and prod forms; test keys still trigger | `stripe-access-token`; **Tested** live-shaped fixture. Publishable keys are a different class. |
| 12. OpenAI API keys | Selected legacy and project/service/admin formats with the upstream marker | `openai-api-key`; **Tested** synthetic legacy form. Other current/legacy formats are not guaranteed. |
| 13. Anthropic API keys | API and admin variants in the upstream fixed-length formats | `anthropic-api-key`, `anthropic-admin-api-key`; **Tested** API variant. |
| 14. Hugging Face tokens | Personal and organization tokens | `huggingface-access-token`, `huggingface-organization-api-token`; **Tested** personal variant. |
| 15. npm registry tokens | `npm_` access tokens | `npm-access-token`; **Tested**. |
| 16. PyPI upload tokens | Selected `pypi-` macaroon representation | `pypi-upload-token`; **Tested**. |
| 17. Databricks personal tokens | `dapi` tokens | `databricks-api-token`; **Tested**. |
| 18. DigitalOcean tokens | PAT, access and refresh variants | `digitalocean-pat`, `digitalocean-access-token`, `digitalocean-refresh-token`; **Tested** PAT. |
| 19. SendGrid API keys | `SG.` tokens | `sendgrid-api-token`; **Tested**. |
| 20. HashiCorp Vault tokens | Service and batch formats, not arbitrary opaque token values | `vault-service-token`, `vault-batch-token`; Rule. |
| 21. Cloudflare | API, global and origin CA keys | `cloudflare-api-key`, `cloudflare-global-api-key`, `cloudflare-origin-ca-key`; Rule; context may be required. |
| 22. Shopify | App access and shared secrets | `shopify-access-token`, `shopify-custom-access-token`, `shopify-private-app-access-token`, `shopify-shared-secret`; Rule. |
| 23. Twilio | API key SID format is an identifier; a separate secret may be needed | `twilio-api-key`; Rule; do not treat identifier as a validated credential. |
| 24. Atlassian | API token | `atlassian-api-token`; Rule. |
| 25. Bitbucket | Client ID and client secret | `bitbucket-client-id`, `bitbucket-client-secret`; Rule. Client ID alone is not a secret. |
| 26. Terraform Cloud / HCP | API token and some password assignments | `hashicorp-tf-api-token`, `hashicorp-tf-password`; Rule. |
| 27. Grafana | API key, cloud token and service-account token | `grafana-api-key`, `grafana-cloud-api-token`, `grafana-service-account-token`; Rule. |
| 28. Datadog | API/access token | `datadog-access-token`; Rule. |
| 29. Sentry | User, organization and other access tokens | `sentry-user-token`, `sentry-org-token`, `sentry-access-token`; Rule. |
| 30. CI/service integrations | Circle of examples: Codecov, Travis CI, Drone, Harness | `codecov-access-token`, `travisci-access-token`, `droneci-access-token`, `harness-api-key`; Rule. |
| 31. Artifact registries | JFrog/Artifactory, RubyGems, Clojars | `jfrog-identity-token`, `artifactory-api-key`, `rubygems-api-token`, `clojars-api-token`; Rule. |
| 32. Deployment platforms | Netlify, Heroku, Fly.io and Pulumi | `netlify-access-token`, `heroku-api-key`, `flyio-access-token`, `pulumi-api-token`; Rule. |
| 33. Data services | PlanetScale, Confluent and ClickHouse | `planetscale-password`, `confluent-secret-key`, `clickhouse-cloud-api-secret-key`; Rule. |
| 34. Collaboration / messaging | Discord, Telegram, Notion, Postman, Linear | `discord-client-secret`, `telegram-bot-api-token`, `notion-api-token`, `postman-api-token`, `linear-api-key`; Rule. |
| 35. 1Password | Secret Key and service-account token | `1password-secret-key`, `1password-service-account-token`; Rule. |
| 36. Other AI providers | Cohere and Perplexity | `cohere-api-token`, `perplexity-api-key`; Rule. |
| 37. Signed bearer tokens | JWT / base64 JWT shapes; tokens may be expired, public, or not authorization credentials | `jwt`, `jwt-base64`; Rule. Not all JWT/JWE variants are covered. |
| 38. Basic/Bearer authentication in shell commands | Some `curl` header and user/password examples | `curl-auth-header`, `curl-auth-user`; Rule. Ordinary HTTP headers are not generally covered by those rules. |
| 39. Opaque API keys and tokens | Labeled, sufficiently random strings with selected syntax and upstream exclusions | `generic-api-key`; Rule. Not reliable for arbitrary secrets, bare random strings or all generated passwords. |
| 40. Binary keystores and structured secrets | PKCS#12/PFX, Kubernetes Secrets, encrypted vaults | **Gap:** upstream path-dependent rules such as `pkcs12-file` and `kubernetes-secret-yaml` must not be claimed as coverage when this adapter supplies text via stdin. Binary/no-text files have separate extraction and coverage limits. |

### Connection URL scope

The core URL rule identifies a literal nonempty password in URI userinfo and a
hostname or bracketed IPv6 address. It supports the listed schemes and
percent-encoded password characters, including short passwords, but is not a
full URI parser. It excludes placeholders such as `${DB_PASSWORD}` and
`<password>`, does not decode embedded encodings, and does not detect every
reserved or unescaped character, multi-host topology, JDBC/ODBC syntax,
query-parameter password, passwordless URL or unrelated scheme. Userinfo
examples in documentation can still be flagged. Global upstream allowlists
apply. The password is never returned in LeakGuard findings; no network request
is made to the URL.

## Presidio and open-source options

- [Presidio's supported entities](https://presidio.dataprivacystack.org/supported_entities/)
  focus on PII, not a built-in comprehensive secret catalog. Its
  [maintainer discussion](https://github.com/data-privacy-stack/presidio/discussions/1370)
  explicitly suggested integrating a secret scanner; it was unanswered in 2024.
  Custom Presidio recognizers are possible, but this research did not identify a
  maintained, comprehensive native Presidio secret-recognizer package suitable
  for adoption. That is a research result, not proof no such package exists.
- [Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml)
  already provides the default catalog used here and is MIT licensed. Reuse its
  versioned scanner, rather than duplicate 222 patterns in Presidio. The
  upstream project describes itself as feature-complete; monitor rule freshness
  and test upgrades. Default rules are embedded in the separately installed
  binary, not bundled in the Python wheel.
- [Yelp detect-secrets](https://github.com/Yelp/detect-secrets) is an Apache-2.0
  Python scanner with plugin and baseline support; evaluate it as an independent
  offline comparator where additional generic/context coverage is needed.
- [Betterleaks](https://github.com/betterleaks/betterleaks), maintained by the
  Gitleaks authors, is MIT licensed and a candidate for future evaluation given
  Gitleaks' security-patches-only status. Its CLI and rules are not assumed to
  be a drop-in replacement. Pin and compare a specific release, explicitly keep
  validation disabled, and verify compatibility with LeakGuard's transport,
  redaction and offline guarantees before considering a migration.
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) and
  [Kingfisher](https://github.com/mongodb/kingfisher) offer broad provider
  detectors and optional live validation. Their repositories identify AGPL-3.0
  and Apache-2.0 licenses respectively. Evaluate exact versions, licenses,
  offline behavior and secret-handling before integration; provider calls are
  outside LeakGuard's offline contract.
- [GitHub's supported pattern catalog](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns)
  is useful for a coverage inventory, but is not itself a Presidio plugin or an
  open-source ruleset to copy without review.

**Recommendation:** retain Gitleaks as the core credential engine, use Presidio
for PII, and add narrowly scoped LeakGuard rules for tested gaps. Avoid running
both engines over the same credential catalog by default; duplicate findings and
different severities complicate policy. A Presidio wrapper is justified only if
another caller specifically needs Presidio's entity/offset interface; it must
preserve offline operation, redaction and fail-closed error handling. Keep
firm-specific labels as explicitly configured private recognizers.

Follow-ups: expand synthetic positive, negative and boundary cases across
provider format versions; assess standalone HTTP authorization headers and
structured/config formats separately; benchmark candidate sources against a
labeled corpus; and pin/revalidate upstream rule changes. Randomness alone
cannot identify a generated password, and public identifiers, hashes, checksums,
fixtures, revoked keys and placeholders need careful treatment. Never test a
suspected credential by authenticating to a provider without explicit approval.
