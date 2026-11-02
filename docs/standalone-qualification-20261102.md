# Standalone qualification — November 2, 2026

The installed macOS arm64 beta was built from
**634442421e6fdf60922639c3d3354f5946e8b530**. The subsequent closeout changes
only smoke-check tools, regression tests and documentation. Product packages,
desktop source, generated UI/static assets and deployment code remain byte-for-byte
unchanged from that installed source; the closeout diff and retained product-file
manifest verify this boundary. No app rebuild is needed for this test/docs change.

| Tested identity | Value |
| --- | --- |
| Product source | 634442421e6fdf60922639c3d3354f5946e8b530 |
| Target / bundled Python | macOS arm64 / CPython 3.11.16 |
| Installed runtime identity | 69afa926ce02221d9d1986f430297c00b234c6521040a686e5836a7bd2ee2bb9 |
| Mac ZIP SHA-256 | 40525b633e8be33f8a05f3a5a03fd506ec9ca4583baea5ed6dfe89a751012a80 |
| Resource manifest SHA-256 | ae23426bbc39894a83f08350afc48876f5fffe8ae17099d5ffcd777e5dad88d3 |
| Application-file manifest SHA-256 | 8cd26d9ac6077190e66ec5864baa1a25fb2163819a53638b4680ee0e6a40c9b8 |
| Signing | Local ad-hoc signature; deep/strict verification passed; not notarized |

The archive receipt was created before the later native acceptance run and still
records its then-current native-acceptance status. The subsequent runtime and
upgrade receipts establish the checks below without changing the sealed archive.
Raw local receipts, profile inventories and private paths are not published here.

## Passed, with bounded claims

- Nine preparer checks and four installed native APFS storage tests passed.
  The prior Linux overlay restriction was preserved; supported native relocation
  is now separately exercised.
- The exact packaged runtime/API synthetic journey passed authentication, single
  profile ownership, expected finding and review, explicit vault
  save/edit/reveal/backup/restore, independent locks, offline plugin
  installation/conformance/explicit enable, disposable Git guards, restart,
  redaction and owned safe shutdown. The successful native run took 39.278 seconds.
- Native application launch and Settings, safe quit and relaunch passed. The
  bundled icon matched the source asset; signature and ZIP integrity checks passed.
  These observations are narrower than complete native session/tray qualification.
- Explicit runtime upgrade created a verified backup. All 15,759 preserved files
  matched their pre-upgrade bytes, with none missing; only the runtime marker and
  executable-path settings changed. Scan storage and the credential vault remained
  locked. No profile filenames or contents are included in this public summary.
- Prior remote qualification of the same product source passed 431 applicable
  installed tests and 147 subtests, independent seven-wheel/103-file identity
  checks, and the authenticated browser workflow. The browser recorded 106
  synthetic positives and zero negative findings, exact sparse cursor paging,
  profile rollback, review/vault/locks/restart, 38 captures and 36 layout/contrast
  cases. Minimum measured viewport-visible text contrast was 4.596.
- The finite fairness proof completed all nine synthetic content versions across
  arrivals, deadline deferral, encrypted reopen and replacement. It uses real
  source-bound acquisition/publication with a deterministic detector. This is
  not a full-machine coverage result or a population latency guarantee.

## Smoke-check correction

The old repository native check incorrectly required a managed inventory job's
coverage label to become complete. Managed jobs deliberately retain incomplete
coverage, including when this finite synthetic source has finished.

The native check disables automatic discovery in its fresh owned profile before\nopening scan storage, then opts in with the single synthetic file it creates. It
requires the exact completed job and managed source, one inspected file and one
enumerated directory, known integer counts, no pending/error/omitted inventory,
no pending files/directories, no last error, and unchanged fixture bytes. The
expected active verified finding must belong to that same source and exact file;
review verification follows the original returned cursors, including sparse
empty pages. Ordinary CLI journeys retain the strict complete-coverage path.

Focused negative controls cover pending old work, failures, omissions,
unsupported entries, wrong job/source/file, unknown or invalid counts/types and
cursor cycles. The scoped helper also passed an isolated installed-runtime replay
without changing the incomplete coverage label. This corrects test expectations;
it does not change product coverage or turn a finding into a clean-machine claim.

## Still unrun or deferred

Native keychain opt-in, OS session lock, sleep/resume, login start, clipboard
behavior, light/dark tray rendering and Finder presentation still require explicit
native checks. An exact-build private baseline replay and live SSH regression
were not run for this build. Remote SSH evidence is controlled local
protocol/session simulation, not a network acquisition claim.

Live queue-age buckets, live stage progress and a universal oldest-work bound
remain unqualified. Native line-only detector locations do not establish exact
span deduplication. Larger Sampo integration, native event/access providers,
recursive archives, fleet management and the broader plugin catalogue remain
deferred; this closeout does not claim they are implemented.

Qualification used local/guarded checks, not new Actions execution. No new release
or tag is published by this closeout.
