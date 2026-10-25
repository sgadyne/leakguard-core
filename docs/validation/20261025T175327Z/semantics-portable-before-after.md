# Same-host portable 50-file diagnostic timing

Three fresh probes per source ran sequentially in paired baseline/integrated order on the same Linux host, using `/usr/bin/python3.11` 3.11.2, Git 2.39.5 and pinned Gitleaks 8.30.1 (SHA-256 `88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509`). Each version of the portable tool creates a fresh empty config/private state and the same 50 ordinary text fixtures, scans cold then warm, and deletes its fixtures. All six actual probes exited 0; baseline exit 0 means diagnostics executed, while all three integrated `--assert-fixed` checks passed.

| Source | Exact commit | Tree |
| --- | --- | --- |
| Baseline | `afe67930b1001f1e087edd4da57241fe86dc6ddc` | `a49b938937af2c954050773d7d8955f51b040b28` |
| Integrated | `cc48a6cf84f063c21ac9e51f954f1c5352799755` | `47790a446ff9ac122825d6e3e26ba1a0754b8179` |

Actual detached-worktree identities and clean status were checked before/after every probe. Heavy-wrapper lane-checkout identities refer to stable clean `ce1ea500`; each exact command instead selects its absolute baseline or integrated worktree script, which selects that worktree's core source. The structured supplemental JSON records both identities to avoid attributing these executions to the wrapper's checkout revision.

| Repetition | Baseline cold seconds | Baseline warm seconds | Integrated cold seconds | Integrated warm seconds |
| --- | ---: | ---: | ---: | ---: |
| 1 | 15.2149 | 0.0027 | 17.4690 | 0.2787 |
| 2 | 15.3570 | 0.0027 | 16.7170 | 0.3071 |
| 3 | 15.9296 | 0.0026 | 16.5906 | 0.2751 |
| Median | 15.3570 | 0.0027 | 16.7170 | 0.2787 |

Every cold sample reports 50 scanned files; every warm sample reports 50 unchanged files. These legacy-path timings are not equivalent correct-work or speedup measurements: in all three baseline positive-cache diagnostics, findings incorrectly fall from 1 to 0 on warm replay. Baseline hooks are non-executable and allow the staged credential commit (exit 0), and the required no-text document hook incorrectly exits 0. Integrated positives replay 1/1 with identical finding IDs, installed executable hooks reject the credential commit (exit 1), required document coverage is INCOMPLETE with hook exit 2, and output is redacted in every run. The separate final benchmark owns normalized final warm-equivalence/count evidence; no optimization claim follows from this comparison.

All probes used the heavy admission queue, the same locale/thread settings, no HOME override and ILMR's per-run private ephemeral TMPDIR. Cold means fresh semantic state/fixtures; OS page caches were not flushed and concurrent admitted host activity was not eliminated. This is same-host finite evidence, not a cross-platform timing claim.

| Probe | Heavy receipt | Private raw log |
| --- | --- | --- |
| Baseline 1 | `job-b398aed133334f73a050cfdd67020aaf.json` | `semantics-portable-baseline-1.raw.log` |
| Integrated 1 | `job-cd04707bfeb24e86bf908d524ad208fa.json` | `semantics-portable-integrated-1.raw.log` |
| Baseline 2 | `job-19cdc2aaaefd4a37a4f1a66b29c5d400.json` | `semantics-portable-baseline-2.raw.log` |
| Integrated 2 | `job-b6a8bf1b96924dbda9882ac14974c7a0.json` | `semantics-portable-integrated-2.raw.log` |
| Baseline 3 | `job-56406262c18a4a1882f849cc84dd9b6d.json` | `semantics-portable-baseline-3.raw.log` |
| Integrated 3 | `job-52406e7b086349aaa3cb0f15d0feaff8.json` | `semantics-portable-integrated-3.raw.log` |

Exact commands, allowlisted diagnostics, medians and cleanup are in `semantics-portable-before-after.json`; JSON was parsed after the ILMR prefix without copying raw errors or fixture values. Raw logs use mode 0600. One initial command was refused by ILMR `run.env.outside_box` for an explicit TMPDIR override (exit 3); it executed no probe and contributes no sample. Its separate admission receipt/log are retained, and the override was removed rather than bypassing the rule.

Both exact created detached worktrees and the unused initial temporary directory were removed after all runs. Only the original lane checkout remains registered; original run source was untouched. No production code or test changes, no running probe jobs.
