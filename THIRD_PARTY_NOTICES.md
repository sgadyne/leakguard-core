# Third-party components

The source distribution contains the wrapper, adapters and synthetic tests; it does not vendor scanner binaries, upstream source forks, real fixtures or model weights.

| Component | Use | Upstream license |
| --- | --- | --- |
| Gitleaks | Required external detection executable; tested with 8.30.1 | MIT, https://github.com/gitleaks/gitleaks/blob/master/LICENSE |
| pypdf | Optional PDF text extraction | BSD-3-Clause, https://github.com/py-pdf/pypdf/blob/main/LICENSE |
| olefile | Optional Outlook compound-file extraction | BSD, https://github.com/decalage2/olefile/blob/master/LICENSE.txt |
| cachetools | Bounded in-process redacted observation LRU | MIT, https://github.com/tkem/cachetools/blob/master/LICENSE |
| ignore | Optional native directory navigation helper | Unlicense or MIT, https://github.com/BurntSushi/ripgrep/tree/master/crates/ignore |

The wrapper's MIT license does not replace the licenses of separately installed dependencies. Preserve dependency notices when redistributing those components. No detect-secrets/PII-model package is required or bundled; they may be integrated as separate plugins. Python and Git are separately installed runtimes/tools under their own licenses.
