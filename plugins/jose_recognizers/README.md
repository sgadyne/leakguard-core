# LeakGuard JOSE recognizers

This optional package provides a native Presidio `EntityRecognizer` for bounded
structural review of compact JOSE values. It emits `JOSE_COMPACT_JWE` for a
five-part compact JWE shape and `JOSE_COMPACT_JWS_CANDIDATE` for a three-part
JWS/JWT-shaped candidate. `JOSE_COMPACT_UNVERIFIED` marks bounded, parseable
compact candidates with unsupported algorithms or critical extensions. These
labels describe serialization structure only; they do not establish credential
exposure, signature validity, issuer, current validity, or impact. The
recognizer emits no matched values or source snippets.
An empty GCM ciphertext, an empty JWS payload, and an `alg: none` JWS signature
can be structurally valid; none is treated as proof of actionable exposure.

Register the factory explicitly through the Presidio detector's native
recognizer-module option, and include all three entity names in that detector's
explicit entity allowlist:

```json
{
  "entities": ["JOSE_COMPACT_JWE", "JOSE_COMPACT_JWS_CANDIDATE", "JOSE_COMPACT_UNVERIFIED"],
  "recognizer-modules": ["jose_recognizers.plugin:build_recognizers"],
  "recognizer-options": "{}"
}
```

The recognizer uses exact source offsets and does not parse or interpret payload
content, decrypt, decompress, fetch keys, or access the network. It checks
base64url alphabet, canonical pad bits, and decoded byte lengths for compact
segments without materializing their decoded payload bytes. Only the bounded
protected header is decoded and parsed as duplicate-free JSON. It checks
content-encryption and key-management lengths, permits an empty encrypted-key
segment only for recognized direct modes, and reports unsupported algorithms
or critical extensions as `JOSE_COMPACT_UNVERIFIED`. Paired single/double
asterisks and inline backticks can delimit a candidate; delimiters are excluded
from the reported offsets, and unpaired asterisks are rejected.

High-confidence JWE labels support key-management algorithms `dir`,
`ECDH-ES`, `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`, `A128KW`, `A192KW`, `A256KW`,
`ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`, `A128GCMKW`,
`A192GCMKW`, `A256GCMKW`, and `PBES2-HS256+A128KW`,
`PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`. RSA-wrapped JWE keys and RSA/PS JWS
signatures are high-confidence only at 256 through 1024 decoded bytes (2048
through 8192 bits); other bounded lengths remain unverified. ECDH public-key
shape checks support EC `P-256`, `P-384`, and `P-521`, and OKP `X25519` and
`X448`, using canonical base64url and fixed coordinate widths without curve
arithmetic. Other key types and curves remain unverified. Supported content
encryption algorithms are `A128GCM`, `A192GCM`, `A256GCM`, `A128CBC-HS256`,
`A192CBC-HS384`, and `A256CBC-HS512`. `zip=DEF` is recognized as a header
value, but payloads are never decompressed. GCM key-wrap `iv`/`tag` and PBES2
`p2s` values require canonical base64url. High-confidence JWS candidates support `none`, `HS256`,
`HS384`, `HS512`, `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`, `PS256`,
`PS384`, `PS512`, and `EdDSA`. Every critical extension is unverified because
this recognizer does not interpret application extensions. The registry,
RSA minimum-size, and EC coordinate-width constraints follow [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html).
Inputs over 16 Mi
characters fail explicitly. Tokens are capped at 16 Ki characters, decoded
headers at 4 Ki bytes and nesting depth 32, candidate input at 1 Mi characters,
and output at 2,048 matches. A recognizable JOSE candidate exceeding its token
or header cap fails the scan explicitly rather than being treated as a clean
result; other oversized dotted runs are outside the recognizer's coverage.

Keep generic JWE findings at review severity by default. Provider/authentication
context and exposure policy belong to separate downstream rules; structural
confidence is not a calibrated probability or a credential-validity signal.

Focused tests use synthetic inputs and need Presidio Analyzer 2.2.365.

Published serialization-vector tests use compact examples from [RFC 7516
Appendix A.1 and A.2](https://www.rfc-editor.org/rfc/rfc7516.txt) and [RFC 7515
Appendix A.1](https://www.rfc-editor.org/rfc/rfc7515.txt). These static public
examples are format positives only; their presence does not establish
actionable exposure, and the tests do not validate their cryptography.
