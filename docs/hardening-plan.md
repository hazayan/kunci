## Kunci hardening plan

### Scope freeze
- Freeze feature work until the acceptance gates below are met.
- Only correctness, testability, and protocol parity work is allowed.

### Acceptance gates (must pass before zjudo integration resumes)
1) Protocol round-trip tests: encrypt -> recover -> decrypt for Tang (unit tests).
2) Client/server wire path: HTTP /adv and /rec basic success/fail tests (if lightweight).
3) Coverage: >= 80% line coverage for core, client, server.
4) Fuzz: JWS/JWE/config fuzz targets build and run for a minimum duration.
5) Interop sanity: confirm message formats match latchset/anatol behavior.

### Test strategy (incremental, unit-first)
- Unit: Tang protocol encrypt/decrypt round-trip with in-process TangServer.
- Unit: JWE header invariants (kid matches an exchange key in adv).
- Unit: Config normalization (raw adv JSON vs wrapped adv).
- Integration: client fetch-adv -> parse adv -> encrypt -> recover via server.
  - Keep optional if it requires heavy infra; otherwise, keep as TODO.

### Coverage
- Use `scripts/coverage.sh` (llvm-cov) for core/client/server.
- Coverage target should be deterministic and run without network access.

### Fuzz
- Use existing `fuzz/` targets:
  - `jwk_parse`, `thumbprint`, `tang_advertisement`, `jws_payload`,
    `jwe_compact`, `pin_config`.
- Require `cargo fuzz` and run each target for a short time budget.

### Interop checklist (reference implementations)
Sources:
- `anatol/clevis.go` + `anatol/tang.go`
- `latchset/tang` and `latchset/clevis`

Checklist:
- Advertisement JWS format: JSON serialization with `payload` and `signatures`.
- `/adv` returns a signed JWKSet with signing + exchange public keys.
- `/rec/{kid}` expects kid as SHA-256 thumbprint of exchange key.
- JWE header fields: `alg=dir`, `enc=A256GCM`, `kid`, `epk`, `clevis` node.
- McCallum-Relyea exchange: key derivation and blinding follow spec.

### TODOs (if infra-heavy)
- Full interop run against latchset tangd binary.
- Networked integration test harness for `/rec` and `/adv`.
