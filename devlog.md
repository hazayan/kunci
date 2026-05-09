[00001] [2026-05-05T16:50:36Z] [PLANNING] Documented server-side FIDO2 wrapped keystore direction for kunci-server keys and clarified that it protects Tang JWKs at rest rather than replacing Tang private-key operations.
[00002] [2026-05-05T16:55:00Z] [PLANNING] Extended the FIDO2 keystore plan with an admin-side encrypted backup and restore flow using the local admin socket and a FIDO2-locked backup artifact.
[00003] [2026-05-08T14:41:17Z] [IMPLEMENTATION] Started the encrypted server keystore milestone by adding Beads tracking, a server key backend abstraction, and an AES-256-GCM encrypted bundle backend with a static test wrapping-key provider.
[00004] [2026-05-08T14:44:54Z] [TEST] Validated the encrypted bundle backend with kunci-core and kunci-server tests, including round-trip load, wrong wrapping-key rejection, plaintext filesystem migration, and automatic encrypted bundle initialization.
[00005] [2026-05-08T15:14:20Z] [IMPLEMENTATION] Wired the encrypted-bundle key backend into kunci-server config and key management commands using a temporary raw 32-byte wrapping-key-file provider.
[00006] [2026-05-08T17:58:03Z] [IMPLEMENTATION] Added encrypted admin backup and restore for server keys using the existing encrypted bundle envelope and raw wrapping-key provider.
[00007] [2026-05-08T17:58:38Z] [TEST] Validated encrypted admin backup and restore with kunci-server, kunci-client, and kunci-core package tests.
[00008] [2026-05-08T19:01:40Z] [IMPLEMENTATION] Added an optional fido2-rs hmac-secret wrapping-key provider with FIDO2 enrollment metadata, server backend wiring, and FIDO2 admin backup options.
[00009] [2026-05-08T19:03:54Z] [TEST] Validated the FIDO2 wrapping provider changes with kunci-client, kunci-core, kunci-server tests and a kunci-server fido2 feature check.
[00010] [2026-05-08T19:19:06Z] [TEST] Validated FIDO2 hmac-secret wrapping on a TrustKey T120 with enrollment, filesystem-to-fido2 migration, unlock-test, encrypted admin backup, restore, and restored unlock-test.
[00011] [2026-05-09T01:51:00Z] [CONFIG] Encrypted the Beads issues export with git-crypt, granted GPG key 83D121B5F6A8A730 access, and documented the default encrypted Beads policy.
