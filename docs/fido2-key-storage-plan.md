# FIDO2 Server Keystore Plan

## Goal

Allow `kunci-server` to protect its Tang server keys with a local FIDO2
authenticator connected to the machine running the server.

This is server-side key storage only. It does not change the client unlock
flow, the bootloader, booster, zhamel, or ZFS dataset binding format.

## Current Server Key Flow

`kunci-server` currently loads a `KeyStore` from a filesystem directory through
`KeyStore::load()` in `core/src/keys.rs`. The store contains:

- signing keys, currently ES512 JWKs, used to sign advertisements
- exchange keys, currently ECMR P-256 JWKs, used for Tang recovery
- rotated keys, represented as hidden `.jwk` files

`TangServer` keeps the resulting `KeyStore` in memory. Advertisement signing
uses the signing private key. Recovery uses the exchange private key for the
McCallum-Relyea operation.

## Important Constraint

A FIDO2 authenticator is not a drop-in replacement for those Tang private-key
operations:

- WebAuthn/FIDO assertions do not provide arbitrary ES512 JWS signing over
  Kunci advertisement payloads.
- FIDO2 credentials do not expose the ECMR scalar multiplication operation
  needed by Tang recovery.
- Many authenticators use ES256 credentials, while Kunci currently uses ES512
  signing keys and ECMR exchange keys.

So the practical and clean design is a FIDO-protected keystore backend: Tang
JWKs remain Tang JWKs, but they are encrypted at rest and are only unwrapped
when the local authenticator derives the keystore wrapping key.

## Proposed Backend

Add a keystore abstraction under `core/src/keys.rs`:

```rust
trait ServerKeyBackend {
    fn load(&self) -> Result<KeyStore>;
    fn create_if_empty(&self) -> Result<()>;
    fn rotate(&self, thumbprints: &[&str]) -> Result<usize>;
}
```

Initial implementations:

- `FilesystemKeyBackend`: current behavior, plain JWK files in a directory.
- `Fido2WrappedFilesystemKeyBackend`: encrypted JWK bundle or encrypted JWK
  files on disk, unwrapped via a local FIDO2 authenticator at server startup.

This keeps Tang protocol code unchanged and isolates storage policy from
advertisement/recovery logic.

## FIDO2 Mechanism

Use the FIDO2 `hmac-secret` extension.

Provisioning:

1. Create a FIDO2 credential for a stable RP ID, for example
   `kunci-server.local`.
2. Generate a random 32-byte salt.
3. Ask the authenticator for `hmac-secret(salt)`.
4. Derive a 32-byte keystore encryption key from that output with HKDF-SHA256.
5. Generate or import the Tang JWKs.
6. Encrypt the keystore material with AES-256-GCM.
7. Store encrypted material plus non-secret FIDO metadata on disk.

Server startup:

1. Read keystore metadata.
2. Locate the configured authenticator or scan compatible devices.
3. Ask for the same `hmac-secret(salt)`.
4. Derive the keystore encryption key.
5. Decrypt the Tang JWKs into memory.
6. Build the normal `KeyStore` and run the current server code unchanged.

Metadata to store:

```json
{
  "version": 1,
  "backend": "fido2-wrapped-filesystem",
  "rp_id": "kunci-server.local",
  "credential_id": "base64url...",
  "salt": "base64url-32-bytes",
  "uv": "discouraged",
  "up": true,
  "kdf": {
    "type": "hkdf-sha256",
    "info": "kunci server keystore fido2 v1"
  },
  "cipher": "A256GCM"
}
```

The metadata is not secret, but should still be root-readable only because it
describes recovery policy and attached hardware.

## Storage Layout Options

Option A: encrypted bundle

- Store one encrypted JSON object containing all active and rotated JWKs.
- Simpler atomic load and simpler authenticated metadata.
- Rotation rewrites the bundle.

Option B: encrypted per-key files

- Preserve the existing Tang-like file layout more closely.
- Allows per-key rotation without rewriting every key.
- Slightly more metadata and failure modes.

Start with option A. It is easier to reason about and test. We can add per-key
files later if operational needs justify it.

## CLI / Config Surface

Server config:

```json
{
  "key_backend": "fido2-wrapped-filesystem",
  "directory": "/var/db/tang",
  "fido2": {
    "rp_id": "kunci-server.local",
    "device": "auto",
    "uv": "discouraged",
    "up": true
  }
}
```

Suggested admin commands:

```sh
kunci-server key init --backend fido2 --directory /var/db/tang --device auto
kunci-server key migrate --from filesystem --to fido2 --directory /var/db/tang
kunci-server key unlock-test --directory /var/db/tang
kunci-server key rotate --directory /var/db/tang
kunci show-keys --admin-sock /var/run/kunci-admin.sock
kunci backup-keys --admin-sock /var/run/kunci-admin.sock --backend fido2 --output tang-keys.kunci-backup
```

Exact CLI placement can be adjusted to the existing server/client split. The
important behavior is that initialization and migration are explicit operations,
not implicit side effects of normal server start.

## Admin Backup Command

Encrypted backup is in scope for the same server-key management feature. It is
not a separate protocol feature and should not change the Tang client-facing API.

The current admin socket only supports `show_keys`. Extend that local privileged
path with a `backup_keys` request that asks the running `kunci-server` to export
its in-memory `KeyStore` as an encrypted backup artifact. The client writes that
artifact to the requested storage path.

Important boundary: the admin command should not return plaintext JWKs. It
should return only an encrypted bundle plus metadata. If we ever need plaintext
export, make it a separate command with explicit naming and stronger operator
friction.

Backup flow:

1. The admin client connects to the local admin socket.
2. It requests `backup_keys` with a backup backend config.
3. The server serializes the active and rotated Tang JWKs from memory.
4. The server encrypts that serialized bundle using the selected backup
   backend.
5. The client writes the encrypted artifact to the configured destination.

For a FIDO2-locked backup, the backup backend can reuse the same encrypted
bundle format as the server keystore backend, but it should support an
independent FIDO2 credential and salt. That avoids coupling the operational
server-start token to the off-host backup token.

Suggested backup artifact shape:

```json
{
  "version": 1,
  "kind": "kunci-server-key-backup",
  "created_at": "2026-05-05T00:00:00Z",
  "source": {
    "signing_thumbprints": ["..."],
    "exchange_thumbprints": ["..."]
  },
  "encryption": {
    "backend": "fido2-wrapped-backup",
    "metadata": {
      "rp_id": "kunci-server-backup.local",
      "credential_id": "base64url...",
      "salt": "base64url-32-bytes",
      "uv": "discouraged",
      "up": true,
      "kdf": {
        "type": "hkdf-sha256",
        "info": "kunci server key backup fido2 v1"
      },
      "cipher": "A256GCM"
    }
  },
  "ciphertext": "base64url..."
}
```

Restore should also be explicit:

```sh
kunci-server key restore --input tang-keys.kunci-backup --directory /var/db/tang
```

Restoring should validate that the backup contains at least one signing key and
one exchange key before replacing or initializing the target keystore.

## Security Notes

- If the FIDO2 authenticator is lost or reset, the encrypted server keystore is
  unrecoverable unless an export, backup authenticator, or recovery backend was
  provisioned.
- Prefer a distinct backup authenticator or a separately enrolled credential for
  backup artifacts. Reusing the online server-start credential for backups
  reduces operational independence.
- Backup artifacts remain highly sensitive even when encrypted. Treat them as
  key material: keep access restricted, log only metadata, and never print
  decrypted JWKs through the admin protocol.
- User presence is useful for interactive server start, but can be operationally
  awkward after reboot. Make it configurable.
- User verification changes hmac-secret output. Store and enforce the UV policy
  consistently.
- The server should log that a FIDO2 keystore was unlocked, but must never log
  JWK contents, derived secrets, salts as secrets, or decrypted bundle material.
- Key material exists in server memory after startup just as it does today. This
  feature protects keys at rest, not against a fully compromised running host.

## Dependencies

Use libfido2 first. It supports the needed `hmac-secret` flow and is available
on Linux and FreeBSD. Kunci can either use a Rust binding if it exposes the
needed calls cleanly or keep a small internal FFI wrapper.

Builder/IaC packages to track:

- Linux: `libfido2`, `hidapi` or distro equivalent, USB HID access rules.
- FreeBSD: `libfido2` package/port and USB HID access for the server user.
- Test nodes need physical FIDO2 devices attached.

## Test Plan

1. Unit-test metadata parsing and validation.
2. Unit-test encrypt/decrypt of a keystore bundle with a fake FIDO2 backend.
3. Unit-test migration from filesystem JWK directory to encrypted bundle.
4. Unit-test rotation through the backend abstraction.
5. Unit-test admin backup artifact generation with a fake FIDO2 backend.
6. Unit-test restore validation from encrypted backup artifacts.
7. Add ignored/manual tests for real devices:
   - init backend with a FIDO2 authenticator
   - start server and fetch `/adv`
   - recover through `/rec/{kid}`
   - export encrypted backup through the admin socket
   - restore encrypted backup into a fresh key directory
   - fail cleanly with device absent
   - fail cleanly with wrong authenticator
   - validate touch timeout and PIN/UV policy
8. Test on Linux first, then FreeBSD.

## Implementation Steps

1. Introduce a storage backend abstraction without changing Tang protocol code.
2. Move current filesystem loading into `FilesystemKeyBackend`.
3. Add encrypted bundle serialization/deserialization for `KeyStore`.
4. Add fake FIDO2 backend and tests.
5. Add libfido2 backend behind a `fido2` feature.
6. Add explicit init/migrate/unlock-test commands.
7. Extend the admin protocol with encrypted `backup_keys` and explicit restore
   commands.
8. Run real-device validation.
9. Update `foji-bsd`, `foji-artix`, and builder IaC notes with libfido2
   dependencies once the real-device path is proven.
