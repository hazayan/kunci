---
title: Kunci Configuration Reference
---

# Kunci Configuration Reference

This document describes Kunci pin configuration formats and trust policies.

## Tang Pin

### Fields

- `adv` (string, required): Tang advertisement JWS. Can be a raw JWS string or a JSON object (will be serialized).
- `url` (string, optional): Tang server URL. Required when `trust=true` to fetch `/policy`.
- `thp` (string, optional): Trusted signing key thumbprint. Enforces strict trust.
- `trust` (bool, optional): Allow TOFU (trust on first use) if the server allows it. Default: `false`.

### Strict Trust (Default)

When `trust=false`, the client **requires** a trusted signing key thumbprint (`thp`). The advertisement must be signed by that key or the operation fails.

### TOFU

When `trust=true`, the client will allow TOFU **only if** the server policy allows it. The client checks `/policy` and refuses if the server disallows TOFU.

### Example (Strict Trust)

```json
{
  "tang": {
    "adv": "<JWS>",
    "url": "http://tang.example",
    "thp": "S256:...."
  }
}
```

### Example (TOFU Allowed)

```json
{
  "tang": {
    "adv": "<JWS>",
    "url": "http://tang.example",
    "trust": true
  }
}
```

## Remote Pin

### Fields

- `adv` (string, required): Tang advertisement JWS or a file path.
- `port` (number, optional): TCP port (default: `8609`).
- `thp` (string, optional): Trusted signing key thumbprint.
- `trust` (bool, optional): Allow TOFU (default: `false`).

### Example

```json
{
  "remote": {
    "adv": "/path/to/adv.json",
    "port": 8609,
    "thp": "S256:...."
  }
}
```

## CLI `--trust`

The `kunci` client accepts `--trust` for tang/remote pins and injects `"trust": true` into the pin config. It is only valid for:

- `kunci encrypt --pin tang|remote --config ... --trust`
- `kunci decrypt --pin tang|remote --config ... --trust`
- `kunci zfs bind --pin tang|remote --config ... --trust`
- `kunci zfs unlock --pin tang|remote --config ... --trust`
- `kunci fetch-adv --as-config --trust`

## Admin Socket

Admin commands (`show-keys`, `backup-keys`, and `unlock-keys`) use a local
Unix socket and require the server to be configured with:

```
kunci-server --admin-sock /var/run/kunci-admin.sock --admin-gid <GID>
```

The server can also load the same options from a JSON config file:

```json
{
  "bind": "127.0.0.1",
  "port": 8080,
  "directory": "/var/db/tang",
  "allow_tofu": false,
  "admin_sock": "/var/run/kunci-admin.sock",
  "admin_gid": 1000,
  "log_level": "info",
  "log_modules": "tang,zfs,remote",
  "log_json": false
}
```

Run it with:

```
kunci-server --config /etc/kunci/server.json
```

Command-line flags override values from the config file when both are provided. Boolean flags still work as plain flags, and can also be forced off with forms such as `--allow-tofu=false` or `--log-json=false`. Kebab-case field names such as `allow-tofu` and `admin-sock` are accepted as aliases for the underscore names.

On the client:

```
kunci show-keys --admin-sock /var/run/kunci-admin.sock --hash S256
```

If an encrypted key backend cannot be unlocked during server startup, the HTTP
server remains available in a locked state. Tang advertisement and recovery
requests return a locked error until the key store is loaded through the admin
socket:

```
kunci unlock-keys \
  --admin-sock /var/run/kunci-admin.sock \
  --backend fido2 \
  --fido2-metadata-file /etc/kunci/fido2-credential.json \
  --fido2-device auto \
  --fido2-pin-file /run/kunci/fido2.pin
```

`unlock-keys` can also load an encrypted backup artifact directly when paired
with `--backup` and the matching backup backend options.

## Server Key Backend

`kunci-server` defaults to the Tang-compatible plaintext filesystem backend:

```json
{
  "directory": "/var/db/tang",
  "key_backend": "filesystem"
}
```

For development and migration testing, the server can load an encrypted bundle
protected by a raw 32-byte wrapping key file:

```json
{
  "directory": "/var/db/tang",
  "key_backend": "encrypted-bundle",
  "encrypted_bundle": {
    "wrapping_key_file": "/etc/kunci/server-wrap.key"
  }
}
```

The raw wrapping key file must contain exactly 32 bytes. This provider is useful
for development, migration, and fallback recovery workflows.

When `kunci-server` is built with the `fido2` feature, it can derive the
encrypted bundle wrapping key from a local FIDO2 authenticator using the
`hmac-secret` extension:

```json
{
  "directory": "/var/db/tang",
  "key_backend": "fido2",
  "fido2": {
    "metadata_file": "/etc/kunci/fido2-credential.json",
    "device": "auto",
    "pin_file": "/run/kunci/fido2.pin"
  }
}
```

The metadata file stores non-secret credential data: relying-party ID,
credential ID, salt, user-verification policy, user-presence policy, and the
wrapping-key derivation label. It does not store the wrapping key or Tang JWKs.
If `device` is `auto`, kunci requires exactly one attached authenticator;
otherwise pass the libfido2 device path explicitly.

Key management commands:

```sh
kunci-server key init \
  --backend encrypted-bundle \
  --directory /var/db/tang \
  --wrapping-key-file /etc/kunci/server-wrap.key

kunci-server key migrate \
  --from filesystem \
  --to encrypted-bundle \
  --source-directory /var/db/tang.plain \
  --directory /var/db/tang \
  --wrapping-key-file /etc/kunci/server-wrap.key

kunci-server key unlock-test \
  --backend encrypted-bundle \
  --directory /var/db/tang \
  --wrapping-key-file /etc/kunci/server-wrap.key

kunci-server key fido2-enroll \
  --metadata-file /etc/kunci/fido2-credential.json \
  --rp-id kunci-server.local \
  --device auto \
  --pin-file /run/kunci/fido2.pin

kunci-server key migrate \
  --from filesystem \
  --to fido2 \
  --source-directory /var/db/tang.plain \
  --directory /var/db/tang \
  --fido2-metadata-file /etc/kunci/fido2-credential.json \
  --fido2-device auto \
  --fido2-pin-file /run/kunci/fido2.pin

kunci-server key unlock-test \
  --backend fido2 \
  --directory /var/db/tang \
  --fido2-metadata-file /etc/kunci/fido2-credential.json \
  --fido2-device auto \
  --fido2-pin-file /run/kunci/fido2.pin
```

Encrypted admin backup and restore:

```sh
kunci backup-keys \
  --admin-sock /var/run/kunci-admin.sock \
  --backend raw-file \
  --wrapping-key-file /etc/kunci/backup-wrap.key \
  --output tang-keys.kunci-backup

kunci backup-keys \
  --admin-sock /var/run/kunci-admin.sock \
  --backend fido2 \
  --fido2-metadata-file /etc/kunci/backup-fido2-credential.json \
  --fido2-device auto \
  --fido2-pin-file /run/kunci/backup-fido2.pin \
  --output tang-keys.kunci-backup

kunci-server --key-backend encrypted-bundle key restore \
  --input tang-keys.kunci-backup \
  --directory /var/db/tang-restored \
  --wrapping-key-file /etc/kunci/server-wrap.key

kunci unlock-keys \
  --admin-sock /var/run/kunci-admin.sock \
  --backend fido2 \
  --fido2-metadata-file /etc/kunci/fido2-credential.json \
  --fido2-device auto \
  --fido2-pin-file /run/kunci/fido2.pin
```

The admin backup command asks the running server to encrypt its in-memory key
store and returns only the encrypted backup artifact over the admin socket. The
artifact does not expose plaintext JWK material to the client. FIDO2-backed
backup should use a distinct metadata file and preferably a distinct
authenticator or credential from the one used for normal server start. See
[Trust Services Backup](trust-services-backup.md) for the primary/backup host
operational model.
