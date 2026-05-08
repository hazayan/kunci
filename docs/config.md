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

Admin commands (e.g., `show-keys`) use a local Unix socket and require the server to be configured with:

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

The raw wrapping key file must contain exactly 32 bytes. This is a temporary
provider for the encrypted keystore milestone; the production backend is
expected to derive the wrapping key from FIDO2 `hmac-secret`.

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
```

Encrypted admin backup and restore:

```sh
kunci backup-keys \
  --admin-sock /var/run/kunci-admin.sock \
  --backend raw-file \
  --wrapping-key-file /etc/kunci/backup-wrap.key \
  --output tang-keys.kunci-backup

kunci-server key restore \
  --input tang-keys.kunci-backup \
  --directory /var/db/tang-restored \
  --wrapping-key-file /etc/kunci/server-wrap.key
```

The admin backup command asks the running server to encrypt its in-memory key
store and returns only the encrypted backup artifact over the admin socket. The
artifact does not expose plaintext JWK material to the client. For this
milestone, `raw-file` is the only backup wrapping backend; FIDO2 wrapping will
replace it once the server has a hardware-backed wrapping-key provider.
