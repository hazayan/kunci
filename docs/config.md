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

On the client:

```
kunci show-keys --admin-sock /var/run/kunci-admin.sock --hash S256
```
