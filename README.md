# Kunci

Kunci is a Rust implementation of the Tang and Clevis protocols, with a
production-facing focus on Tang server operation and FreeBSD ZFS native
encryption workflows.

## Current Scope

The parts of Kunci that are suitable to describe as current public functionality
are:

- a Tang-compatible server
- a client that can fetch advertisements, recover keys, and perform
  Tang/Clevis encrypt and decrypt operations
- FreeBSD ZFS bind, unlock, unbind, and list flows built around `kunci:jwe`
  and related dataset properties
- a local admin socket path for server key inspection via `show-keys`

The repository also contains additional pin and storage code, but not all of it
is complete enough to present as production-ready.

## What Works Today

### Tang Server

`kunci-server` serves Tang advertisements and recovery endpoints, supports
server key management from a JWK directory, and can expose a local admin Unix
socket for operational commands.

### Client Operations

`kunci` currently supports:

- `fetch-adv`
- `recover`
- `encrypt`
- `decrypt`
- `show-keys`
- `zfs bind`
- `zfs unlock`
- `zfs unbind`
- `zfs list`

### FreeBSD ZFS Integration

Kunci supports binding Tang or Remote pin data to native-encrypted ZFS datasets
on FreeBSD and recovering wrapping keys later for unlock flows.

The current ZFS-facing property model includes:

- `kunci:jwe`
- `kunci:pin`

This is the surface that has been driving the related `zhamel` bootloader work.

## Incomplete or Experimental Areas

These areas exist in the tree but should not be described as production-ready:

- LUKS and dm-crypt integration
- TPM2-backed unlock
- Yubikey-backed unlock
- some auxiliary pin implementations intended for experimentation or testing

In particular, several LUKS operations are still stubs, and TPM2 support is not
complete beyond configuration and partial plumbing.

## Trust Model

Tang clients should provide an advertisement and URL, and by default should pin
trust to a known signing key thumbprint unless TOFU is explicitly enabled.
Server-side TOFU support is disabled by default and must be enabled
intentionally.

Enable TOFU support on the server:

```bash
kunci-server --allow-tofu
```

Show server signing key thumbprints via the local admin socket:

```bash
kunci-server --admin-sock /var/run/kunci-admin.sock --admin-gid 1000
kunci show-keys --admin-sock /var/run/kunci-admin.sock --hash S256
```

## Build

Prerequisites:

- Rust via `rustup`
- system libraries required by the enabled feature set

Build the main workspace:

```bash
cargo build --workspace --features=full
```

Run tests:

```bash
cargo test --workspace --features=full
```

Build release artifacts:

```bash
cargo build --workspace --features=full --release
```

Feature flags:

- `full`: enables the main cryptographic and network dependencies
- `tpm2`: enables TPM2-specific code paths
- `yubikey`: enables Yubikey-specific code paths

## Examples

Fetch a Tang advertisement and emit a client config:

```bash
kunci --server http://tang.example.com fetch-adv --as-config
```

Encrypt with a Tang pin:

```bash
kunci encrypt --pin tang --config tang.json --input plaintext.txt --output encrypted.jwe
```

Decrypt with a Tang pin:

```bash
kunci decrypt --pin tang --config tang.json --input encrypted.jwe --output plaintext.txt
```

Bind a ZFS dataset:

```bash
kunci zfs bind --dataset zroot/ROOT/default --pin tang --config tang.json
```

Unlock a ZFS dataset:

```bash
kunci zfs unlock --dataset zroot/ROOT/default
```

## Repository Layout

```text
core/      Shared protocol, pin, JOSE, Tang, and ZFS logic
client/    CLI client
server/    Tang-compatible server
dmcrypt/   LUKS and dm-crypt integration work
bsd/       FreeBSD-specific integration material
```

## Security Notes

- cryptographic operations are implemented in Rust with established libraries
- sensitive material is zeroized where practical
- trust-on-first-use must be explicitly enabled
- review incomplete features carefully before deploying them in sensitive paths

## License

Kunci is licensed under the BSD 2-Clause license. See [LICENSE](LICENSE).
