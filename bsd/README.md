# Kunci on FreeBSD

This directory contains FreeBSD-specific resources for using Kunci with ZFS native encryption.

## Overview

Kunci now supports binding Clevis pins to ZFS encrypted datasets, allowing automatic unlocking of encrypted ZFS datasets during boot using network-bound decryption (Tang/Remote pins).

## Prerequisites

- FreeBSD 13.0 or newer
- OpenZFS 2.4.0 or newer with native encryption support
- Rust toolchain (for building from source)

## Installation

### Building from Source

```bash
# Install Rust (if not already installed)
pkg install rust

# Clone the repository
git clone https://github.com/your-org/kunci.git
cd kunci

# Build the project
cargo build --release

# Install the binaries
cp target/release/kunci /usr/local/bin/
```

### Using the Installation Script

Alternatively, run the provided installation script:

```bash
cd bsd
./install.sh
```

## Configuration

### 1. Create an Encrypted ZFS Dataset

```bash
# Create a pool if you don't have one
zpool create mypool /dev/ada0

# Create an encrypted dataset
zfs create -o encryption=on -o keyformat=raw -o keylocation=prompt mypool/encrypted
```

### 2. Bind a Clevis Pin to the Dataset

```bash
# Bind using Tang pin
kunci zfs bind --dataset mypool/encrypted --pin tang --config '{"url":"http://tang.example.com"}'

# Bind using Remote pin
kunci zfs bind --dataset mypool/encrypted --pin remote --config '{"adv":"/path/to/adv.json","port":8609}'
```

### 3. Test Unlocking

```bash
# Unlock the dataset (requires network access for Tang/Remote)
kunci zfs unlock --dataset mypool/encrypted
```

## Boot Integration

### Using the rc.d Script

The provided `kunci_zfs` rc.d script can automatically unlock ZFS datasets during boot:

1. Copy the script to `/usr/local/etc/rc.d/`:

```bash
cp bsd/kunci_zfs /usr/local/etc/rc.d/
chmod 555 /usr/local/etc/rc.d/kunci_zfs
```

2. Enable the service in `/etc/rc.conf`:

```bash
# Add to /etc/rc.conf
kunci_zfs_enable="YES"
kunci_zfs_datasets="mypool/encrypted"
```

3. Optional: Specify additional options:

```bash
kunci_zfs_opts="--log-level debug --log-modules tang,zfs"
```

### Manual Boot Integration

If you prefer to integrate manually, add the following to your `/etc/rc.local`:

```bash
# Unlock ZFS datasets with Kunci
for dataset in mypool/encrypted otherpool/root; do
    /usr/local/bin/kunci zfs unlock --dataset $dataset || echo "Failed to unlock $dataset"
done
```

## Configuration Files

### Kunci Configuration

Kunci can be configured via a configuration file at `/usr/local/etc/kunci.conf` or `~/.config/kunci/config`. Example:

```json
{
  "default_server": "http://tang.example.com",
  "timeout": 30,
  "log_level": "info",
  "log_modules": "tang,zfs"
}
```

### ZFS Properties

Kunci uses the following ZFS properties:

- `kunci:jwe`: Stores the Clevis JWE (encrypted wrapping key)
- `kunci:pin`: (Optional) Pin name for unlocking

You can view these properties with:

```bash
zfs get -r kunci:jwe mypool
```

## Troubleshooting

### Common Issues

1. **Dataset not found**: Ensure the dataset exists and is encrypted.
2. **Network unreachable**: For Tang/Remote pins, ensure network is available during boot.
3. **Permission denied**: The rc.d script runs as root; ensure it has access to necessary resources.

### Debugging

Enable core logging:

```bash
kunci --log-level debug --log-modules tang,zfs zfs unlock --dataset mypool/encrypted
```

Check system logs:

```bash
tail -f /var/log/messages
```

### Testing Without Boot

Test the unlocking process manually before configuring boot:

```bash
# Unload the key
zfs unload-key mypool/encrypted

# Try unlocking with Kunci
kunci zfs unlock --dataset mypool/encrypted
```

## Security Considerations

1. **Network Security**: Ensure Tang server communication is secure (HTTPS recommended).
2. **Key Storage**: The encrypted wrapping key is stored in a ZFS property, which is only accessible to root.
3. **Boot Order**: Ensure network is available before `kunci_zfs` runs (it should run after networking).

## Uninstallation

To remove Kunci from your system:

1. Unbind all datasets:

```bash
kunci zfs unbind --dataset mypool/encrypted
```

2. Remove the rc.d script:

```bash
rm /usr/local/etc/rc.d/kunci_zfs
```

3. Remove from `/etc/rc.conf`:

```bash
# Remove or comment out the kunci_zfs lines
kunci_zfs_enable="NO"
```

4. Remove the binary:

```bash
rm /usr/local/bin/kunci
```

## Support

For issues and questions, please refer to the main [Kunci documentation](../README.md) or file an issue on GitHub.
