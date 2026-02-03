# Kunci: A Rust Implementation of Clevis/Tang

Kunci is a Rust implementation of the Clevis and Tang protocols for network-bound disk encryption (NBDE), developed with agent-assistant. It provides a comprehensive suite of cryptographic pins for use in automated decryption of encrypted storage.

## Project Overview

Kunci implements the Clevis framework for automated decryption using cryptographic "pins". These pins interface with various cryptographic backends to encrypt and decrypt data using keys derived from external systems (like a Tang server) or hardware tokens.

The project includes:
- A core library with the pin framework and protocol implementations
- A command-line client for encryption and decryption operations
- A cryptsetup plugin for LUKS integration
- A Tang server implementation for key management

## Supported Pins

### Tang Pin
Network-bound encryption using a Tang server. Supports ECDH key exchange with ECMR (McCallum-Relyea) protocol and ConcatKDF key derivation.
Strict trust is enforced by default; clients must provide a trusted signing key thumbprint (`thp`) unless TOFU is explicitly enabled by both server and client.

### Remote Pin
Reverse Tang protocol allowing a client to act as a proxy for a Tang server. Useful for network segmentation and firewall traversal.

### Yubikey Pin
Hardware token-based encryption using Yubikey's challenge-response capability. Supports slots 1 and 2 with PBKDF2 key derivation.

### TPM2 Pin
Trusted Platform Module 2.0 integration for hardware-backed encryption with optional PCR binding (configuration parsing implemented, hardware integration pending).

### SSS Pin
Shamir's Secret Sharing for splitting secrets across multiple shares with configurable thresholds.

### Null Pin
Testing and development pin with no actual encryption (for protocol validation).

## Distinguishing Features

### Compared to Latchset (Original C Implementation)

**Performance & Safety**
- Memory-safe implementation in Rust eliminates entire classes of vulnerabilities
- Modern cryptographic libraries with constant-time operations
- Async-capable architecture for high-concurrency environments

**Code Quality & Maintainability**
- Type-safe API with comprehensive error handling
- Modular design with clean separation between pins and protocols
- Extensive unit and integration testing (44+ tests)

**Feature Parity & Extensions**
- Full support for all thumbprint algorithms (S1, S224, S256, S384, S512)
- Improved URL handling with automatic scheme normalization
- Enhanced TCP handling in Remote pin with timeouts and error recovery

### Compared to Anatol (Go Implementation)

**Performance Characteristics**
- Zero-cost abstractions and minimal runtime overhead
- Better memory efficiency for embedded systems
- Compile-time optimization opportunities

**Language Ecosystem**
- Integration with Rust's cryptographic ecosystem (ring, rustls, etc.)
- Stronger type system preventing runtime configuration errors
- Better FFI capabilities for integration with C/C++ systems

**Implementation Differences**
- More granular feature flags for selective compilation
- Explicit error types with detailed context
- Structured concurrency model for network operations

## Current Gaps

### TPM2 Hardware Integration
While the configuration parsing and data structures for TPM2 are fully implemented, actual hardware integration requires the `tss-esapi` crate and access to TPM2 hardware or emulator. This is a compile-time optional feature.

### Advanced Network Testing
End-to-end integration tests with actual Tang servers require external setup and are not included in the default test suite. The project includes unit tests for all cryptographic primitives and protocol logic.

### Cryptsetup Plugin Maturity
The dmcrypt plugin is built and functional, but may require additional testing with various kernel versions and cryptsetup configurations.

## Building and Testing

### Prerequisites
- Rust 1.60+ (via rustup)
- OpenSSL development libraries (for some dependencies)
- Yubikey tools (for Yubikey pin testing, optional)
- TPM2 tools (for TPM2 pin, optional)

### Build Commands
```bash
# Build all components
cargo build --workspace --features=full

# Run tests
cargo test --workspace --features=full

# Build release version
cargo build --workspace --features=full --release
```

### Feature Flags
- `full`: Enables all cryptographic features and network dependencies
- `tpm2`: Enables TPM2 pin (requires TPM2 hardware)
- `yubikey`: Enables Yubikey pin (requires ykchalresp)

## Usage Examples

### Basic Encryption with Tang
```rust
use kunci_core::pin::{Pin, PinRegistry};
use kunci_core::pin::tang::TangPin;

let pin = TangPin::new();
let config = serde_json::json!({
    "adv": "eyJhbGciOiJFUzI1NiIsImtpZCI6I...",
    "url": "http://tang.example.com"
});

let plaintext = b"secret data";
let ciphertext = pin.encrypt(&config, plaintext)?;
```

### Command Line Client
```bash
# Encrypt a file using Tang with a config file
kunci encrypt --pin tang --config tang.json --input plaintext.txt --output encrypted.jwe

# Decrypt a file using Tang
kunci decrypt --pin tang --config tang.json --input encrypted.jwe --output plaintext.txt
```

### LUKS Integration
```bash
# Bind a LUKS device to a Tang server
kunci luks bind --adv advertisement.jws --url http://tang.example.com /dev/sda1

# List bindings
kunci luks list /dev/sda1
```

## Configuration

See `docs/config.md` for detailed configuration fields and trust policy behavior.

## Server Policy and Admin Socket

Enable TOFU support on the server:

```bash
kunci-server --allow-tofu
```

Show server signing key thumbprints via the local admin socket:

```bash
kunci-server --admin-sock /var/run/kunci-admin.sock --admin-gid 1000
kunci show-keys --admin-sock /var/run/kunci-admin.sock --hash S256
```

## Architecture

Kunci follows a modular architecture:

```
kunci-core/           # Core pin framework and protocol implementations
├── src/pin/         # Pin trait and registry
├── src/tang/        # Tang protocol implementation
├── src/remote/      # Remote pin implementation
├── src/yubikey/     # Yubikey pin implementation
├── src/tpm2/        # TPM2 pin implementation
└── src/crypto/      # Cryptographic primitives

kunci-client/        # Command-line interface
kunci-server/        # Tang server implementation
kunci-dmcrypt/       # Cryptsetup plugin for LUKS
```

## Security Considerations

Kunci is designed with security as a primary concern:

- All cryptographic operations use audited libraries (ring, p256, etc.)
- Memory is zeroized when no longer needed
- No unsafe code in the core cryptographic paths
- Comprehensive error handling prevents information leakage
- Regular dependency updates for security patches

## Contributing

Contributions are welcome! Please open an issue or pull request on the project repository to discuss changes.

## License

Kunci is licensed under the GPL 3.0. See the LICENSE file for details.

## Acknowledgments

- The [Latchset Clevis/Tang](https://github.com/latchset/clevis) project for the original implementation
- [Anatol's Go implementation](https://github.com/anatol/tang.go) for reference and test vectors
- The Rust cryptographic community for excellent libraries and guidance

## Support

For bugs and feature requests, please use the issue tracker. For security vulnerabilities, please contact the maintainers directly.
