//! Core types and utilities for Tang and Clevis implementation in Rust.
//!
//! This crate provides the core cryptographic and protocol logic for
//! implementing Tang (server) and Clevis (client) functionality.
//!
//! # Features
//!
//! - `full`: Enables all cryptographic dependencies and JOSE support.
//! - `jose`: Enables JOSE (JSON Object Signing and Encryption) support.
//! - `crypto`: Enables cryptographic primitives (ECDH, ECMR, etc.).
//! - `tpm2`: Enables TPM2 pin support for hardware security modules.
//!
//! # Modules
//!
//! - [`error`]: Error types used throughout the crate.
//! - [`jwk`]: JSON Web Key (JWK) types and operations.
//! - [`keys`]: Key management and storage.
//! - [`tang`]: Tang-specific protocol logic (advertisement, recovery).
//! - [`crypto`]: Cryptographic primitives and operations.
//! - [`jose`]: JOSE (JSON Object Signing and Encryption) utilities.
//! - [`remote`]: Remote pin for proxy Tang server support.

#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod crypto;
/// Admin protocol types for local Unix socket requests.
pub mod admin;

/// Error types used throughout the crate.
pub mod error;

/// Logging helpers for the core crate.
pub mod log;
pub mod jose;
pub mod jwk;
pub mod keys;
#[cfg(target_os = "linux")]
pub mod luks;
pub mod pin;
pub mod remote;
pub mod sss;
pub mod tang;
pub mod thumbprint;
pub mod yubikey;
#[cfg(feature = "tpm2")]
pub mod tpm2;
/// ZFS native encryption integration (available on all platforms that support ZFS).
pub mod zfs;

/// Re-export of common error types.
pub use error::{Error, Result};

/// Decrypt a Clevis JWE (JSON Web Encryption) using the default pin registry.
///
/// This function creates a registry with all supported pins (Tang, SSS, Remote, Yubikey, TPM2)
/// and uses it to decrypt the provided JWE.
///
/// # Arguments
///
/// * `jwe` - The JWE as a JSON value (must be a valid JWE JSON structure).
///
/// # Returns
///
/// The decrypted plaintext as a byte vector.
pub fn decrypt(jwe: &serde_json::Value) -> Result<Vec<u8>> {
    use crate::pin::{PinRegistry, SssPin};
    use crate::remote::RemotePin;
    use crate::yubikey::YubikeyPin;

    let mut registry = PinRegistry::new();
    #[cfg(feature = "full")]
    registry.register(Box::new(crate::pin::TangPin::new()));
    registry.register(Box::new(SssPin::new()));
    registry.register(Box::new(RemotePin::new()));
    registry.register(Box::new(YubikeyPin::new()));
    #[cfg(feature = "tpm2")]
    registry.register(Box::new(crate::tpm2::Tpm2Pin::new()));

    registry.decrypt(jwe)
}

/// A prelude for convenient importing of commonly used types.
pub mod prelude {
    pub use crate::error::{Error, Result};
    pub use crate::jwk::Jwk;
    pub use crate::keys::KeyStore;
    #[cfg(target_os = "linux")]
    pub use crate::luks::{LuksSlot, LuksVolume, LuksVersion};
    pub use crate::pin::{Pin, PinConfig, PinRegistry};
    pub use crate::remote::RemotePin;
    pub use crate::tang::{Advertisement, RecoveryRequest, RecoveryResponse};
}
