//! Key management and storage for Tang.
//!
//! This module provides functionality for loading, storing, and managing
//! cryptographic keys used by the Tang server.
//!
//! # Key Storage
//!
//! Keys are stored as JSON Web Key (JWK) files in a directory. The directory
//! structure follows the Tang convention:
//!
//! - Regular keys: `<thumbprint>.jwk`
//! - Rotated keys: `.<thumbprint>.jwk` (hidden files)
//!
//! Where `<thumbprint>` is the base64url-encoded SHA-256 thumbprint of the key.
//!
//! # Key Types
//!
//! Tang uses two types of keys:
//!
//! 1. **Signing keys** (`alg: "ES512"`): Used to sign advertisements
//! 2. **Exchange keys** (`alg: "ECMR"`): Used for McCallum-Relyea key exchange
//!
//! # Examples
//!
//! ```no_run
//! # use kunci_core::keys::KeyStore;
//! # use kunci_core::error::Result;
//! # fn main() -> Result<()> {
//! // Load keys from a directory (creates new keys if none exist)
//! let store = KeyStore::load("/var/db/tang")?;
//!
//! // Get the advertisement JWS
//! let jws = store.advertisement(None)?;
//!
//! // Find a key by thumbprint
//! let jwk = store.find_key("qgmqJSo6AEEuVQY7zVlklqdTMqY")?;
//! # Ok(())
//! # }
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::crypto;
use crate::error::{Error, Result};
use crate::jwk::{Jwk, JwkSet};

/// Default hash algorithm for thumbprints (SHA-256).
const DEFAULT_THP_HASH: &str = "S256";

/// Supported hash algorithms for thumbprints.
const SUPPORTED_HASHES: &[&str] = &["S1", "S224", "S256", "S384", "S512"];

/// A key store that manages Tang keys.
#[derive(Debug, Clone)]
pub struct KeyStore {
    /// Regular (non-rotated) keys.
    pub keys: Vec<Jwk>,
    /// Rotated keys (hidden files starting with '.').
    pub rotated_keys: Vec<Jwk>,
    /// Signing keys extracted from regular keys.
    pub signing_keys: Vec<Jwk>,
    /// Payload keys (signing and exchange keys from regular keys).
    pub payload_keys: Vec<Jwk>,
}

impl KeyStore {
    /// Loads keys from the specified directory.
    ///
    /// If the directory doesn't exist or contains no keys, new signing and
    /// exchange keys will be generated automatically.
    ///
    /// # Arguments
    ///
    /// * `jwkdir` - Path to the directory containing JWK files.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The directory cannot be read
    /// - Key files are invalid
    /// - New keys cannot be generated
    pub fn load<P: AsRef<Path>>(jwkdir: P) -> Result<Self> {
        let jwkdir = jwkdir.as_ref();
        crate::klog!(
            module: "keys",
            level: crate::log::LogLevel::Debug,
            "load_start";
            dir = jwkdir.display().to_string()
        );

        // Check if directory exists
        if !jwkdir.exists() {
            fs::create_dir_all(jwkdir)?;
        }

        let mut store = Self::load_keys(jwkdir)?;

        // If no regular keys found, create new ones
        if store.keys.is_empty() {
            crate::klog!(
                module: "keys",
                level: crate::log::LogLevel::Info,
                "load_no_keys_create";
                dir = jwkdir.display().to_string()
            );
            Self::create_new_keys(jwkdir)?;
            store = Self::load_keys(jwkdir)?;
        }

        // Prepare signing and payload keys
        store.prepare_keys()?;

        crate::klog!(
            module: "keys",
            level: crate::log::LogLevel::Debug,
            "load_ok";
            key_count = store.key_count(),
            rotated_count = store.rotated_key_count(),
            signing_count = store.signing_key_count()
        );
        Ok(store)
    }

    /// Loads keys from the specified directory without creating new ones.
    ///
    /// If the directory doesn't exist or contains no keys, an error is returned.
    ///
    /// # Arguments
    ///
    /// * `jwkdir` - Path to the directory containing JWK files.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The directory cannot be read
    /// - Key files are invalid
    /// - No keys are found
    pub fn load_no_auto_create<P: AsRef<Path>>(jwkdir: P) -> Result<Self> {
        let jwkdir = jwkdir.as_ref();
        crate::klog!(
            module: "keys",
            level: crate::log::LogLevel::Info,
            "load_no_auto_create";
            dir = jwkdir.display().to_string()
        );

        // Check if directory exists
        if !jwkdir.exists() {
            return Err(Error::config("Key directory does not exist"));
        }

        let mut store = Self::load_keys(jwkdir)?;

        if store.keys.is_empty() {
            return Err(Error::config("No keys found"));
        }

        store.prepare_keys()?;

        Ok(store)
    }

    /// Loads existing keys from a directory without creating new ones.
    fn load_keys(jwkdir: &Path) -> Result<Self> {
        let mut keys = Vec::new();
        let mut rotated_keys = Vec::new();
        let mut skipped_invalid = 0usize;
        let mut skipped_unreadable = 0usize;
        let mut skipped_non_jwk = 0usize;

        for entry in fs::read_dir(jwkdir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip non-files and files without .jwk extension
            if !path.is_file() {
                continue;
            }

            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| Error::config("Invalid filename"))?;

            // Check if it's a .jwk file
            if !filename.ends_with(".jwk") {
                skipped_non_jwk += 1;
                continue;
            }

            // Determine if it's rotated (starts with '.')
            let is_rotated = filename.starts_with('.');

            // Read and parse the JWK file
            let mut file = File::open(&path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;

            // Skip files that cannot be parsed as JWK
            let jwk: Jwk = match serde_json::from_str(&contents) {
                Ok(jwk) => jwk,
                Err(_) => {
                    skipped_unreadable += 1;
                    continue;
                }
            };

            // Skip invalid JWKs (e.g., missing required fields)
            if jwk.validate().is_err() {
                skipped_invalid += 1;
                continue;
            }

            if is_rotated {
                rotated_keys.push(jwk);
            } else {
                keys.push(jwk);
            }
        }

        crate::klog!(
            module: "keys",
            level: crate::log::LogLevel::Debug,
            "load_keys";
            key_count = keys.len(),
            rotated_count = rotated_keys.len(),
            skipped_invalid = skipped_invalid,
            skipped_unreadable = skipped_unreadable,
            skipped_non_jwk = skipped_non_jwk
        );
        Ok(Self {
            keys,
            rotated_keys,
            signing_keys: Vec::new(),
            payload_keys: Vec::new(),
        })
    }

    /// Creates new signing and exchange keys in the directory.
    ///
    /// Creates two keys:
    /// 1. A signing key with algorithm ES512
    /// 2. An exchange key with algorithm ECMR
    ///
    /// Keys are saved with permissions 0440 (read-only for owner and group).
    pub fn create_new_keys(jwkdir: &Path) -> Result<()> {
        // Set umask to 0337 (so files are created as 0440)
        // In Rust, we can't easily set umask temporarily, so we'll set permissions after creation
        let algs = ["ES512", "ECMR"];

        crate::klog!(
            module: "keys",
            level: crate::log::LogLevel::Info,
            "create_new_keys";
            dir = jwkdir.display().to_string(),
            algorithms = format!("{:?}", algs)
        );

        for alg in algs.iter() {
            // Generate the key
            let jwk = Self::generate_key(alg)?;

            // Compute thumbprint
            let thumbprint = jwk
                .thumbprint(DEFAULT_THP_HASH)
                .map_err(|e| Error::crypto(format!("Failed to compute thumbprint: {}", e)))?;

            // Create filename
            let filename = format!("{}.jwk", thumbprint);
            let path = jwkdir.join(filename);

            // Write the key
            let json = serde_json::to_string_pretty(&jwk)
                .map_err(|e| Error::config(format!("Failed to serialize JWK: {}", e)))?;

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)?;

            file.write_all(json.as_bytes())?;
            file.sync_all()?;

            // Set permissions to 0440 (read-only for owner and group)
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o440);
            fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }

    /// Generates a new key with the specified algorithm.
    ///
    /// # Arguments
    ///
    /// * `alg` - The algorithm to use ("ES512" for signing, "ECMR" for exchange).
    ///
    /// # Returns
    ///
    /// A new JWK with the specified algorithm.
    /// Generates a new cryptographic key for the given algorithm.
    ///
    /// # Arguments
    ///
    /// * `alg` - The algorithm to generate a key for (e.g., "ES512", "ECMR").
    ///
    /// # Returns
    ///
    /// A JWK containing the generated key pair.
    fn generate_key(alg: &str) -> Result<Jwk> {
        crypto::generate_key(alg).map_err(|e| Error::crypto(e.to_string()))
    }

    /// Prepares the signing and payload key sets.
    ///
    /// This method must be called after loading keys. It populates:
    /// - `signing_keys`: Regular keys that can sign
    /// - `payload_keys`: Regular keys that can sign or derive keys
    fn prepare_keys(&mut self) -> Result<()> {
        self.signing_keys.clear();
        self.payload_keys.clear();

        for jwk in &self.keys {
            // Check if key can sign
            if Self::can_sign(jwk) {
                self.signing_keys.push(jwk.clone());
                self.payload_keys.push(jwk.to_public());
            }
            // Check if key can derive keys (exchange key)
            else if Self::can_derive_key(jwk) {
                self.payload_keys.push(jwk.to_public());
            }
        }

        if self.signing_keys.is_empty() {
            return Err(Error::config("No signing keys found"));
        }

        if self.payload_keys.is_empty() {
            return Err(Error::config("No payload keys found"));
        }

        crate::klog!(
            module: "keys",
            level: crate::log::LogLevel::Debug,
            "prepare_keys_ok";
            signing_keys = self.signing_keys.len(),
            payload_keys = self.payload_keys.len()
        );
        Ok(())
    }

    /// Checks if a JWK can be used for signing.
    fn can_sign(jwk: &Jwk) -> bool {
        // Check key operations
        if let Some(key_ops) = jwk.key_ops() {
            key_ops.iter().any(|op| op == "sign")
        } else {
            // Check alg field for signing algorithms
            matches!(
                jwk.alg(),
                Some("ES256" | "ES384" | "ES512" | "RS256" | "RS384" | "RS512")
            )
        }
    }

    /// Checks if a JWK can be used for key derivation (exchange).
    fn can_derive_key(jwk: &Jwk) -> bool {
        // Check key operations
        if let Some(key_ops) = jwk.key_ops() {
            key_ops.iter().any(|op| op == "deriveKey")
        } else {
            // Check alg field for ECMR
            jwk.alg() == Some("ECMR")
        }
    }

    /// Finds a key by its thumbprint.
    ///
    /// Searches both regular and rotated keys.
    ///
    /// # Arguments
    ///
    /// * `thumbprint` - The base64url-encoded thumbprint to search for.
    ///
    /// # Returns
    ///
    /// The JWK if found, or `None` if not found.
    pub fn find_key(&self, thumbprint: &str) -> Result<Option<Jwk>> {
        // Search in regular keys
        for jwk in &self.keys {
            if let Ok(tp) = jwk.thumbprint(DEFAULT_THP_HASH) {
                if tp == thumbprint {
                    return Ok(Some(jwk.clone()));
                }
            }

            // Also check alternative hash algorithms
            for hash_alg in SUPPORTED_HASHES {
                if let Ok(tp) = jwk.thumbprint(hash_alg) {
                    if tp == thumbprint {
                        return Ok(Some(jwk.clone()));
                    }
                }
            }
        }

        // Search in rotated keys
        for jwk in &self.rotated_keys {
            if let Ok(tp) = jwk.thumbprint(DEFAULT_THP_HASH) {
                if tp == thumbprint {
                    return Ok(Some(jwk.clone()));
                }
            }

            // Also check alternative hash algorithms
            for hash_alg in SUPPORTED_HASHES {
                if let Ok(tp) = jwk.thumbprint(hash_alg) {
                    if tp == thumbprint {
                        return Ok(Some(jwk.clone()));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Finds a signing key by its thumbprint.
    ///
    /// Similar to `find_key`, but only returns the key if it can be used for signing.
    pub fn find_signing_key(&self, thumbprint: &str) -> Result<Option<Jwk>> {
        if let Some(jwk) = self.find_key(thumbprint)? {
            if Self::can_sign(&jwk) {
                return Ok(Some(jwk));
            }
        }
        Ok(None)
    }

    /// Finds an exchange key by its thumbprint.
    ///
    /// Similar to `find_key`, but only returns the key if it can be used for key derivation.
    pub fn find_exchange_key(&self, thumbprint: &str) -> Result<Option<Jwk>> {
        if let Some(jwk) = self.find_key(thumbprint)? {
            if Self::can_derive_key(&jwk) {
                return Ok(Some(jwk));
            }
        }
        Ok(None)
    }

    /// Creates an advertisement JWS.
    ///
    /// # Arguments
    ///
    /// * `signing_thumbprint` - Optional thumbprint of a specific signing key to include.
    ///                          If `None`, uses all regular signing keys.
    ///
    /// # Returns
    ///
    /// A JWS compact serialization as a string.
    pub fn advertisement(&self, signing_thumbprint: Option<&str>) -> Result<String> {
        crate::klog!(
            module: "keys",
            level: crate::log::LogLevel::Debug,
            "advertisement";
            signing_thumbprint = signing_thumbprint.unwrap_or("")
        );
        // Get the payload (public keys)
        let payload = self.create_payload()?;

        // Get signing keys
        let signing_keys = if let Some(thumbprint) = signing_thumbprint {
            let mut keys = self.signing_keys.clone();
            if let Some(jwk) = self.find_signing_key(thumbprint)? {
                keys.push(jwk.to_public());
            }
            keys
        } else {
            self.signing_keys.clone()
        };

        // Create JWS with content type "jwk-set+json"
        crate::jose::create_jws(&payload, &signing_keys, Some("jwk-set+json"))
    }

    /// Creates the payload for advertisements.
    ///
    /// The payload contains all regular keys that can sign or derive keys.
    pub(crate) fn create_payload(&self) -> Result<Value> {
        crate::klog!(
            module: "keys",
            level: crate::log::LogLevel::Debug,
            "create_payload";
            payload_keys = self.payload_keys.len()
        );
        let jwk_set = JwkSet {
            keys: self.payload_keys.clone(),
        };

        serde_json::to_value(jwk_set)
            .map_err(|e| Error::config(format!("Failed to create payload: {}", e)))
    }


    /// Returns the number of regular keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Returns the number of rotated keys.
    pub fn rotated_key_count(&self) -> usize {
        self.rotated_keys.len()
    }

    /// Returns the number of signing keys.
    pub fn signing_key_count(&self) -> usize {
        self.signing_keys.len()
    }

    /// Returns all keys (regular and rotated).
    pub fn all_keys(&self) -> Vec<Jwk> {
        let mut all = self.keys.clone();
        all.extend(self.rotated_keys.clone());
        all
    }

    /// Returns all thumbprints for a given key.
    ///
    /// Computes thumbprints using all supported hash algorithms.
    pub fn key_thumbprints(&self, jwk: &Jwk) -> Result<Vec<String>> {
        let mut thumbprints = Vec::new();

        for hash_alg in SUPPORTED_HASHES {
            if let Ok(tp) = jwk.thumbprint(hash_alg) {
                thumbprints.push(tp);
            }
        }

        Ok(thumbprints)
    }
}

/// Computes a SHA-256 hash of data and returns it as base64url.
pub fn sha256_hash(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = sha256_hash(data);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 43); // Base64url SHA-256 is 43 chars
    }

    #[test]
    fn test_can_sign() {
        // Valid EC key with dummy x and y (required for EC keys)
        let signing_jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-521",
            "alg": "ES512",
            "key_ops": ["sign", "verify"],
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        }))
        .unwrap();

        let exchange_jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ECMR",
            "key_ops": ["deriveKey"],
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        }))
        .unwrap();

        assert!(KeyStore::can_sign(&signing_jwk));
        assert!(!KeyStore::can_sign(&exchange_jwk));
    }

    #[test]
    fn test_can_derive_key() {
        let signing_jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-521",
            "alg": "ES512",
            "key_ops": ["sign", "verify"],
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        }))
        .unwrap();

        let exchange_jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ECMR",
            "key_ops": ["deriveKey"],
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        }))
        .unwrap();

        assert!(!KeyStore::can_derive_key(&signing_jwk));
        assert!(KeyStore::can_derive_key(&exchange_jwk));
    }

    #[test]
    #[cfg(feature = "full")]
    fn test_load_empty_directory() {
        let tempdir = TempDir::new().unwrap();
        let result = KeyStore::load(tempdir.path());

        // Should succeed and create keys
        assert!(result.is_ok());
        let store = result.unwrap();

        // Should have 2 keys (ES512 and ECMR)
        assert_eq!(store.key_count(), 2);
        assert_eq!(store.signing_key_count(), 1); // Only ES512 can sign
        assert!(store.signing_keys[0].is_private());
        assert!(store.payload_keys.iter().all(|key| !key.is_private()));
    }

    #[test]
    #[cfg(feature = "full")]
    fn test_find_key() {
        let tempdir = TempDir::new().unwrap();
        let store = KeyStore::load(tempdir.path()).unwrap();

        // Get thumbprint of first key
        let jwk = &store.keys[0];
        let thumbprint = jwk.thumbprint(DEFAULT_THP_HASH).unwrap();

        // Should find the key
        let found = store.find_key(&thumbprint).unwrap();
        assert!(found.is_some());

        // Should not find non-existent key
        let not_found = store.find_key("nonexistent").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_load_original_keys() {
        use std::path::Path;

        // Path to original test keys
        let keys_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("latchset/tang/tests/keys");

        if !keys_dir.exists() {
            eprintln!("Skipping: keys directory not found: {:?}", keys_dir);
            return;
        }

        // Try to load keys using our KeyStore
        let result = KeyStore::load(&keys_dir);
        assert!(result.is_ok(), "Failed to load keys: {:?}", result.err());

        let store = result.unwrap();

        // Original test directory contains 4 .jwk files (2 regular, 2 rotated)
        // plus some invalid files (empty.jwk, invalid.jwk, another-bad-file)
        // Regular keys: qgmqJSo6AEEuVQY7zVlklqdTMqY.jwk, -bWkGaJi0Zdvxaj4DCp28umLcRA.jwk
        // Rotated keys: .r4E2wG1u_YyKUo0N0rIK7jJF5Xg.jwk, .uZ0s8YTXcGcuWduWWBSiR2OjOVg.jwk
        // Total valid JWKs: 4
        assert_eq!(store.key_count(), 2);
        assert_eq!(store.rotated_key_count(), 2);
        assert_eq!(store.signing_key_count(), 1); // Only one signing key (ES512)
    }

    #[test]
    fn test_thumbprint_matches_original() {
        use std::fs;
        use std::path::Path;

        // Path to original test keys
        let keys_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("latchset/tang/tests/keys");
        if !keys_dir.exists() {
            eprintln!("Skipping: keys directory not found: {:?}", keys_dir);
            return;
        }

        // Load the ES512 signing key
        let es512_path = keys_dir.join("qgmqJSo6AEEuVQY7zVlklqdTMqY.jwk");
        let content = fs::read_to_string(es512_path).unwrap();
        let jwk: Jwk = serde_json::from_str(&content).unwrap();

        // Compute thumbprint using our implementation
        // Note: The original Tang test keys use SHA-1 (S1) for filenames
        let thumbprint = jwk.thumbprint("S1").unwrap();

        // Should match the filename (without .jwk extension)
        assert_eq!(thumbprint, "qgmqJSo6AEEuVQY7zVlklqdTMqY");
    }
}
