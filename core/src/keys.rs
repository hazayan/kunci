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
use std::path::{Path, PathBuf};

#[cfg(feature = "full")]
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "full")]
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::crypto;
use crate::error::{Error, Result};
use crate::jwk::{Jwk, JwkSet};

/// Default hash algorithm for thumbprints (SHA-256).
const DEFAULT_THP_HASH: &str = "S256";

/// Supported hash algorithms for thumbprints.
const SUPPORTED_HASHES: &[&str] = &["S1", "S224", "S256", "S384", "S512"];

const ENCRYPTED_BUNDLE_FILE: &str = "keystore.bundle.json";
const ENCRYPTED_BUNDLE_KIND: &str = "kunci-server-keystore";
const ENCRYPTED_BACKUP_KIND: &str = "kunci-server-key-backup";
const ENCRYPTED_BUNDLE_CIPHER: &str = "A256GCM";

/// Server key storage backend.
pub trait ServerKeyBackend {
    /// Loads the server key store.
    fn load(&self) -> Result<KeyStore>;

    /// Creates server keys when the backend is empty.
    fn create_if_empty(&self) -> Result<()>;
}

/// Plain filesystem backend using Tang-compatible JWK files.
#[derive(Debug, Clone)]
pub struct FilesystemKeyBackend {
    directory: PathBuf,
    auto_create: bool,
}

impl FilesystemKeyBackend {
    /// Creates a filesystem backend for the given JWK directory.
    pub fn new<P: Into<PathBuf>>(directory: P) -> Self {
        Self {
            directory: directory.into(),
            auto_create: true,
        }
    }

    /// Sets whether missing keys should be created automatically.
    pub fn with_auto_create(mut self, auto_create: bool) -> Self {
        self.auto_create = auto_create;
        self
    }

    /// Returns the backend directory.
    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

impl ServerKeyBackend for FilesystemKeyBackend {
    fn load(&self) -> Result<KeyStore> {
        if self.auto_create {
            KeyStore::load(&self.directory)
        } else {
            KeyStore::load_no_auto_create(&self.directory)
        }
    }

    fn create_if_empty(&self) -> Result<()> {
        if !self.directory.exists() {
            fs::create_dir_all(&self.directory)?;
        }
        let store = KeyStore::load_keys(&self.directory)?;
        if store.keys.is_empty() {
            KeyStore::create_new_keys(&self.directory)?;
        }
        Ok(())
    }
}

/// Provider for a 256-bit keystore wrapping key.
pub trait WrappingKeyProvider {
    /// Returns a 32-byte wrapping key.
    fn wrapping_key(&self) -> Result<[u8; 32]>;
}

/// Test and migration helper wrapping key provider.
#[derive(Debug, Clone)]
pub struct StaticWrappingKeyProvider {
    key: [u8; 32],
}

impl StaticWrappingKeyProvider {
    /// Creates a provider from raw key bytes.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl WrappingKeyProvider for StaticWrappingKeyProvider {
    fn wrapping_key(&self) -> Result<[u8; 32]> {
        Ok(self.key)
    }
}

/// Raw 32-byte wrapping key provider backed by a file.
#[derive(Debug, Clone)]
pub struct RawFileWrappingKeyProvider {
    path: PathBuf,
}

impl RawFileWrappingKeyProvider {
    /// Creates a raw key-file provider.
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self { path: path.into() }
    }

    /// Returns the key file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl WrappingKeyProvider for RawFileWrappingKeyProvider {
    fn wrapping_key(&self) -> Result<[u8; 32]> {
        let bytes = fs::read(&self.path)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            Error::config(format!(
                "Raw wrapping key file {} must contain exactly 32 bytes, got {}",
                self.path.display(),
                bytes.len()
            ))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PlainKeyBundle {
    version: u8,
    keys: Vec<Jwk>,
    rotated_keys: Vec<Jwk>,
}

/// Encrypted key bundle or encrypted backup envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedKeyBundle {
    version: u8,
    kind: String,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

impl EncryptedKeyBundle {
    /// Returns the bundle kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }
}

/// Encrypted filesystem bundle backend.
#[cfg(feature = "full")]
#[derive(Debug, Clone)]
pub struct EncryptedBundleKeyBackend<P> {
    directory: PathBuf,
    key_provider: P,
    auto_create: bool,
}

#[cfg(feature = "full")]
impl<P> EncryptedBundleKeyBackend<P>
where
    P: WrappingKeyProvider,
{
    /// Creates an encrypted bundle backend for the given directory.
    pub fn new<D: Into<PathBuf>>(directory: D, key_provider: P) -> Self {
        Self {
            directory: directory.into(),
            key_provider,
            auto_create: false,
        }
    }

    /// Sets whether a missing encrypted bundle should be initialized.
    pub fn with_auto_create(mut self, auto_create: bool) -> Self {
        self.auto_create = auto_create;
        self
    }

    /// Returns the encrypted bundle path.
    pub fn bundle_path(&self) -> PathBuf {
        self.directory.join(ENCRYPTED_BUNDLE_FILE)
    }

    /// Writes an encrypted bundle from an existing key store.
    pub fn save_store(&self, store: &KeyStore) -> Result<()> {
        if !self.directory.exists() {
            fs::create_dir_all(&self.directory)?;
        }

        let bundle = self.encrypt_store(store, ENCRYPTED_BUNDLE_KIND)?;
        let json = serde_json::to_vec_pretty(&bundle)
            .map_err(|e| Error::config(format!("Failed to serialize encrypted bundle: {}", e)))?;

        let path = self.bundle_path();
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(&json)?;
        file.sync_all()?;

        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o440);
        fs::set_permissions(&path, perms)?;
        Ok(())
    }

    /// Migrates a plaintext JWK directory into an encrypted bundle directory.
    pub fn migrate_from_filesystem<S: AsRef<Path>>(&self, source_directory: S) -> Result<()> {
        let store = KeyStore::load_no_auto_create(source_directory)?;
        self.save_store(&store)
    }

    /// Creates an encrypted backup artifact from a key store.
    pub fn backup_store(&self, store: &KeyStore) -> Result<Vec<u8>> {
        let bundle = self.encrypt_store(store, ENCRYPTED_BACKUP_KIND)?;
        serde_json::to_vec_pretty(&bundle)
            .map_err(|e| Error::config(format!("Failed to serialize encrypted backup: {}", e)))
    }

    /// Restores a key store from an encrypted backup artifact.
    pub fn restore_backup(&self, artifact: &[u8]) -> Result<KeyStore> {
        let bundle: EncryptedKeyBundle = serde_json::from_slice(artifact)
            .map_err(|e| Error::config(format!("Failed to parse encrypted backup: {}", e)))?;
        self.decrypt_store(&bundle, ENCRYPTED_BACKUP_KIND)
    }

    /// Writes an encrypted bundle restored from an encrypted backup artifact.
    pub fn restore_backup_to_bundle(&self, artifact: &[u8]) -> Result<()> {
        let store = self.restore_backup(artifact)?;
        self.save_store(&store)
    }

    fn encrypt_store(&self, store: &KeyStore, kind: &str) -> Result<EncryptedKeyBundle> {
        let plain = PlainKeyBundle {
            version: 1,
            keys: store.keys.clone(),
            rotated_keys: store.rotated_keys.clone(),
        };
        let plaintext = serde_json::to_vec(&plain)
            .map_err(|e| Error::config(format!("Failed to serialize key bundle: {}", e)))?;
        self.encrypt_bundle(&plaintext, kind)
    }

    fn decrypt_store(&self, bundle: &EncryptedKeyBundle, kind: &str) -> Result<KeyStore> {
        let plaintext = self.decrypt_bundle(bundle, kind)?;
        let plain: PlainKeyBundle = serde_json::from_slice(&plaintext)
            .map_err(|e| Error::config(format!("Failed to parse key bundle: {}", e)))?;
        if plain.version != 1 {
            return Err(Error::config(format!(
                "Unsupported key bundle version: {}",
                plain.version
            )));
        }
        KeyStore::from_keys(plain.keys, plain.rotated_keys)
    }

    #[allow(deprecated)]
    fn encrypt_bundle(&self, plaintext: &[u8], kind: &str) -> Result<EncryptedKeyBundle> {
        let key = self.key_provider.wrapping_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::crypto(format!("Invalid wrapping key: {}", e)))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| Error::crypto(format!("Failed to encrypt key bundle: {}", e)))?;

        Ok(EncryptedKeyBundle {
            version: 1,
            kind: kind.to_string(),
            cipher: ENCRYPTED_BUNDLE_CIPHER.to_string(),
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    #[allow(deprecated)]
    fn decrypt_bundle(&self, bundle: &EncryptedKeyBundle, kind: &str) -> Result<Vec<u8>> {
        if bundle.version != 1 {
            return Err(Error::config(format!(
                "Unsupported encrypted key bundle version: {}",
                bundle.version
            )));
        }
        if bundle.kind != kind {
            return Err(Error::config(format!(
                "Unsupported encrypted key bundle kind: {}",
                bundle.kind
            )));
        }
        if bundle.cipher != ENCRYPTED_BUNDLE_CIPHER {
            return Err(Error::config(format!(
                "Unsupported encrypted key bundle cipher: {}",
                bundle.cipher
            )));
        }

        let nonce = URL_SAFE_NO_PAD
            .decode(&bundle.nonce)
            .map_err(|e| Error::config(format!("Invalid key bundle nonce: {}", e)))?;
        if nonce.len() != 12 {
            return Err(Error::config("Invalid key bundle nonce length"));
        }
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&bundle.ciphertext)
            .map_err(|e| Error::config(format!("Invalid key bundle ciphertext: {}", e)))?;
        let key = self.key_provider.wrapping_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::crypto(format!("Invalid wrapping key: {}", e)))?;
        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|e| Error::crypto(format!("Failed to decrypt key bundle: {}", e)))
    }
}

#[cfg(feature = "full")]
impl<P> ServerKeyBackend for EncryptedBundleKeyBackend<P>
where
    P: WrappingKeyProvider,
{
    fn load(&self) -> Result<KeyStore> {
        let path = self.bundle_path();
        if !path.exists() {
            if self.auto_create {
                self.create_if_empty()?;
            } else {
                return Err(Error::config(format!(
                    "Encrypted key bundle does not exist: {}",
                    path.display()
                )));
            }
        }

        let data = fs::read(&path)?;
        let bundle: EncryptedKeyBundle = serde_json::from_slice(&data)
            .map_err(|e| Error::config(format!("Failed to parse encrypted key bundle: {}", e)))?;
        self.decrypt_store(&bundle, ENCRYPTED_BUNDLE_KIND)
    }

    fn create_if_empty(&self) -> Result<()> {
        let path = self.bundle_path();
        if path.exists() {
            return Ok(());
        }
        let store = KeyStore::generate_new()?;
        self.save_store(&store)
    }
}

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
    /// Creates a key store from existing regular and rotated keys.
    pub fn from_keys(keys: Vec<Jwk>, rotated_keys: Vec<Jwk>) -> Result<Self> {
        let mut store = Self {
            keys,
            rotated_keys,
            signing_keys: Vec::new(),
            payload_keys: Vec::new(),
        };
        store.prepare_keys()?;
        Ok(store)
    }

    /// Generates a fresh Tang key store in memory.
    #[cfg(feature = "full")]
    pub fn generate_new() -> Result<Self> {
        let mut keys = Vec::new();
        for alg in ["ES512", "ECMR"] {
            keys.push(Self::generate_key(alg)?);
        }
        Self::from_keys(keys, Vec::new())
    }

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
    fn test_filesystem_backend_loads_default_key_store() {
        let tempdir = TempDir::new().unwrap();
        let backend = FilesystemKeyBackend::new(tempdir.path());
        let store = backend.load().unwrap();

        assert_eq!(store.key_count(), 2);
        assert_eq!(store.signing_key_count(), 1);
        assert!(backend.directory().exists());
    }

    #[test]
    #[cfg(feature = "full")]
    fn test_encrypted_bundle_roundtrip() {
        let source_dir = TempDir::new().unwrap();
        let bundle_dir = TempDir::new().unwrap();
        let source = KeyStore::load(source_dir.path()).unwrap();
        let backend = EncryptedBundleKeyBackend::new(
            bundle_dir.path(),
            StaticWrappingKeyProvider::new([7; 32]),
        );

        backend.save_store(&source).unwrap();
        let loaded = backend.load().unwrap();

        assert_eq!(loaded.key_count(), source.key_count());
        assert_eq!(loaded.rotated_key_count(), source.rotated_key_count());
        assert_eq!(loaded.signing_key_count(), source.signing_key_count());
        assert!(loaded.signing_keys[0].is_private());
        assert!(backend.bundle_path().exists());
        assert_eq!(
            std::fs::read_dir(bundle_dir.path()).unwrap().count(),
            1,
            "encrypted backend should store a bundle, not plaintext JWK files"
        );
    }

    #[test]
    #[cfg(feature = "full")]
    fn test_encrypted_bundle_rejects_wrong_wrapping_key() {
        let source_dir = TempDir::new().unwrap();
        let bundle_dir = TempDir::new().unwrap();
        let source = KeyStore::load(source_dir.path()).unwrap();
        let backend = EncryptedBundleKeyBackend::new(
            bundle_dir.path(),
            StaticWrappingKeyProvider::new([7; 32]),
        );
        backend.save_store(&source).unwrap();

        let wrong_backend = EncryptedBundleKeyBackend::new(
            bundle_dir.path(),
            StaticWrappingKeyProvider::new([8; 32]),
        );
        let err = wrong_backend.load().unwrap_err();

        assert!(err.to_string().contains("Failed to decrypt key bundle"));
    }

    #[test]
    #[cfg(feature = "full")]
    fn test_encrypted_bundle_migrates_from_filesystem() {
        let source_dir = TempDir::new().unwrap();
        let bundle_dir = TempDir::new().unwrap();
        let source = KeyStore::load(source_dir.path()).unwrap();
        let backend = EncryptedBundleKeyBackend::new(
            bundle_dir.path(),
            StaticWrappingKeyProvider::new([9; 32]),
        );

        backend.migrate_from_filesystem(source_dir.path()).unwrap();
        let loaded = backend.load().unwrap();

        assert_eq!(loaded.key_count(), source.key_count());
        assert_eq!(loaded.signing_key_count(), source.signing_key_count());
        assert!(backend.bundle_path().exists());
    }

    #[test]
    #[cfg(feature = "full")]
    fn test_encrypted_bundle_auto_create_initializes_bundle() {
        let bundle_dir = TempDir::new().unwrap();
        let backend = EncryptedBundleKeyBackend::new(
            bundle_dir.path(),
            StaticWrappingKeyProvider::new([10; 32]),
        )
        .with_auto_create(true);

        let loaded = backend.load().unwrap();

        assert_eq!(loaded.key_count(), 2);
        assert_eq!(loaded.signing_key_count(), 1);
        assert!(backend.bundle_path().exists());
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
