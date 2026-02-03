//! Tang-specific protocol logic for advertisement and recovery operations.
//!
//! This module implements the Tang server protocol as described in the
//! Tang specification, including:
//!
//! - Advertisement of public keys (JWS-signed JWK Set)
//! - McCallum-Relyea key exchange for recovery
//! - Protocol-level validation and error handling
//!
//! # Protocol Overview
//!
//! Tang implements a simple HTTP REST API:
//!
//! | Method   | Path         | Operation                                     |
//! |---------:|:-------------|:----------------------------------------------|
//! | `GET`    | `/adv`       | Fetch public keys (advertisement)             |
//! | `GET`    | `/adv/{kid}` | Fetch public keys using specified signing key |
//! | `POST`   | `/rec/{kid}` | Perform recovery using specified exchange key |
//!
//! The advertisement is a JWS-signed JWK Set containing all public keys
//! that can be used for signing or key exchange. The recovery operation
//! implements the McCallum-Relyea key exchange protocol.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::jose;
use crate::jwk::{Jwk, JwkSet};
use crate::keys::KeyStore;

/// Tang advertisement response.
///
/// An advertisement is a JWS-signed JWK Set containing all public keys
/// available for signing or key exchange. The JWS is signed by all
/// available signing keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advertisement {
    /// The JWS-signed advertisement (compact serialization).
    pub jws: String,
}

impl Advertisement {
    /// Creates a new advertisement from a key store.
    ///
    /// # Arguments
    ///
    /// * `key_store` - The key store containing the keys to advertise.
    ///
    /// # Returns
    ///
    /// An advertisement containing all public keys from the key store,
    /// signed by all available signing keys.
    pub fn from_key_store(key_store: &KeyStore) -> Result<Self> {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "adv_from_store_start";
            key_count = key_store.key_count(),
            signing_key_count = key_store.signing_key_count()
        );
        // Get the payload (public keys for signing and exchange)
        let payload = key_store.create_payload()?;

        // Get signing keys
        let signing_keys = key_store.signing_keys.clone();

        // Create JWS advertisement
        let jws = jose::create_advertisement(&payload, &signing_keys)?;

        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "adv_from_store_ok";
            jws_len = jws.len()
        );
        Ok(Self { jws })
    }

    /// Creates a new advertisement using a specific signing key.
    ///
    /// This is used when a client requests an advertisement signed by
    /// a specific key (e.g., for trust chain upgrades).
    ///
    /// # Arguments
    ///
    /// * `key_store` - The key store containing the keys.
    /// * `signing_thumbprint` - The thumbprint of the signing key to use.
    ///
    /// # Returns
    ///
    /// An advertisement signed by all regular signing keys plus the
    /// specified key (which may be rotated/hidden).
    pub fn with_signing_key(key_store: &KeyStore, signing_thumbprint: &str) -> Result<Self> {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "adv_with_key_start";
            kid = signing_thumbprint
        );
        // Get the payload (public keys for signing and exchange)
        let payload = key_store.create_payload()?;

        // Get signing keys plus the requested key
        let mut signing_keys = key_store.signing_keys.clone();

        // Find the requested signing key
        if let Some(jwk) = key_store.find_signing_key(signing_thumbprint)? {
            signing_keys.push(jwk);
        }

        // Create JWS advertisement
        let jws = jose::create_advertisement(&payload, &signing_keys)?;

        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "adv_with_key_ok";
            kid = signing_thumbprint,
            jws_len = jws.len()
        );
        Ok(Self { jws })
    }

    /// Verifies the advertisement signatures.
    ///
    /// # Arguments
    ///
    /// * `verification_key` - The key to use for verification.
    ///
    /// # Returns
    ///
    /// The verified payload (JWK Set) if verification succeeds.
    pub fn verify(&self, verification_key: &Jwk) -> Result<JwkSet> {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "adv_verify_start";
            jws_len = self.jws.len(),
            key_has_kid = verification_key.kid().is_some()
        );
        let payload = jose::verify_jws(&self.jws, verification_key)?;

        serde_json::from_value(payload)
            .map_err(|e| Error::validation(format!("Failed to parse JWK Set: {}", e)))
    }

    /// Extracts the JWK Set from the advertisement without verification.
    ///
    /// # Warning
    ///
    /// This does not verify signatures! Use only when you have already
    /// verified the advertisement or are performing "trust on first use".
    ///
    /// # Returns
    ///
    /// The JWK Set from the advertisement payload.
    pub fn extract_unverified(&self) -> Result<JwkSet> {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "adv_extract_start";
            jws_len = self.jws.len()
        );
        let payload = jose::extract_jws_payload(&self.jws)?;

        serde_json::from_value(payload)
            .map_err(|e| Error::validation(format!("Failed to parse JWK Set: {}", e)))
    }
}

/// Recovery request from a client.
///
/// The client sends a JWK representing `xJWK = cJWK + eJWK` where:
/// - `cJWK` is the client's public key from provisioning
/// - `eJWK` is an ephemeral key for blinding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    /// The JWK to use for recovery (`xJWK` in McCallum-Relyea notation).
    #[serde(flatten)]
    pub jwk: Jwk,
}

impl RecoveryRequest {
    /// Validates the recovery request.
    ///
    /// Checks that the JWK is valid for the recovery operation:
    /// - Must be an EC key
    /// - Must be valid for key derivation (`deriveKey` operation)
    /// - Should have algorithm "ECMR" or be compatible
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid, error otherwise.
    pub fn validate(&self) -> Result<()> {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "recover_validate_start"
        );
        // Must be an EC key
        match &self.jwk {
            Jwk::EC(ec_jwk) => {
                // Check curve is supported (P-256 for ECMR)
                if ec_jwk.crv != "P-256" {
                    return Err(Error::validation(format!(
                        "Unsupported curve for recovery: {}",
                        ec_jwk.crv
                    )));
                }

                // Check algorithm if present
                if let Some(alg) = &ec_jwk.alg {
                    if alg != "ECMR" && alg != "ECDH" {
                        return Err(Error::validation(format!(
                            "Unsupported algorithm for recovery: {}",
                            alg
                        )));
                    }
                }

                // The key should have deriveKey operation or be implicitly for ECMR
                if let Some(key_ops) = &ec_jwk.key_ops {
                    if !key_ops.iter().any(|op| op == "deriveKey") {
                        return Err(Error::validation(
                            "Recovery key must support deriveKey operation".to_string(),
                        ));
                    }
                }

                Ok(())
            }
            _ => Err(Error::validation(
                "Recovery request must be an EC key".to_string(),
            )),
        }
    }
}

/// Recovery response from the server.
///
/// The server returns a JWK representing `yJWK = xJWK * S` where:
/// - `xJWK` is the client's request
/// - `S` is the server's private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResponse {
    /// The JWK result (`yJWK` in McCallum-Relyea notation).
    #[serde(flatten)]
    pub jwk: Jwk,
}

impl RecoveryResponse {
    /// Creates a recovery response for a client request.
    ///
    /// Implements the server side of the McCallum-Relyea exchange:
    /// `yJWK = xJWK * S` where `S` is the server's private key.
    ///
    /// # Arguments
    ///
    /// * `request` - The client's recovery request.
    /// * `server_key` - The server's exchange key (must have private component).
    ///
    /// # Returns
    ///
    /// A recovery response containing `yJWK`.
    #[cfg(feature = "full")]
    pub fn from_request(request: &RecoveryRequest, server_key: &Jwk) -> Result<Self> {
        use crate::crypto;

        // Validate request
        request.validate()?;

        // Server key must have private component
        if !server_key.is_private() {
            return Err(Error::invalid_key(
                "Server exchange key must have private component for recovery".to_string(),
            ));
        }

        // Perform McCallum-Relyea exchange
        let result_jwk = crypto::mccallum_relyea_exchange(server_key, &request.jwk)
            .map_err(|e| Error::crypto(format!("Key exchange failed: {}", e)))?;

        Ok(Self { jwk: result_jwk })
    }

    #[cfg(not(feature = "full"))]
    pub fn from_request(_request: &RecoveryRequest, _server_key: &Jwk) -> Result<Self> {
        Err(Error::crypto("Cryptographic features not enabled"))
    }
}

/// Protocol-level configuration for Tang operations.
#[derive(Debug, Clone)]
pub struct TangConfig {
    /// Directory containing JWK files.
    pub jwk_dir: String,
    /// Default thumbprint hash algorithm.
    pub default_thp_hash: String,
    /// Whether to automatically create keys if none exist.
    pub auto_create_keys: bool,
    /// Whether the server allows clients to request TOFU.
    pub allow_tofu: bool,
}

impl Default for TangConfig {
    fn default() -> Self {
        Self {
            jwk_dir: "/var/db/tang".to_string(),
            default_thp_hash: "S256".to_string(),
            auto_create_keys: true,
            allow_tofu: false,
        }
    }
}

impl TangConfig {
    /// Creates a new configuration.
    pub fn new(jwk_dir: impl Into<String>) -> Self {
        Self {
            jwk_dir: jwk_dir.into(),
            ..Default::default()
        }
    }

    /// Disables automatic key creation.
    pub fn without_auto_create_keys(mut self) -> Self {
        self.auto_create_keys = false;
        self
    }

    /// Allows TOFU requests from clients.
    pub fn with_allow_tofu(mut self, allow: bool) -> Self {
        self.allow_tofu = allow;
        self
    }

    /// Sets a custom thumbprint hash algorithm.
    pub fn with_thp_hash(mut self, hash: impl Into<String>) -> Self {
        self.default_thp_hash = hash.into();
        self
    }
}

/// Tang server policy exposed to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TangPolicy {
    /// Whether the server allows TOFU requests.
    pub allow_tofu: bool,
}

/// High-level Tang server operations.
#[derive(Debug, Clone)]
pub struct TangServer {
    /// Configuration.
    config: TangConfig,
    /// Key store.
    key_store: KeyStore,
}

impl TangServer {
    /// Creates a new Tang server instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration.
    ///
    /// # Returns
    ///
    /// A new server instance with keys loaded from the configured directory.
    pub fn new(config: TangConfig) -> Result<Self> {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Info,
            "server_new";
            jwk_dir = config.jwk_dir.as_str(),
            auto_create_keys = config.auto_create_keys
        );
        let key_store = if config.auto_create_keys {
            KeyStore::load(&config.jwk_dir)?
        } else {
            // Load keys without auto-creation
            KeyStore::load_no_auto_create(&config.jwk_dir)?
        };

        Ok(Self { config, key_store })
    }

    /// Gets the advertisement.
    ///
    /// # Returns
    ///
    /// The default advertisement (signed by all regular signing keys).
    pub fn get_advertisement(&self) -> Result<Advertisement> {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "server_get_adv"
        );
        Advertisement::from_key_store(&self.key_store)
    }

    /// Gets an advertisement signed by a specific key.
    ///
    /// # Arguments
    ///
    /// * `signing_thumbprint` - Thumbprint of the signing key to use.
    ///
    /// # Returns
    ///
    /// An advertisement signed by all regular signing keys plus the
    /// specified key.
    pub fn get_advertisement_with_key(&self, signing_thumbprint: &str) -> Result<Advertisement> {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "server_get_adv_key";
            kid = signing_thumbprint
        );
        Advertisement::with_signing_key(&self.key_store, signing_thumbprint)
    }

    /// Performs a recovery operation.
    ///
    /// # Arguments
    ///
    /// * `exchange_thumbprint` - Thumbprint of the exchange key to use.
    /// * `request` - The client's recovery request.
    ///
    /// # Returns
    ///
    /// The recovery response containing `yJWK`.
    pub fn recover(
        &self,
        exchange_thumbprint: &str,
        request: &RecoveryRequest,
    ) -> Result<RecoveryResponse> {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "server_recover_start";
            kid = exchange_thumbprint
        );
        // Find the exchange key
        let exchange_key = self
            .key_store
            .find_exchange_key(exchange_thumbprint)?
            .ok_or_else(|| {
                Error::key_not_found(format!("Exchange key not found: {}", exchange_thumbprint))
            })?;

        // Create response
        let response = RecoveryResponse::from_request(request, &exchange_key)?;
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "server_recover_ok";
            kid = exchange_thumbprint
        );
        Ok(response)
    }

    /// Gets the key store.
    pub fn key_store(&self) -> &KeyStore {
        &self.key_store
    }

    /// Gets the configuration.
    pub fn config(&self) -> &TangConfig {
        &self.config
    }

    /// Rotates keys (moves them to hidden files).
    ///
    /// This method rotates all regular keys in the JWK directory by:
    /// 1. Renaming regular key files (e.g., `thumbprint.jwk`) to hidden files (e.g., `.thumbprint.jwk`)
    /// 2. Creating new ES512 and ECMR keys with proper permissions (0440)
    ///
    /// After rotation, the server's key store is reloaded to reflect the changes.
    ///
    /// # Arguments
    ///
    /// * `thumbprints` - Thumbprints of keys to rotate. If empty, rotates all regular keys.
    ///
    /// # Returns
    ///
    /// Number of keys successfully rotated.
    pub fn rotate_keys(&mut self, thumbprints: &[&str]) -> Result<usize> {
        use std::fs;
        
        let jwkdir = Path::new(&self.config.jwk_dir);
        
        if !jwkdir.exists() {
            return Err(Error::config(format!("Key directory does not exist: {}", self.config.jwk_dir)));
        }
        
        // Read directory entries
        let entries = fs::read_dir(jwkdir)
            .map_err(|e| Error::config(format!("Failed to read key directory: {}", e)))?;
        
        let mut rotated_count = 0;
        
        for entry in entries {
            let entry = entry.map_err(|e| Error::config(format!("Failed to read directory entry: {}", e)))?;
            let path = entry.path();
            
            // Skip non-files and files without .jwk extension
            if !path.is_file() {
                continue;
            }
            
            let filename = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name,
                None => continue,
            };
            
            // Skip files that don't end with .jwk
            if !filename.ends_with(".jwk") {
                continue;
            }
            
            // Skip already hidden files (starting with '.')
            if filename.starts_with('.') {
                continue;
            }
            
            // Extract thumbprint from filename (remove .jwk extension)
            let thumbprint = &filename[..filename.len() - 4];
            
            // If specific thumbprints are specified, check if this one should be rotated
            if !thumbprints.is_empty() && !thumbprints.contains(&thumbprint) {
                continue;
            }
            
            // Create new hidden filename
            let new_filename = format!(".{}", filename);
            let new_path = jwkdir.join(new_filename);
            
            // Rename the file
            fs::rename(&path, &new_path)
                .map_err(|e| Error::config(format!("Failed to rotate key {}: {}", thumbprint, e)))?;
            
            rotated_count += 1;
        }
        
        // Create new keys if we rotated any keys
        if rotated_count > 0 {
            // Create new ES512 and ECMR keys
            KeyStore::create_new_keys(jwkdir)
                .map_err(|e| Error::config(format!("Failed to create new keys: {}", e)))?;
            
            // Reload the key store to reflect changes
            self.key_store = if self.config.auto_create_keys {
                KeyStore::load(jwkdir)?
            } else {
                KeyStore::load_no_auto_create(jwkdir)?
            };
        }
        
        Ok(rotated_count)
    }

    /// Generates new keys.
    ///
    /// # Arguments
    ///
    /// * `algorithms` - Algorithms to generate (e.g., ["ES512", "ECMR"]).
    ///
    /// # Returns
    ///
    /// Thumbprints of newly generated keys.
    pub fn generate_keys(&self, _algorithms: &[&str]) -> Result<Vec<String>> {
        // Implementation would generate new keys
        // For now, return placeholder
        Ok(Vec::new())
    }
}

/// Client-side Tang operations.
#[derive(Debug)]
pub struct TangClient {
    /// Server URL.
    server_url: String,
    /// Optional trusted advertisement for verification.
    trusted_advertisement: Option<Advertisement>,
}

/// Shared Tang protocol functions used by multiple pins.
pub mod protocol;

impl TangClient {
    /// Creates a new Tang client.
    ///
    /// # Arguments
    ///
    /// * `server_url` - Base URL of the Tang server.
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            trusted_advertisement: None,
        }
    }

    /// Sets a trusted advertisement for verification.
    pub fn with_trusted_advertisement(mut self, advertisement: Advertisement) -> Self {
        self.trusted_advertisement = Some(advertisement);
        self
    }

    /// Fetches the server advertisement.
    ///
    /// # Returns
    ///
    /// The server's advertisement.
    #[cfg(feature = "full")]
    pub async fn fetch_advertisement(&self) -> Result<Advertisement> {
        use reqwest;

        let url = self.build_url("/adv");
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "client_fetch_adv_start";
            url = url.as_str()
        );
        let response = reqwest::get(&url)
            .await
            .map_err(|e| Error::http(format!("Failed to fetch advertisement: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::http(format!(
                "Server returned error: {}",
                response.status()
            )));
        }

        let jws: String = response
            .text()
            .await
            .map_err(|e| Error::http(format!("Failed to read advertisement: {}", e)))?;

        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "client_fetch_adv_ok";
            url = url.as_str(),
            jws_len = jws.len()
        );
        Ok(Advertisement { jws })
    }

    #[cfg(not(feature = "full"))]
    pub async fn fetch_advertisement(&self) -> Result<Advertisement> {
        Err(Error::http("HTTP client features not enabled"))
    }

    /// Performs a recovery operation.
    ///
    /// # Arguments
    ///
    /// * `exchange_thumbprint` - Thumbprint of the exchange key to use.
    /// * `request` - The recovery request.
    ///
    /// # Returns
    ///
    /// The recovery response from the server.
    #[cfg(feature = "full")]
    pub async fn recover(
        &self,
        exchange_thumbprint: &str,
        request: &RecoveryRequest,
    ) -> Result<RecoveryResponse> {
        use reqwest;

        let url = self.build_url(&format!("/rec/{}", exchange_thumbprint));
        let client = reqwest::Client::new();

        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "client_recover_start";
            url = url.as_str(),
            kid = exchange_thumbprint
        );
        let request_json = serde_json::to_value(request)
            .map_err(|e| Error::http(format!("Failed to serialize request: {}", e)))?;

        let response = client
            .post(&url)
            .json(&request_json)
            .send()
            .await
            .map_err(|e| Error::http(format!("Failed to send recovery request: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::http(format!(
                "Server returned error: {}",
                response.status()
            )));
        }

        let jwk: Jwk = response
            .json()
            .await
            .map_err(|e| Error::http(format!("Failed to parse response: {}", e)))?;

        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "client_recover_ok";
            url = url.as_str(),
            kid = exchange_thumbprint
        );
        Ok(RecoveryResponse { jwk })
    }

    #[cfg(not(feature = "full"))]
    pub async fn recover(
        &self,
        _exchange_thumbprint: &str,
        _request: &RecoveryRequest,
    ) -> Result<RecoveryResponse> {
        Err(Error::http("HTTP client features not enabled"))
    }

    /// Builds a full URL with the given path.
    ///
    /// This method normalizes the server URL by adding the `http://` scheme if missing,
    /// then appends the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to append (e.g., "/adv" or "/rec/:thumbprint").
    ///
    /// # Returns
    ///
    /// The fully constructed URL.
    pub fn build_url(&self, path: &str) -> String {
        // Normalize URL: add http:// if no scheme is present
        let base_url = if !self.server_url.contains("://") {
            format!("http://{}", self.server_url)
        } else {
            self.server_url.clone()
        };

        let full = format!("{}{}", base_url, path);
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "client_build_url";
            base_url = base_url.as_str(),
            path = path,
            full_url = full.as_str()
        );
        full
    }
}

/// Utilities for working with Tang protocol.
pub mod util {
    use super::*;

    /// Extracts thumbprints from a JWK Set.
    ///
    /// # Arguments
    ///
    /// * `jwk_set` - The JWK Set to extract thumbprints from.
    /// * `hash_alg` - The hash algorithm to use for thumbprints.
    ///
    /// # Returns
    ///
    /// A map from thumbprint to JWK.
    pub fn extract_thumbprints(jwk_set: &JwkSet, hash_alg: &str) -> Result<HashMap<String, Jwk>> {
        let mut map = HashMap::new();

        for jwk in &jwk_set.keys {
            let thumbprint = jwk
                .thumbprint(hash_alg)
                .map_err(|e| Error::crypto(format!("Failed to compute thumbprint: {}", e)))?;
            map.insert(thumbprint, jwk.clone());
        }

        Ok(map)
    }

    /// Filters JWKs by key operation.
    ///
    /// # Arguments
    ///
    /// * `jwk_set` - The JWK Set to filter.
    /// * `operation` - The key operation to filter by (e.g., "sign", "deriveKey").
    ///
    /// # Returns
    ///
    /// A new JWK Set containing only keys with the specified operation.
    pub fn filter_by_operation(jwk_set: &JwkSet, operation: &str) -> JwkSet {
        let mut filtered = JwkSet::new();

        for jwk in &jwk_set.keys {
            if jwk.has_op(operation) {
                filtered.add(jwk.clone());
            }
        }

        filtered
    }

    /// Validates a JWK Set for Tang advertisement.
    ///
    /// Checks that the JWK Set contains at least one signing key and
    /// one exchange key.
    ///
    /// # Arguments
    ///
    /// * `jwk_set` - The JWK Set to validate.
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid, error otherwise.
    pub fn validate_advertisement(jwk_set: &JwkSet) -> Result<()> {
        let has_signing_key = jwk_set.keys.iter().any(|jwk| {
            jwk.has_op("sign") || matches!(jwk.alg(), Some("ES256" | "ES384" | "ES512"))
        });

        let has_exchange_key = jwk_set
            .keys
            .iter()
            .any(|jwk| jwk.has_op("deriveKey") || jwk.alg() == Some("ECMR"));

        if !has_signing_key {
            return Err(Error::validation(
                "Advertisement must contain at least one signing key".to_string(),
            ));
        }

        if !has_exchange_key {
            return Err(Error::validation(
                "Advertisement must contain at least one exchange key".to_string(),
            ));
        }

        Ok(())
    }

    /// Returns signing keys from a JWK set.
    pub fn signing_keys(jwk_set: &JwkSet) -> Vec<Jwk> {
        jwk_set
            .keys
            .iter()
            .filter(|jwk| jwk.has_op("verify") || matches!(jwk.alg(), Some("ES256" | "ES384" | "ES512")))
            .cloned()
            .collect()
    }

    /// Verifies that the advertisement JWS is signed by at least one signing key.
    pub fn verify_advertisement_signatures(jws: &str, jwk_set: &JwkSet) -> Result<()> {
        let signing = signing_keys(jwk_set);
        if signing.is_empty() {
            return Err(Error::validation(
                "Advertisement has no signing keys for verification".to_string(),
            ));
        }
        let mut verified = false;
        for key in signing {
            if jose::verify_jws(jws, &key).is_ok() {
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(Error::validation(
                "Advertisement signatures failed verification".to_string(),
            ));
        }
        Ok(())
    }

    /// Enforces trusted signing key policy for an advertisement.
    pub fn enforce_advertisement_trust(
        jws: &str,
        jwk_set: &JwkSet,
        thumbprint: Option<&str>,
        allow_tofu: bool,
    ) -> Result<()> {
        if let Some(thp) = thumbprint {
            let signing = signing_keys(jwk_set);
            let mut trusted = false;
            for key in signing {
                let matches = key
                    .thumbprint("S256")
                    .map(|tp| tp == thp)
                    .unwrap_or(false)
                    || key
                        .thumbprint("S1")
                        .map(|tp| tp == thp)
                        .unwrap_or(false);
                if matches && jose::verify_jws(jws, &key).is_ok() {
                    trusted = true;
                    break;
                }
            }
            if !trusted {
                return Err(Error::validation(format!(
                    "Trusted JWK '{}' did not sign the advertisement",
                    thp
                )));
            }
            return Ok(());
        }

        if allow_tofu {
            return Ok(());
        }

        Err(Error::validation(
            "Missing trusted signing key thumbprint (thp); set trust=true to allow TOFU"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tang::util::validate_advertisement;
    use tempfile::TempDir;

    #[test]
    fn test_recovery_request_validation() {
        let valid_request = RecoveryRequest {
            jwk: Jwk::EC(crate::jwk::EcJwk {
                crv: "P-256".to_string(),
                x: "test".to_string(),
                y: "test".to_string(),
                d: None,
                alg: Some("ECMR".to_string()),
                use_: Some("enc".to_string()),
                key_ops: Some(vec!["deriveKey".to_string()]),
                kid: None,
            }),
        };

        assert!(valid_request.validate().is_ok());

        let invalid_curve = RecoveryRequest {
            jwk: Jwk::EC(crate::jwk::EcJwk {
                crv: "P-384".to_string(),
                x: "test".to_string(),
                y: "test".to_string(),
                d: None,
                alg: Some("ECMR".to_string()),
                use_: None,
                key_ops: None,
                kid: None,
            }),
        };

        assert!(invalid_curve.validate().is_err());

        let invalid_algorithm = RecoveryRequest {
            jwk: Jwk::EC(crate::jwk::EcJwk {
                crv: "P-256".to_string(),
                x: "test".to_string(),
                y: "test".to_string(),
                d: None,
                alg: Some("RSA".to_string()),
                use_: None,
                key_ops: None,
                kid: None,
            }),
        };

        assert!(invalid_algorithm.validate().is_err());
    }

    #[test]
    fn test_tang_config() {
        let config = TangConfig::new("/test/dir");
        assert_eq!(config.jwk_dir, "/test/dir");
        assert_eq!(config.default_thp_hash, "S256");
        assert!(config.auto_create_keys);

        let config = config.without_auto_create_keys();
        assert!(!config.auto_create_keys);
    }

    #[test]
    fn test_util_filter_by_operation() {
        let mut jwk_set = JwkSet::new();

        jwk_set.add(Jwk::EC(crate::jwk::EcJwk {
            crv: "P-256".to_string(),
            x: "test1".to_string(),
            y: "test1".to_string(),
            d: None,
            alg: Some("ES256".to_string()),
            use_: Some("sig".to_string()),
            key_ops: Some(vec!["sign".to_string(), "verify".to_string()]),
            kid: None,
        }));

        jwk_set.add(Jwk::EC(crate::jwk::EcJwk {
            crv: "P-256".to_string(),
            x: "test2".to_string(),
            y: "test2".to_string(),
            d: None,
            alg: Some("ECMR".to_string()),
            use_: Some("enc".to_string()),
            key_ops: Some(vec!["deriveKey".to_string()]),
            kid: None,
        }));

        let signing_keys = util::filter_by_operation(&jwk_set, "sign");
        assert_eq!(signing_keys.keys.len(), 1);

        let exchange_keys = util::filter_by_operation(&jwk_set, "deriveKey");
        assert_eq!(exchange_keys.keys.len(), 1);
    }

    #[test]
    fn test_validate_advertisement_requires_signing_key() {
        let tempdir = TempDir::new().unwrap();
        let store = KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();
        let payload = jose::extract_jws_payload(&adv).unwrap();
        let jwk_set: JwkSet = serde_json::from_value(payload).unwrap();

        let mut no_signing = JwkSet::new();
        for key in jwk_set.keys.iter().filter(|jwk| jwk.has_op("deriveKey")) {
            no_signing.add(key.clone());
        }
        let err = validate_advertisement(&no_signing).unwrap_err();
        assert!(err.to_string().contains("signing key"));
    }

    #[test]
    fn test_validate_advertisement_requires_exchange_key() {
        let tempdir = TempDir::new().unwrap();
        let store = KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();
        let payload = jose::extract_jws_payload(&adv).unwrap();
        let jwk_set: JwkSet = serde_json::from_value(payload).unwrap();

        let mut no_exchange = JwkSet::new();
        for key in jwk_set.keys.iter().filter(|jwk| jwk.has_op("sign")) {
            no_exchange.add(key.clone());
        }
        let err = validate_advertisement(&no_exchange).unwrap_err();
        assert!(err.to_string().contains("exchange key"));
    }

    #[test]
    fn test_verify_advertisement_signatures_fails_with_wrong_keys() {
        let tempdir = TempDir::new().unwrap();
        let store = KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();

        let tempdir_other = TempDir::new().unwrap();
        let other_store = KeyStore::load(tempdir_other.path()).unwrap();
        let other_adv = other_store.advertisement(None).unwrap();
        let payload = jose::extract_jws_payload(&other_adv).unwrap();
        let other_jwk_set: JwkSet = serde_json::from_value(payload).unwrap();

        let err = util::verify_advertisement_signatures(&adv, &other_jwk_set).unwrap_err();
        assert!(err.to_string().contains("failed verification"));
    }

    #[test]
    fn test_enforce_advertisement_trust_allows_tofu() {
        let tempdir = TempDir::new().unwrap();
        let store = KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();
        let payload = jose::extract_jws_payload(&adv).unwrap();
        let jwk_set: JwkSet = serde_json::from_value(payload).unwrap();

        util::enforce_advertisement_trust(&adv, &jwk_set, None, true).unwrap();
    }

    #[test]
    fn test_enforce_advertisement_trust_rejects_mismatched_thumbprint() {
        let tempdir = TempDir::new().unwrap();
        let store = KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();
        let payload = jose::extract_jws_payload(&adv).unwrap();
        let jwk_set: JwkSet = serde_json::from_value(payload).unwrap();

        let err =
            util::enforce_advertisement_trust(&adv, &jwk_set, Some("bad"), false).unwrap_err();
        assert!(err.to_string().contains("did not sign"));
    }

    #[test]
    fn test_tang_client_build_url() {
        // Test URL normalization (adding http:// when missing)
        let client = TangClient::new("localhost:8080");
        let url = client.build_url("/adv");
        assert_eq!(url, "http://localhost:8080/adv");

        // Test with scheme already present
        let client = TangClient::new("http://localhost:8080");
        let url = client.build_url("/adv");
        assert_eq!(url, "http://localhost:8080/adv");

        let client = TangClient::new("https://example.com");
        let url = client.build_url("/adv");
        assert_eq!(url, "https://example.com/adv");

        // Test with IPv4 address (no scheme)
        let client = TangClient::new("127.0.0.1:8080");
        let url = client.build_url("/rec/abc123");
        assert_eq!(url, "http://127.0.0.1:8080/rec/abc123");

        // Test with IPv6 address (no scheme) - note: IPv6 addresses in URLs require brackets
        // but our simple normalization doesn't add brackets. We'll skip this for now as
        // the Go implementation handles it, but we can add later if needed.

        // Test that existing scheme is not doubled
        let client = TangClient::new("http://example.com");
        let url = client.build_url("/adv");
        assert_eq!(url, "http://example.com/adv");

        let client = TangClient::new("https://example.com");
        let url = client.build_url("/adv");
        assert_eq!(url, "https://example.com/adv");
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_advertisement_extract_unverified() {
        let tempdir = TempDir::new().unwrap();
        let store = KeyStore::load(tempdir.path()).unwrap();
        let adv = Advertisement::from_key_store(&store).unwrap();
        let jwk_set = adv.extract_unverified().unwrap();

        assert!(jwk_set.keys.len() >= 2);
        validate_advertisement(&jwk_set).unwrap();
    }
}
