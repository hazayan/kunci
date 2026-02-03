//! Clevis pin interface and implementations.
//!
//! This module provides the pin interface for Clevis, allowing different
//! encryption/decryption methods (pins) to be used interchangeably.

use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

use crate::error::{Error, Result};

/// Configuration for a pin, represented as a JSON object.
pub type PinConfig = Value;

/// Pin metadata (name, version, description).
#[derive(Debug, Clone)]
pub struct PinMetadata {
    /// Pin name.
    pub name: String,
    /// Pin version.
    pub version: String,
    /// Pin description.
    pub description: String,
}

/// Pin trait that all Clevis pins must implement.
pub trait Pin: Send + Sync {
    /// Returns metadata about the pin.
    fn metadata(&self) -> PinMetadata;

    /// Encrypts data using the pin configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The pin configuration.
    /// * `plaintext` - The data to encrypt.
    ///
    /// # Returns
    ///
    /// The encrypted data as a JSON object (JWE format).
    fn encrypt(&self, config: &PinConfig, plaintext: &[u8]) -> Result<Value>;

    /// Decrypts data using the pin configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The pin configuration (may be embedded in the JWE).
    /// * `ciphertext` - The encrypted data (JWE JSON).
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    fn decrypt(&self, config: &PinConfig, ciphertext: &Value) -> Result<Vec<u8>>;
}

/// A registry of available pins.
pub struct PinRegistry {
    pins: HashMap<String, Box<dyn Pin>>,
}

impl fmt::Debug for PinRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinRegistry")
            .field("pins", &self.pins.len())
            .finish()
    }
}

impl PinRegistry {
    /// Creates a new, empty pin registry.
    pub fn new() -> Self {
        Self {
            pins: HashMap::new(),
        }
    }

    /// Registers a pin with the registry.
    pub fn register(&mut self, pin: Box<dyn Pin>) {
        let metadata = pin.metadata();
        self.pins.insert(metadata.name.clone(), pin);
    }

    /// Returns a reference to a pin by name.
    pub fn get(&self, name: &str) -> Option<&dyn Pin> {
        self.pins.get(name).map(|p| p.as_ref())
    }

    /// Returns a list of registered pin names.
    pub fn pin_names(&self) -> Vec<String> {
        self.pins.keys().cloned().collect()
    }

    /// Decrypt a Clevis JWE (JSON Web Encryption) using a registered pin.
    ///
    /// This method extracts the pin name from the JWE's "protected" header,
    /// looks up the corresponding pin, and delegates decryption to that pin.
    ///
    /// # Arguments
    ///
    /// * `jwe` - The JWE as a JSON value (must be a valid JWE JSON structure).
    ///
    /// # Returns
    ///
    /// The decrypted plaintext as a byte vector.
    pub fn decrypt(&self, jwe: &serde_json::Value) -> Result<Vec<u8>> {
        // Extract the protected header
        let protected = jwe
            .get("protected")
            .ok_or_else(|| Error::validation("Missing 'protected' header in JWE".to_string()))?;

        // Decode the protected header (it's base64url encoded)
        let protected_str = protected
            .as_str()
            .ok_or_else(|| Error::validation("Protected header must be a string".to_string()))?;

        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let protected_bytes = URL_SAFE_NO_PAD.decode(protected_str)
            .map_err(|e| Error::crypto(format!("Failed to decode protected header: {}", e)))?;
        let protected_json: serde_json::Value = serde_json::from_slice(&protected_bytes)
            .map_err(|e| Error::crypto(format!("Failed to parse protected header: {}", e)))?;

        // Extract the pin name from the "clevis" object
        let clevis = protected_json
            .get("clevis")
            .ok_or_else(|| Error::validation("Missing 'clevis' object in protected header".to_string()))?;

        let pin_name = clevis
            .get("pin")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::validation("Missing 'pin' field in clevis object".to_string()))?;

        // Look up the pin
        let pin = self.get(pin_name)
            .ok_or_else(|| Error::validation(format!("Pin '{}' not registered", pin_name)))?;

        // For now, pass an empty config. Some pins (like Tang) require additional configuration.
        // In the future, we might need to pass a configuration that includes, for example, the Tang advertisement.
        let config = serde_json::Value::Object(serde_json::Map::new());

        pin.decrypt(&config, jwe)
    }
}

impl Default for PinRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Null pin (for testing and development).
///
/// The null pin does not perform any encryption; it simply returns the plaintext.
#[derive(Debug)]
pub struct NullPin;

impl NullPin {
    /// Creates a new null pin.
    pub fn new() -> Self {
        Self
    }
}

impl Pin for NullPin {
    fn metadata(&self) -> PinMetadata {
        PinMetadata {
            name: "null".to_string(),
            version: "0.1.0".to_string(),
            description: "Null pin for testing (no encryption)".to_string(),
        }
    }

    fn encrypt(&self, _config: &PinConfig, plaintext: &[u8]) -> Result<Value> {
        // Return a simple JSON structure with the plaintext base64-encoded.
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let base64_plaintext = STANDARD.encode(plaintext);
        Ok(serde_json::json!({
            "protected": {},
            "encrypted_key": "",
            "iv": "",
            "ciphertext": base64_plaintext,
            "tag": ""
        }))
    }

    fn decrypt(&self, _config: &PinConfig, ciphertext: &Value) -> Result<Vec<u8>> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        // Extract the base64-encoded plaintext from the ciphertext JSON.
        let base64_str = ciphertext
            .get("ciphertext")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::validation("Missing ciphertext field".to_string()))?;

        STANDARD
            .decode(base64_str)
            .map_err(|e| Error::validation(format!("Failed to decode base64: {}", e)))
    }
}

/// SSS (Shamir's Secret Sharing) pin.
///
/// This pin uses Shamir's Secret Sharing to split a secret into multiple shares.
/// The configuration must specify the threshold and the number of shares.
#[derive(Debug)]
pub struct SssPin;

impl SssPin {
    /// Creates a new SSS pin.
    pub fn new() -> Self {
        Self
    }
}

impl Pin for SssPin {
    fn metadata(&self) -> PinMetadata {
        PinMetadata {
            name: "sss".to_string(),
            version: "0.1.0".to_string(),
            description: "Shamir's Secret Sharing pin".to_string(),
        }
    }

    fn encrypt(&self, config: &PinConfig, plaintext: &[u8]) -> Result<Value> {
        use base64::engine::general_purpose::STANDARD;
        use base64::engine::Engine;
        use rand::RngCore;

        // Parse configuration
        let t = config
            .get("t")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::validation("Missing threshold (t) in SSS config".to_string()))?
            as usize;

        let n = config
            .get("n")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                Error::validation("Missing number of shares (n) in SSS config".to_string())
            })? as usize;

        if t < 1 || n < t {
            return Err(Error::validation("Invalid threshold or number of shares".to_string()));
        }

        // Generate a random secret key (32 bytes)
        let mut secret_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_key);

        // Create SSS configuration with 32-byte key and threshold t
        let sss_config = crate::sss::SssConfig::generate(32, t)
            .map_err(|e| Error::crypto(format!("Failed to generate SSS config: {}", e)))?;

        // Generate n shares
        let mut shares = Vec::with_capacity(n);
        for _ in 0..n {
            let point = sss_config
                .point()
                .map_err(|e| Error::crypto(format!("Failed to generate SSS point: {}", e)))?;
            shares.push(point);
        }

        // Encode data for storage
        let prime_bytes = sss_config.p.to_bytes_be();
        let prime_b64 = STANDARD.encode(&prime_bytes);
        
        let shares_b64: Vec<String> = shares
            .iter()
            .map(|share| STANDARD.encode(share))
            .collect();

        // For now, we store the plaintext as base64 (no actual encryption)
        // In a real implementation, we would encrypt the plaintext with the secret key
        let ciphertext_b64 = STANDARD.encode(plaintext);

        // Construct JWE-like structure with SSS parameters in unprotected header
        let jwe = serde_json::json!({
            "protected": {
                "alg": "SSS",
                "enc": "none", // No encryption, just encoding for demonstration
            },
            "unprotected": {
                "sss": {
                    "p": prime_b64,
                    "shares": shares_b64,
                    "t": t,
                    "n": n,
                }
            },
            "ciphertext": ciphertext_b64,
        });

        Ok(jwe)
    }

    fn decrypt(&self, _config: &PinConfig, ciphertext: &Value) -> Result<Vec<u8>> {
        use base64::engine::general_purpose::STANDARD;
        use base64::engine::Engine;

        // Extract SSS parameters from unprotected header
        let sss_params = ciphertext
            .get("unprotected")
            .and_then(|u| u.get("sss"))
            .ok_or_else(|| Error::validation("Missing SSS parameters in ciphertext".to_string()))?;

        let prime_b64 = sss_params
            .get("p")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::validation("Missing prime (p) in SSS parameters".to_string()))?;

        let shares_b64 = sss_params
            .get("shares")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::validation("Missing shares in SSS parameters".to_string()))?;

        // Decode prime and shares
        let prime_bytes = STANDARD.decode(prime_b64)
            .map_err(|e| Error::crypto(format!("Failed to decode prime: {}", e)))?;
        let prime = num_bigint::BigUint::from_bytes_be(&prime_bytes);

        let shares: Result<Vec<Vec<u8>>> = shares_b64
            .iter()
            .map(|share_b64| {
                share_b64
                    .as_str()
                    .ok_or_else(|| Error::validation("Invalid share encoding".to_string()))
                    .and_then(|s| {
                        STANDARD.decode(s)
                            .map_err(|e| Error::crypto(format!("Failed to decode share: {}", e)))
                    })
            })
            .collect();

        let shares = shares?;

        // Recover the secret key (not used in this demonstration)
        let _secret_key = crate::sss::recover(&prime, &shares)
            .map_err(|e| Error::crypto(format!("Failed to recover secret: {}", e)))?;

        // Extract and decode the ciphertext (which is just base64 encoded plaintext)
        let ciphertext_b64 = ciphertext
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::validation("Missing ciphertext".to_string()))?;

        let plaintext = STANDARD.decode(ciphertext_b64)
            .map_err(|e| Error::crypto(format!("Failed to decode ciphertext: {}", e)))?;

        Ok(plaintext)
    }
}

/// Tang pin for network-bound encryption.
///
/// This pin uses a Tang server to perform key exchange and encryption.
#[cfg(feature = "full")]
#[derive(Debug)]
pub struct TangPin;

#[cfg(feature = "full")]
impl TangPin {
    /// Creates a new Tang pin.
    pub fn new() -> Self {
        Self
    }

    fn normalize_adv(value: &Value) -> Result<String> {
        if let Some(adv) = value.as_str() {
            return Ok(adv.to_string());
        }
        if value.is_object() || value.is_array() {
            return serde_json::to_string(value)
                .map_err(|e| Error::validation(format!("Failed to serialize adv: {}", e)));
        }
        Err(Error::validation(
            "Invalid 'adv' format in Tang configuration".to_string(),
        ))
    }

    fn ensure_tofu_allowed(url: &str) -> Result<()> {
        let policy = crate::tang::protocol::HttpExchangeCallback::new(url).fetch_policy()?;
        if !policy.allow_tofu {
            return Err(Error::validation(
                "Server policy does not allow TOFU".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "full")]
impl Pin for TangPin {
    fn metadata(&self) -> PinMetadata {
        PinMetadata {
            name: "tang".to_string(),
            version: "0.1.0".to_string(),
            description: "Tang network-bound encryption pin".to_string(),
        }
    }

    fn encrypt(&self, config: &PinConfig, plaintext: &[u8]) -> Result<Value> {
        let tang_node = if let Some(node) = config.get("tang") {
            node
        } else {
            config
        };
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "encrypt";
            plaintext_len = plaintext.len(),
            has_tang_node = config.get("tang").is_some()
        );

        // Parse configuration - advertisement must be provided
        let adv_value = tang_node
            .get("adv")
            .ok_or_else(|| Error::validation("Missing 'adv' (advertisement) in Tang configuration".to_string()))?;
        let adv = Self::normalize_adv(adv_value)?;
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "encrypt_adv";
            adv_len = adv.len()
        );

        let thp = tang_node.get("thp").and_then(|v| v.as_str());
        let url = tang_node.get("url").and_then(|v| v.as_str());
        let allow_tofu = tang_node
            .get("trust")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if allow_tofu {
            let url = url.ok_or_else(|| {
                Error::validation("TOFU requires 'url' to verify server policy".to_string())
            })?;
            Self::ensure_tofu_allowed(url)?;
        }
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "encrypt_inputs";
            thp_present = thp.is_some(),
            url_present = url.is_some()
        );

        let mut tang_map = serde_json::Map::new();
        tang_map.insert("adv".to_string(), Value::String(adv.to_string()));
        if let Some(thp) = thp {
            tang_map.insert("thp".to_string(), Value::String(thp.to_string()));
        }
        if let Some(url) = url {
            tang_map.insert("url".to_string(), Value::String(url.to_string()));
        }
        if allow_tofu {
            tang_map.insert("trust".to_string(), Value::Bool(true));
        }
        let tang_node = Value::Object(tang_map);

        let clevis_node = serde_json::json!({
            "pin": "tang",
            "tang": tang_node
        });

        let jwe_string = crate::tang::protocol::encrypt_with_tang_protocol(
            plaintext,
            &adv,
            thp,
            clevis_node,
            allow_tofu,
        )?;

        // Return as JSON object (compact JWE string)
        Ok(serde_json::json!({
            "jwe": jwe_string
        }))
    }

    fn decrypt(&self, config: &PinConfig, ciphertext: &Value) -> Result<Vec<u8>> {
        let tang_node = if let Some(node) = config.get("tang") {
            node
        } else if let Some(clevis) = config.get("clevis") {
            clevis
                .get("tang")
                .ok_or_else(|| Error::validation("Missing tang config".to_string()))?
        } else {
            config
        };

        let adv_value = tang_node
            .get("adv")
            .ok_or_else(|| Error::validation("Missing 'adv' in Tang configuration".to_string()))?;
        let adv = Self::normalize_adv(adv_value)?;
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "decrypt_adv";
            adv_len = adv.len()
        );

        let thp = tang_node.get("thp").and_then(|v| v.as_str());
        let allow_tofu = tang_node
            .get("trust")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let url = tang_node
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::validation("Missing 'url' in Tang configuration".to_string()))?;
        if allow_tofu {
            Self::ensure_tofu_allowed(url)?;
        }
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "decrypt_url";
            url = url
        );

        let jwe_compact = crate::zfs::convert_jwe_json_to_compact(ciphertext)?;
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "decrypt_jwe";
            jwe_len = jwe_compact.len()
        );
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Info,
            "decrypt_start"
        );
        let exchange = crate::tang::protocol::HttpExchangeCallback::new(url);
        let key = crate::tang::protocol::recover_key_with_tang_protocol(
            &jwe_compact,
            &adv,
            thp,
            &exchange,
            allow_tofu,
        )?;
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "decrypt_recover_ok";
            key_len = key.len()
        );
        let plaintext = crate::jose::jwe_decrypt_dir_a256gcm(&jwe_compact, &key)
            .map_err(|e| Error::crypto(format!("JWE decryption failed: {}", e)))?;
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Info,
            "decrypt_ok";
            plaintext_len = plaintext.len()
        );
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::json;
    use tempfile::TempDir;

    #[cfg(feature = "full")]
    #[test]
    fn test_tang_encrypt_emits_jwe_only() {
        let tempdir = TempDir::new().unwrap();
        let store = crate::keys::KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();
        let thp = store
            .signing_keys
            .first()
            .and_then(|key| key.thumbprint("S256").ok())
            .expect("signing key thumbprint");

        let pin = TangPin::new();
        let config = json!({
            "adv": adv,
            "thp": thp
        });
        let ciphertext = pin.encrypt(&config, b"secret").unwrap();

        assert!(ciphertext.get("jwe").is_some());
        assert!(ciphertext.get("client_key").is_none());

        let jwe = ciphertext.get("jwe").and_then(|v| v.as_str()).unwrap();
        let header_b64 = jwe.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: Value = serde_json::from_slice(&header_bytes).unwrap();

        assert!(header.get("epk").is_some());
        assert!(header.get("clevis").is_some());
        assert!(header.get("client_jwk").is_none());
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_tang_decrypt_requires_url() {
        let tempdir = TempDir::new().unwrap();
        let store = crate::keys::KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();

        let pin = TangPin::new();
        let config = json!({
            "adv": adv
        });
        let ciphertext = json!({});

        let err = pin.decrypt(&config, &ciphertext).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Missing 'url'"));
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_tang_normalize_adv_accepts_object_or_string() {
        let adv_obj = json!({
            "payload": "abc",
            "signatures": []
        });
        let adv_from_obj = TangPin::normalize_adv(&adv_obj).unwrap();
        assert!(adv_from_obj.contains("\"payload\":\"abc\""));

        let adv_str_value = json!("jws-string");
        let adv_from_str = TangPin::normalize_adv(&adv_str_value).unwrap();
        assert_eq!(adv_from_str, "jws-string");
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_tang_encrypt_requires_adv() {
        let pin = TangPin::new();
        let config = json!({
            "url": "http://example"
        });
        let err = pin.encrypt(&config, b"secret").unwrap_err();
        assert!(err.to_string().contains("Missing 'adv'"));
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_tang_encrypt_rejects_invalid_adv_type() {
        let pin = TangPin::new();
        let config = json!({
            "adv": 42,
            "url": "http://example"
        });
        let err = pin.encrypt(&config, b"secret").unwrap_err();
        assert!(err.to_string().contains("Invalid 'adv'"));
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_tang_decrypt_requires_adv() {
        let pin = TangPin::new();
        let config = json!({
            "url": "http://example"
        });
        let err = pin.decrypt(&config, &json!({})).unwrap_err();
        assert!(err.to_string().contains("Missing 'adv'"));
    }
}
