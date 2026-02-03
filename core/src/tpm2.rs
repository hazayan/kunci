//! TPM2 pin implementation for Clevis.
//!
//! This module provides TPM2 pin support, which uses Trusted Platform Module 2.0
//! for hardware-backed encryption and decryption with optional PCR binding.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::pin::{Pin, PinConfig, PinMetadata};

/// TPM2 pin configuration for encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tpm2EncryptConfig {
    /// Hash algorithm used in the computation of the object name (default: sha256)
    #[serde(default = "default_hash")]
    pub hash: String,
    
    /// Algorithm type for the generated key (default: ecc)
    #[serde(default = "default_key")]
    pub key: String,
    
    /// PCR algorithm bank to use for policy (default: sha1)
    #[serde(default = "default_pcr_bank")]
    pub pcr_bank: String,
    
    /// PCR list used for policy. If not present, no policy is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_ids: Option<Value>,
    
    /// Binary PCR hashes encoded in base64. If not present, the hash values are looked up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_digest: Option<String>,
}

fn default_hash() -> String { "sha256".to_string() }
fn default_key() -> String { "ecc".to_string() }
fn default_pcr_bank() -> String { "sha1".to_string() }

/// TPM2 pin configuration for decryption (embedded in JWE header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tpm2DecryptConfig {
    /// Hash algorithm used in the computation of the object name.
    pub hash: String,
    
    /// Algorithm type for the generated key.
    pub key: String,
    
    /// Public part of the sealed object (TPM2B_PUBLIC in base64url).
    pub jwk_pub: String,
    
    /// Private part of the sealed object (TPM2B_PRIVATE in base64url).
    pub jwk_priv: String,
    
    /// PCR algorithm bank used for policy.
    pub pcr_bank: String,
    
    /// PCR list used for policy.
    pub pcr_ids: Option<Value>,
}

/// TPM2 pin implementation.
#[derive(Debug)]
pub struct Tpm2Pin;

impl Tpm2Pin {
    /// Creates a new TPM2 pin.
    pub fn new() -> Self {
        Self
    }
    
    /// Parses TPM2 encryption configuration from JSON.
    fn parse_encrypt_config(config: &PinConfig) -> Result<Tpm2EncryptConfig> {
        serde_json::from_value(config.clone())
            .map_err(|e| Error::validation(format!("Invalid TPM2 configuration: {}", e)))
    }
    
    /// Parses TPM2 decryption configuration from JWE header.
    fn parse_decrypt_config(config: &PinConfig) -> Result<Tpm2DecryptConfig> {
        serde_json::from_value(config.clone())
            .map_err(|e| Error::validation(format!("Invalid TPM2 decryption configuration: {}", e)))
    }
}

impl Pin for Tpm2Pin {
    fn metadata(&self) -> PinMetadata {
        PinMetadata {
            name: "tpm2".to_string(),
            version: "0.1.0".to_string(),
            description: "TPM2 hardware security module pin".to_string(),
        }
    }

    #[cfg(feature = "tpm2")]
    fn encrypt(&self, _config: &PinConfig, _plaintext: &[u8]) -> Result<Value> {
        Err(Error::external("TPM2 encryption not implemented yet".to_string()))
    }

    #[cfg(not(feature = "tpm2"))]
    fn encrypt(&self, _config: &PinConfig, _plaintext: &[u8]) -> Result<Value> {
        Err(Error::external("TPM2 feature not enabled".to_string()))
    }

    #[cfg(feature = "tpm2")]
    fn decrypt(&self, _config: &PinConfig, _ciphertext: &Value) -> Result<Vec<u8>> {
        Err(Error::external("TPM2 decryption not implemented yet".to_string()))
    }

    #[cfg(not(feature = "tpm2"))]
    fn decrypt(&self, _config: &PinConfig, _ciphertext: &Value) -> Result<Vec<u8>> {
        Err(Error::external("TPM2 feature not enabled".to_string()))
    }
}

impl Default for Tpm2Pin {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse PCR IDs from a JSON value (similar to Go's parsePcrIds).
fn parse_pcr_ids(pcr_ids: &Value) -> Result<Vec<u32>> {
    match pcr_ids {
        Value::Null => Ok(vec![]),
        Value::String(s) => {
            let mut ids = Vec::new();
            for part in s.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let id = part.parse::<u32>()
                    .map_err(|e| Error::validation(format!("Invalid PCR ID '{}': {}", part, e)))?;
                ids.push(id);
            }
            Ok(ids)
        }
        Value::Array(arr) => {
            let mut ids = Vec::new();
            for val in arr {
                match val {
                    Value::Number(n) => {
                        let id = n.as_u64()
                            .ok_or_else(|| Error::validation(format!("PCR ID must be a non-negative integer: {}", n)))? as u32;
                        ids.push(id);
                    }
                    Value::String(s) => {
                        let id = s.parse::<u32>()
                            .map_err(|e| Error::validation(format!("Invalid PCR ID '{}': {}", s, e)))?;
                        ids.push(id);
                    }
                    _ => return Err(Error::validation("PCR ID must be a number or string".to_string())),
                }
            }
            Ok(ids)
        }
        _ => Err(Error::validation("Invalid PCR IDs format".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tpm2_pin_metadata() {
        let pin = Tpm2Pin::new();
        let metadata = pin.metadata();
        
        assert_eq!(metadata.name, "tpm2");
        assert_eq!(metadata.version, "0.1.0");
        assert!(metadata.description.contains("TPM2"));
    }
    
    #[test]
    fn test_parse_pcr_ids() {
        // Null
        let val = Value::Null;
        let ids = parse_pcr_ids(&val).unwrap();
        assert!(ids.is_empty());
        
        // String
        let val = Value::String("0,1,2,3".to_string());
        let ids = parse_pcr_ids(&val).unwrap();
        assert_eq!(ids, vec![0, 1, 2, 3]);
        
        // Array of numbers
        let val = json!([0, 1, 2, 3]);
        let ids = parse_pcr_ids(&val).unwrap();
        assert_eq!(ids, vec![0, 1, 2, 3]);
        
        // Array of strings
        let val = json!(["0", "1", "2", "3"]);
        let ids = parse_pcr_ids(&val).unwrap();
        assert_eq!(ids, vec![0, 1, 2, 3]);
    }
}
