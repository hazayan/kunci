//! Yubikey pin implementation for Clevis.
//!
//! This module provides Yubikey pin support, which uses Yubikey hardware tokens
//! for challenge-response based encryption and decryption.
//!
//! The Yubikey pin implements the following functionality:
//! - Challenge-response authentication using Yubikey's HMAC-SHA1 challenge-response capability
//! - Support for slots 1 and 2
//! - PBKDF2 key derivation with configurable hash algorithms (SHA1, SHA256)
//! - Integration with `ykchalresp` and `ykinfo` command-line tools

use std::io::Write;
use std::process::{Command, Stdio};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hex;
use pbkdf2::pbkdf2;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::pin::{Pin, PinConfig, PinMetadata};

/// Yubikey pin configuration for encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubikeyEncryptConfig {
    /// Yubikey slot to use (1 or 2)
    pub slot: u8,
}

/// Yubikey key derivation function configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubikeyKdf {
    /// KDF type (only "pbkdf2" supported)
    #[serde(rename = "type", default = "default_kdf_type")]
    pub type_: String,
    
    /// Hash algorithm (e.g., "sha256")
    #[serde(default = "default_hash")]
    pub hash: String,
    
    /// Iteration count
    #[serde(default = "default_iterations")]
    pub iter: u32,
    
    /// Salt (base64url encoded)
    pub salt: String,
}

fn default_kdf_type() -> String { "pbkdf2".to_string() }
fn default_hash() -> String { "sha256".to_string() }
fn default_iterations() -> u32 { 1000 }

/// Yubikey pin configuration for decryption (embedded in JWE header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubikeyDecryptConfig {
    /// Type of operation (only "chalresp" supported)
    #[serde(rename = "type")]
    pub type_: String,
    
    /// Challenge (base64url encoded)
    pub challenge: String,
    
    /// Yubikey slot to use (1 or 2)
    pub slot: u8,
    
    /// Key derivation function configuration
    pub kdf: YubikeyKdf,
}

/// Yubikey pin implementation.
#[derive(Debug)]
pub struct YubikeyPin;

impl YubikeyPin {
    /// Creates a new Yubikey pin.
    pub fn new() -> Self {
        Self
    }
    
    /// Parses Yubikey encryption configuration from JSON.
    fn parse_encrypt_config(config: &PinConfig) -> Result<YubikeyEncryptConfig> {
        serde_json::from_value(config.clone())
            .map_err(|e| Error::validation(format!("Invalid Yubikey configuration: {}", e)))
    }
    
    /// Parses Yubikey decryption configuration from JWE header.
    fn parse_decrypt_config(config: &PinConfig) -> Result<YubikeyDecryptConfig> {
        serde_json::from_value(config.clone())
            .map_err(|e| Error::validation(format!("Invalid Yubikey decryption configuration: {}", e)))
    }
    
    /// Validates that the slot is either 1 or 2.
    fn validate_slot(slot: u8) -> Result<()> {
        if slot != 1 && slot != 2 {
            Err(Error::validation(format!("Invalid slot value: {}. Slot must be 1 or 2", slot)))
        } else {
            Ok(())
        }
    }
}

/// Perform challenge-response with a specific Yubikey.
///
/// # Arguments
///
/// * `index` - The Yubikey index (starting from 0).
/// * `slot` - The slot (1 or 2).
/// * `challenge` - The challenge bytes (must be 32 bytes).
///
/// # Returns
///
/// The response as 20 bytes.
fn challenge_response_one_yubikey(index: u8, slot: u8, challenge: &[u8]) -> Result<Vec<u8>> {
    let mut cmd = Command::new("ykchalresp");
    cmd.arg(format!("-n{}", index))
        .arg("-i-")
        .arg(format!("-{}", slot));
    
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::external(format!("Failed to spawn ykchalresp: {}", e)))?;
    
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| Error::external("Failed to open stdin"))?;
        stdin.write_all(challenge)
            .map_err(|e| Error::external(format!("Failed to write challenge to ykchalresp: {}", e)))?;
    }
    
    let output = child.wait_with_output()
        .map_err(|e| Error::external(format!("Failed to wait for ykchalresp: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::external(format!("ykchalresp failed: {}", stderr)));
    }
    
    // Output is hex, 40 characters (20 bytes) plus newline
    let hex_output = String::from_utf8(output.stdout)
        .map_err(|e| Error::external(format!("Invalid UTF-8 from ykchalresp: {}", e)))?;
    let hex_trimmed = hex_output.trim();
    if hex_trimmed.len() != 40 {
        return Err(Error::external(format!("Invalid response length: expected 40 hex chars, got {}", hex_trimmed.len())));
    }
    
    let mut response = vec![0u8; 20];
    hex::decode_to_slice(hex_trimmed, &mut response)
        .map_err(|e| Error::external(format!("Failed to decode hex response: {}", e)))?;
    
    Ok(response)
}

/// Check if a Yubikey exists at the given index.
fn yubikey_exists(index: u8) -> bool {
    let output = Command::new("ykinfo")
        .arg(format!("-n{}", index))
        .arg("-a")
        .output();
    
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Try all Yubikeys until one succeeds.
///
/// This function tries Yubikey indexes starting from 0 until it gets a successful response.
/// If a Yubikey exists but fails, it continues to the next index.
/// If no Yubikey responds, returns an error.
fn challenge_response_all_yubikeys(slot: u8, challenge: &[u8]) -> Result<Vec<u8>> {
    for index in 0.. {
        match challenge_response_one_yubikey(index, slot, challenge) {
            Ok(response) => return Ok(response),
            Err(e) => {
                // If the Yubikey doesn't exist, we stop searching.
                if !yubikey_exists(index) {
                    return Err(e);
                }
                // Otherwise, continue to next index.
            }
        }
    }
    
    // Unreachable because the loop goes forever until success or error.
    unreachable!()
}

/// Derive key using PBKDF2 with given parameters.
    fn derive_key(password: &[u8], salt: &[u8], iterations: u32, hash: &str) -> Result<Vec<u8>> {
        let mut key = vec![0u8; 32]; // 256 bits
        
        match hash {
            "sha256" => {
                use sha2::Sha256;
                let _ = pbkdf2::<hmac::Hmac<Sha256>>(password, salt, iterations, &mut key);
            }
            "sha1" => {
                use sha1::Sha1;
                let _ = pbkdf2::<hmac::Hmac<Sha1>>(password, salt, iterations, &mut key);
            }
            _ => return Err(Error::validation(format!("Unsupported hash algorithm: {}", hash))),
        }
        
        Ok(key)
    }

impl Pin for YubikeyPin {
    fn metadata(&self) -> PinMetadata {
        PinMetadata {
            name: "yubikey".to_string(),
            version: "0.1.0".to_string(),
            description: "Yubikey hardware token pin".to_string(),
        }
    }

    fn encrypt(&self, config: &PinConfig, plaintext: &[u8]) -> Result<Value> {
        use rand::RngCore;
        
        // Parse configuration
        let cfg = Self::parse_encrypt_config(config)?;
        
        // Validate slot
        Self::validate_slot(cfg.slot)?;
        
        // Generate random challenge (32 bytes)
        let mut challenge = [0u8; 32];
        rand::rng().fill_bytes(&mut challenge);
        
        // Get response from Yubikey
        let response = challenge_response_all_yubikeys(cfg.slot, &challenge)?;
        
        // Generate random salt (32 bytes)
        let mut salt = [0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        
        // Derive key using PBKDF2
        let iterations = 1000;
        let hash = "sha256";
        let key = derive_key(&response, &salt, iterations, hash)?;
        
        // Create clevis node
        let clevis_node = json!({
            "pin": "yubikey",
            "yubikey": {
                "type": "chalresp",
                "slot": cfg.slot,
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "kdf": {
                    "type": "pbkdf2",
                    "hash": hash,
                    "iter": iterations,
                    "salt": URL_SAFE_NO_PAD.encode(salt),
                }
            }
        });
        
        let header = json!({
            "alg": "dir",
            "enc": "A256GCM",
            "clevis": clevis_node,
        });

        let jwe_compact = crate::jose::jwe_encrypt_dir_a256gcm(plaintext, &key, &header)
            .map_err(|e| Error::crypto(format!("JWE encryption failed: {}", e)))?;
        
        // The compact JWE string is in the format: protected..iv.ciphertext.tag
        // because direct encryption (alg=dir) has empty encrypted key.
        let parts: Vec<&str> = jwe_compact.split('.').collect();
        if parts.len() != 5 {
            return Err(Error::crypto(format!("Invalid JWE compact format: {}", jwe_compact)));
        }
        let protected = parts[0];
        let iv = parts[2];
        let ciphertext = parts[3];
        let tag = parts[4];
        
        // Build JWE JSON structure
        let jwe_value = json!({
            "protected": protected,
            "iv": iv,
            "ciphertext": ciphertext,
            "tag": tag
        });
        
        Ok(jwe_value)
    }

    fn decrypt(&self, _config: &PinConfig, ciphertext: &Value) -> Result<Vec<u8>> {
        // Extract Yubikey configuration from ciphertext
        let clevis_node = ciphertext
            .get("protected")
            .and_then(|p| p.get("clevis"))
            .ok_or_else(|| Error::validation("Missing clevis node in JWE header".to_string()))?;
            
        let yubikey_config = Self::parse_decrypt_config(clevis_node)?;
        
        // Validate configuration
        if yubikey_config.type_ != "chalresp" {
            return Err(Error::validation(format!("Unsupported Yubikey type: {}", yubikey_config.type_)));
        }
        
        Self::validate_slot(yubikey_config.slot)?;
        
        // Decode challenge
        let challenge = URL_SAFE_NO_PAD.decode(&yubikey_config.challenge)
            .map_err(|e| Error::crypto(format!("Failed to decode challenge: {}", e)))?;
        if challenge.len() != 32 {
            return Err(Error::validation(format!("Challenge must be 32 bytes, got {}", challenge.len())));
        }
        
        // Decode salt
        let salt = URL_SAFE_NO_PAD.decode(&yubikey_config.kdf.salt)
            .map_err(|e| Error::crypto(format!("Failed to decode salt: {}", e)))?;
        if salt.len() != 32 {
            return Err(Error::validation(format!("Salt must be 32 bytes, got {}", salt.len())));
        }
        
        // Get response from Yubikey
        let response = challenge_response_all_yubikeys(yubikey_config.slot, &challenge)?;
        
        // Derive key
        let key = derive_key(&response, &salt, yubikey_config.kdf.iter, &yubikey_config.kdf.hash)?;
        
        // Convert JWE JSON to compact string
        let protected = ciphertext
            .get("protected")
            .and_then(|p| p.as_str())
            .ok_or_else(|| Error::validation("Missing protected header".to_string()))?;
        let iv = ciphertext
            .get("iv")
            .and_then(|i| i.as_str())
            .ok_or_else(|| Error::validation("Missing IV".to_string()))?;
        let ciphertext_b64 = ciphertext
            .get("ciphertext")
            .and_then(|c| c.as_str())
            .ok_or_else(|| Error::validation("Missing ciphertext".to_string()))?;
        let tag = ciphertext
            .get("tag")
            .and_then(|t| t.as_str())
            .ok_or_else(|| Error::validation("Missing tag".to_string()))?;
        
        // For direct encryption (alg=dir), the encrypted key is empty, so the compact string is:
        // protected..iv.ciphertext.tag
        let jwe_compact = format!("{}..{}.{}.{}", protected, iv, ciphertext_b64, tag);
        
        // Decrypt
        crate::jose::jwe_decrypt_dir_a256gcm(&jwe_compact, &key)
            .map_err(|e| Error::crypto(format!("JWE decryption failed: {}", e)))
    }
}

impl Default for YubikeyPin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Check if a Yubikey is present for testing.
    fn yubikey_present() -> bool {
        let output = Command::new("lsusb").output();
        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout.contains("Yubikey")
            }
            Err(_) => false,
        }
    }
    
    #[test]
    fn test_yubikey_pin_metadata() {
        let pin = YubikeyPin::new();
        let metadata = pin.metadata();
        
        assert_eq!(metadata.name, "yubikey");
        assert_eq!(metadata.version, "0.1.0");
        assert!(metadata.description.contains("Yubikey"));
    }
    
    #[test]
    fn test_parse_encrypt_config() {
        let config = json!({
            "slot": 1
        });
        
        let result = YubikeyPin::parse_encrypt_config(&config);
        assert!(result.is_ok());
        
        let cfg = result.unwrap();
        assert_eq!(cfg.slot, 1);
    }
    
    #[test]
    fn test_validate_slot_valid() {
        assert!(YubikeyPin::validate_slot(1).is_ok());
        assert!(YubikeyPin::validate_slot(2).is_ok());
    }
    
    #[test]
    fn test_validate_slot_invalid() {
        assert!(YubikeyPin::validate_slot(0).is_err());
        assert!(YubikeyPin::validate_slot(3).is_err());
        assert!(YubikeyPin::validate_slot(255).is_err());
    }
    
    #[test]
    fn test_parse_decrypt_config() {
        let config = json!({
            "type": "chalresp",
            "challenge": "challenge_base64",
            "slot": 2,
            "kdf": {
                "type": "pbkdf2",
                "hash": "sha256",
                "iter": 1000,
                "salt": "salt_base64"
            }
        });
        
        let result = YubikeyPin::parse_decrypt_config(&config);
        assert!(result.is_ok());
        
        let cfg = result.unwrap();
        assert_eq!(cfg.type_, "chalresp");
        assert_eq!(cfg.challenge, "challenge_base64");
        assert_eq!(cfg.slot, 2);
        assert_eq!(cfg.kdf.type_, "pbkdf2");
        assert_eq!(cfg.kdf.hash, "sha256");
        assert_eq!(cfg.kdf.iter, 1000);
        assert_eq!(cfg.kdf.salt, "salt_base64");
    }
    
    #[test]
    fn test_encrypt_decrypt_placeholder() {
        // Skip if no Yubikey present
        if !yubikey_present() {
            return;
        }
        
        let pin = YubikeyPin::new();
        let config = json!({
            "slot": 2
        });
        let plaintext = b"test data";
        
        // Encrypt
        let ciphertext = pin.encrypt(&config, plaintext).unwrap();
        
        // Verify structure
        assert!(ciphertext.get("protected").is_some());
        assert!(ciphertext.get("ciphertext").is_some());
        
        // Decrypt (placeholder implementation just decodes base64)
        let decrypted = pin.decrypt(&config, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
