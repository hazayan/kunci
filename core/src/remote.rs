//! Remote pin implementation for Clevis.
//!
//! This module provides remote pin support, which is a client that acts as a proxy
//! to another Tang server. It allows for network-bound encryption with a remote
//! Tang server that may be behind a firewall or in a different network.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::jose;
use crate::jwk::JwkSet;
use crate::pin::{Pin, PinConfig, PinMetadata};
use crate::tang::protocol::{encrypt_with_tang_protocol, recover_key_with_tang_protocol, ExchangeCallback};

/// Remote pin configuration for encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteEncryptConfig {
    /// A trusted advertisement (JSON string or file path)
    pub adv: String,
    
    /// Port to listen for incoming requests (default: 8609)
    #[serde(default = "default_port")]
    pub port: u16,
    
    /// The thumbprint of a trusted signing key (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thp: Option<String>,

    /// Whether to allow TOFU (trust on first use).
    #[serde(default)]
    pub trust: bool,
}

fn default_port() -> u16 { 8609 }

/// Remote pin configuration for decryption (embedded in JWE header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteDecryptConfig {
    /// Advertisement from the remote server (base64 encoded)
    pub adv: String,
    
    /// Port to listen for incoming requests
    pub port: u16,

    /// The thumbprint of a trusted signing key (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thp: Option<String>,

    /// Whether to allow TOFU (trust on first use).
    #[serde(default)]
    pub trust: bool,
}

/// Remote pin implementation.
#[derive(Debug)]
pub struct RemotePin;

impl RemotePin {
    /// Creates a new remote pin.
    pub fn new() -> Self {
        Self
    }
    
    /// Parses remote encryption configuration from JSON.
    fn parse_encrypt_config(config: &PinConfig) -> Result<RemoteEncryptConfig> {
        serde_json::from_value(config.clone())
            .map_err(|e| Error::validation(format!("Invalid remote configuration: {}", e)))
    }
    
    /// Parses remote decryption configuration from JWE header.
    fn parse_decrypt_config(config: &PinConfig) -> Result<RemoteDecryptConfig> {
        serde_json::from_value(config.clone())
            .map_err(|e| Error::validation(format!("Invalid remote decryption configuration: {}", e)))
    }
    
    /// Loads advertisement from a string that may be a JSON string or a file path.
    fn load_advertisement(adv: &str) -> Result<String> {
        // Try to parse as JSON first
        if let Ok(_) = serde_json::from_str::<Value>(adv) {
            return Ok(adv.to_string());
        }
        
        // If that fails, try to read as a file
        std::fs::read_to_string(adv)
            .map_err(|e| Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read advertisement file: {}", e)
            )))
    }

    fn decode_advertisement(adv: &str) -> String {
        match URL_SAFE_NO_PAD.decode(adv) {
            Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| adv.to_string()),
            Err(_) => adv.to_string(),
        }
    }
}

impl Pin for RemotePin {
    fn metadata(&self) -> PinMetadata {
        PinMetadata {
            name: "remote".to_string(),
            version: "0.1.0".to_string(),
            description: "Remote Tang server proxy pin".to_string(),
        }
    }

    fn encrypt(&self, config: &PinConfig, plaintext: &[u8]) -> Result<Value> {
        // Parse configuration
        let cfg = Self::parse_encrypt_config(config)?;
        crate::klog!(
            module: "remote",
            level: crate::log::LogLevel::Debug,
            "encrypt";
            plaintext_len = plaintext.len(),
            port = cfg.port,
            adv_len = cfg.adv.len()
        );
        
        // Load advertisement
        let advertisement = Self::load_advertisement(&cfg.adv)?;
        
        // Create clevis node for remote pin
        let clevis_node = json!({
            "pin": "remote",
            "remote": {
                "adv": advertisement,
                "port": cfg.port,
                "thp": cfg.thp,
                "trust": cfg.trust
            }
        });
        
        // Encrypt using shared Tang protocol
        let jwe = encrypt_with_tang_protocol(
            plaintext,
            &advertisement,
            cfg.thp.as_deref(),
            clevis_node,
            cfg.trust,
        )?;
        
        // Parse JWE compact to JSON for return
        let parts: Vec<&str> = jwe.split('.').collect();
        if parts.len() != 5 {
            return Err(Error::validation("Invalid JWE compact format".to_string()));
        }
        
        // Decode header
        let header_b64 = parts[0];
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64)
            .map_err(|e| Error::crypto(format!("Failed to decode JWE header: {}", e)))?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| Error::crypto(format!("Failed to parse JWE header: {}", e)))?;
        
        // Build JWE JSON structure
        Ok(json!({
            "protected": header,
            "encrypted_key": parts[1],
            "iv": parts[2],
            "ciphertext": parts[3],
            "tag": parts[4]
        }))
    }

    fn decrypt(&self, _config: &PinConfig, ciphertext: &Value) -> Result<Vec<u8>> {
        // Extract remote configuration from ciphertext
        let remote_node = ciphertext
            .get("protected")
            .and_then(|p| p.get("clevis"))
            .and_then(|c| c.get("remote"))
            .ok_or_else(|| Error::validation("Missing remote configuration in JWE header".to_string()))?;
            
        let remote_config = Self::parse_decrypt_config(remote_node)?;
        
        let advertisement = Self::decode_advertisement(&remote_config.adv);
        crate::klog!(
            module: "remote",
            level: crate::log::LogLevel::Debug,
            "decrypt";
            port = remote_config.port,
            adv_len = advertisement.len()
        );
        
        // Create TCP exchange callback
        let exchange_callback = TcpExchangeCallback {
            port: remote_config.port,
        };
        
        // Convert JWE JSON to compact format
        let protected = ciphertext
            .get("protected")
            .ok_or_else(|| Error::validation("Missing protected header".to_string()))?;
        let protected_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(protected)?);
        
        let encrypted_key = ciphertext
            .get("encrypted_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let iv = ciphertext
            .get("iv")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::validation("Missing IV".to_string()))?;
        let ciphertext_b64 = ciphertext
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::validation("Missing ciphertext".to_string()))?;
        let tag = ciphertext
            .get("tag")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::validation("Missing tag".to_string()))?;
        
        let jwe_compact = format!(
            "{}.{}.{}.{}.{}",
            protected_b64, encrypted_key, iv, ciphertext_b64, tag
        );
        crate::klog!(
            module: "remote",
            level: crate::log::LogLevel::Debug,
            "decrypt_jwe";
            jwe_len = jwe_compact.len()
        );
        
        // Recover key using shared Tang protocol with TCP exchange
        let key = recover_key_with_tang_protocol(
            &jwe_compact,
            &advertisement,
            remote_config.thp.as_deref(),
            &exchange_callback,
            remote_config.trust,
        )?;

        jose::jwe_decrypt_dir_a256gcm(&jwe_compact, &key)
            .map_err(|e| Error::crypto(format!("JWE decryption failed: {}", e)))
    }
}

/// TCP exchange callback for remote pin decryption.
struct TcpExchangeCallback {
    port: u16,
}

impl ExchangeCallback for TcpExchangeCallback {
    fn exchange(
        &self,
        server_key_id: &str,
        advertized_keys: &JwkSet,
        request_data: &[u8],
        _allow_tofu: bool,
    ) -> Result<Vec<u8>> {
        // Start listening on the configured port
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))
            .map_err(|e| Error::network(format!("Failed to bind to port {}: {}", self.port, e)))?;
        
        // Set non-blocking to implement a timeout on accept
        listener.set_nonblocking(true)
            .map_err(|e| Error::network(format!("Failed to set non-blocking: {}", e)))?;
        
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(30);
        
        loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    // Set the stream back to blocking for normal I/O
                    stream.set_nonblocking(false)
                        .map_err(|e| Error::network(format!("Failed to set stream blocking: {}", e)))?;
                    
                    match handle_remote_request(stream, advertized_keys, server_key_id, request_data) {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            // Log error and continue to wait for another connection
                            eprintln!("Remote pin request failed: {}", e);
                            // Continue the loop to wait for another connection
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection yet, check if timed out
                    if start.elapsed() > timeout {
                        return Err(Error::network("Timeout waiting for connection".to_string()));
                    }
                    // Sleep for a short time to avoid busy-waiting
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    return Err(Error::network(format!("Failed to accept connection: {}", e)));
                }
            }
        }
    }
}

/// Handle a remote client connection.
fn handle_remote_request(
    stream: TcpStream,
    stored_advertized_keys: &JwkSet,
    server_key_id: &str,
    request_data: &[u8],
) -> Result<Vec<u8>> {
    // Set read timeout on the original stream (affects clones too)
    stream.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| Error::network(format!("Failed to set read timeout: {}", e)))?;

    // Clone the stream for reading and writing
    let mut reader_stream = stream.try_clone()
        .map_err(|e| Error::network(format!("Failed to clone stream for reading: {}", e)))?;
    let mut writer = stream.try_clone()
        .map_err(|e| Error::network(format!("Failed to clone stream for writing: {}", e)))?;

    // Create a BufReader for reading from the clone
    let mut reader = BufReader::new(&mut reader_stream);

    // Read client advertisement
    let mut client_adv_line = String::new();
    reader.read_line(&mut client_adv_line)
        .map_err(|e| Error::network(format!("Failed to read client advertisement: {}", e)))?;
    
    let client_adv = client_adv_line.trim();
    
    // Verify client advertisement
    verify_remote_keys(client_adv, stored_advertized_keys, server_key_id)?;
    
    // Send server key ID and request data using the writer
    let request_line = format!("{}\n", server_key_id);
    writer.write_all(request_line.as_bytes())
        .map_err(|e| Error::network(format!("Failed to write server key ID: {}", e)))?;
    
    writer.write_all(request_data)
        .map_err(|e| Error::network(format!("Failed to write request data: {}", e)))?;
    
    writer.write_all(b"\n")
        .map_err(|e| Error::network(format!("Failed to write newline: {}", e)))?;
    
    // Read response
    let mut response_line = String::new();
    reader.read_line(&mut response_line)
        .map_err(|e| Error::network(format!("Failed to read response: {}", e)))?;
    
    // The response should be base64 encoded
    let response_bytes = URL_SAFE_NO_PAD.decode(response_line.trim())
        .map_err(|e| Error::crypto(format!("Failed to decode response: {}", e)))?;
    
    Ok(response_bytes)
}

/// Verify that a client's advertisement is valid.
fn verify_remote_keys(
    client_adv: &str,
    stored_advertized_keys: &JwkSet,
    server_key_id: &str,
) -> Result<()> {
    // Extract payload from JWS without verification
    let payload = jose::extract_jws_payload(client_adv)
        .map_err(|e| Error::validation(format!("Failed to extract JWS payload: {}", e)))?;
    
    let client_jwk_set: JwkSet = serde_json::from_value(payload)
        .map_err(|e| Error::validation(format!("Failed to parse client JWK set: {}", e)))?;
    
    // Verify signatures using stored signing keys only (strict trust)
    let stored_signing_keys = filter_keys(stored_advertized_keys, "verify");
    if stored_signing_keys.keys.is_empty() {
        return Err(Error::validation("Stored advertisement has no signing keys".to_string()));
    }
    let mut verified = false;
    for key in &stored_signing_keys.keys {
        if jose::verify_jws(client_adv, key).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(Error::validation(
            "Client advertisement did not verify against trusted signing keys".to_string(),
        ));
    }
    
    // Check that client has the server's exchange key
    let client_derive_keys = filter_keys(&client_jwk_set, "deriveKey");
    if let Ok(Some(_)) = client_derive_keys.find_by_thumbprint(server_key_id) {
        Ok(())
    } else {
        Err(Error::validation(format!("Client does not have derive key with ID {}", server_key_id)))
    }
}

/// Filter JWKs by key operation.
fn filter_keys(jwk_set: &JwkSet, operation: &str) -> JwkSet {
    let mut filtered = JwkSet::new();
    
    for jwk in &jwk_set.keys {
        if jwk.has_op(operation) {
            filtered.add(jwk.clone());
        }
    }
    
    filtered
}

/// Check if two JWK sets have intersecting keys (by thumbprint).
#[cfg(test)]
fn keys_intersect(set1: &JwkSet, set2: &JwkSet) -> bool {
    use std::collections::HashMap;
    // Compute thumbprints for set1
    let mut thumbprints1 = HashMap::new();
    for jwk in &set1.keys {
        if let Ok(tp) = jwk.thumbprint("S256") {
            thumbprints1.insert(tp, jwk);
        }
    }
    
    // Check if any key in set2 has a matching thumbprint
    for jwk in &set2.keys {
        if let Ok(tp) = jwk.thumbprint("S256") {
            if thumbprints1.contains_key(&tp) {
                return true;
            }
        }
    }
    
    false
}

impl Default for RemotePin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::Jwk;
    use tempfile::TempDir;
    
    #[test]
    fn test_remote_pin_metadata() {
        let pin = RemotePin::new();
        let metadata = pin.metadata();
        
        assert_eq!(metadata.name, "remote");
        assert_eq!(metadata.version, "0.1.0");
        assert!(metadata.description.contains("Remote"));
    }
    
    #[test]
    fn test_parse_encrypt_config() {
        let config = json!({
            "adv": "/path/to/adv.json",
            "port": 8609,
            "thp": "abc123"
        });
        
        let result = RemotePin::parse_encrypt_config(&config);
        assert!(result.is_ok());
        
        let cfg = result.unwrap();
        assert_eq!(cfg.adv, "/path/to/adv.json");
        assert_eq!(cfg.port, 8609);
        assert_eq!(cfg.thp, Some("abc123".to_string()));
    }
    
    #[test]
    fn test_parse_encrypt_config_defaults() {
        let config = json!({
            "adv": "/path/to/adv.json"
        });
        
        let result = RemotePin::parse_encrypt_config(&config);
        assert!(result.is_ok());
        
        let cfg = result.unwrap();
        assert_eq!(cfg.adv, "/path/to/adv.json");
        assert_eq!(cfg.port, 8609); // default
        assert_eq!(cfg.thp, None);
    }
    
    #[test]
    fn test_parse_decrypt_config() {
        let config = json!({
            "adv": "eyJhIjogMX0=",
            "port": 8609
        });
        
        let result = RemotePin::parse_decrypt_config(&config);
        assert!(result.is_ok());
        
        let cfg = result.unwrap();
        assert_eq!(cfg.adv, "eyJhIjogMX0=");
        assert_eq!(cfg.port, 8609);
    }

    #[test]
    fn test_decode_advertisement_raw() {
        let adv = "not-base64";
        let decoded = RemotePin::decode_advertisement(adv);
        assert_eq!(decoded, adv);
    }

    #[test]
    fn test_decode_advertisement_base64() {
        let adv = URL_SAFE_NO_PAD.encode(r#"{"keys":[]}"#);
        let decoded = RemotePin::decode_advertisement(&adv);
        assert_eq!(decoded, r#"{"keys":[]}"#);
    }
    
    #[test]
    fn test_filter_keys() {
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
        
        let verify_keys = filter_keys(&jwk_set, "verify");
        assert_eq!(verify_keys.keys.len(), 1);
        
        let derive_keys = filter_keys(&jwk_set, "deriveKey");
        assert_eq!(derive_keys.keys.len(), 1);
    }
    
    #[test]
    fn test_keys_intersect() {
        let mut set1 = JwkSet::new();
        let mut set2 = JwkSet::new();
        
        // Add same key to both sets
        let jwk = Jwk::EC(crate::jwk::EcJwk {
            crv: "P-256".to_string(),
            x: "test".to_string(),
            y: "test".to_string(),
            d: None,
            alg: Some("ES256".to_string()),
            use_: Some("sig".to_string()),
            key_ops: Some(vec!["verify".to_string()]),
            kid: None,
        });
        
        set1.add(jwk.clone());
        set2.add(jwk);
        
        assert!(keys_intersect(&set1, &set2));
        
        // Add different key to set2
        let jwk2 = Jwk::EC(crate::jwk::EcJwk {
            crv: "P-256".to_string(),
            x: "different".to_string(),
            y: "different".to_string(),
            d: None,
            alg: Some("ES256".to_string()),
            use_: Some("sig".to_string()),
            key_ops: Some(vec!["verify".to_string()]),
            kid: None,
        });
        
        let mut set3 = JwkSet::new();
        set3.add(jwk2);
        
        // set1 and set3 don't intersect
        assert!(!keys_intersect(&set1, &set3));
    }

    #[test]
    fn test_verify_remote_keys_accepts_trusted_adv() {
        let tempdir = TempDir::new().unwrap();
        let store = crate::keys::KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();
        let payload = jose::extract_jws_payload(&adv).unwrap();
        let jwk_set: JwkSet = serde_json::from_value(payload).unwrap();

        let server_key_id = jwk_set
            .keys
            .iter()
            .find(|jwk| jwk.has_op("deriveKey"))
            .and_then(|jwk| jwk.thumbprint("S256").ok())
            .expect("exchange key thumbprint");

        verify_remote_keys(&adv, &jwk_set, &server_key_id).unwrap();
    }

    #[test]
    fn test_verify_remote_keys_rejects_untrusted_adv() {
        let tempdir = TempDir::new().unwrap();
        let store = crate::keys::KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();

        let tempdir_other = TempDir::new().unwrap();
        let other_store = crate::keys::KeyStore::load(tempdir_other.path()).unwrap();
        let other_adv = other_store.advertisement(None).unwrap();
        let payload = jose::extract_jws_payload(&other_adv).unwrap();
        let other_jwk_set: JwkSet = serde_json::from_value(payload).unwrap();

        let server_key_id = other_jwk_set
            .keys
            .iter()
            .find(|jwk| jwk.has_op("deriveKey"))
            .and_then(|jwk| jwk.thumbprint("S256").ok())
            .expect("exchange key thumbprint");

        let err = verify_remote_keys(&adv, &other_jwk_set, &server_key_id).unwrap_err();
        assert!(err.to_string().contains("did not verify"));
    }

    #[test]
    fn test_verify_remote_keys_requires_exchange_key() {
        let tempdir = TempDir::new().unwrap();
        let store = crate::keys::KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();
        let payload = jose::extract_jws_payload(&adv).unwrap();
        let jwk_set: JwkSet = serde_json::from_value(payload).unwrap();

        let err = verify_remote_keys(&adv, &jwk_set, "missing").unwrap_err();
        assert!(err.to_string().contains("derive key"));
    }
}
