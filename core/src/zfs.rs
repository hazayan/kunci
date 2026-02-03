//! ZFS native encryption integration for Clevis.
//!
//! This module provides functionality for binding Clevis pins to ZFS encrypted datasets,
//! allowing automatic unlocking of encrypted ZFS datasets during boot.

use std::process::Command;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::pin::PinRegistry;

/// ZFS property name for storing the Clevis JWE.
const CLEVIS_PROPERTY: &str = "kunci:jwe";

/// ZFS dataset encryption key length (32 bytes for AES-256-GCM).
const ZFS_KEY_LEN: usize = 32;

/// ZFS dataset information.
#[derive(Debug, Clone)]
pub struct ZfsDataset {
    /// Dataset name (e.g., "pool/root").
    pub name: String,
    /// Whether the dataset is currently loaded (key is loaded).
    pub loaded: bool,
    /// Encryption algorithm in use.
    pub encryption: Option<String>,
    /// Clevis JWE if bound.
    pub clevis_jwe: Option<String>,
}

/// Binds a Clevis pin to a ZFS dataset.
///
/// # Arguments
///
/// * `dataset` - Name of the ZFS dataset (e.g., "pool/root").
/// * `pin_name` - Name of the pin to bind (e.g., "tang", "remote").
/// * `pin_config` - Configuration for the pin.
///
/// # Returns
///
/// The generated wrapping key (32 bytes) that was encrypted and stored.
pub fn bind_zfs(dataset: &str, pin_name: &str, pin_config: &Value) -> Result<Vec<u8>> {
    crate::klog!(
        module: "zfs",
        level: crate::log::LogLevel::Info,
        "bind";
        dataset = dataset,
        pin = pin_name
    );
    // Generate a random wrapping key for ZFS
    let wrapping_key = generate_wrapping_key()?;

    // Create pin registry and get the pin
    let mut registry = PinRegistry::new();
    registry.register(Box::new(crate::pin::NullPin::new()));
    registry.register(Box::new(crate::pin::SssPin::new()));
    #[cfg(feature = "full")]
    registry.register(Box::new(crate::pin::TangPin::new()));
    registry.register(Box::new(crate::remote::RemotePin::new()));
    registry.register(Box::new(crate::yubikey::YubikeyPin::new()));
    #[cfg(feature = "tpm2")]
    registry.register(Box::new(crate::tpm2::Tpm2Pin::new()));

    let pin = registry
        .get(pin_name)
        .ok_or_else(|| Error::validation(format!("Pin '{}' not found", pin_name)))?;

    // Encrypt the wrapping key with the pin
    let jwe_value = pin.encrypt(pin_config, &wrapping_key)?;
    
    // Extract JWE compact string from the result
    let jwe_compact = jwe_value
        .get("jwe")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::crypto("Pin encryption did not return a JWE string".to_string()))?;
    crate::klog!(
        module: "zfs",
        level: crate::log::LogLevel::Debug,
        "bind_jwe";
        jwe_len = jwe_compact.len()
    );

    // Update the dataset key to the wrapping key so unlock succeeds later.
    change_zfs_key(dataset, &wrapping_key)?;

    // Store the JWE as a ZFS property
    set_zfs_property(dataset, CLEVIS_PROPERTY, jwe_compact)?;

    Ok(wrapping_key)
}

/// Unlocks a ZFS dataset using a Clevis pin.
///
/// # Arguments
///
/// * `dataset` - Name of the ZFS dataset (e.g., "pool/root").
/// * `pin_name` - Name of the pin to use for unlocking (optional, will try to detect from JWE).
/// * `pin_config` - Configuration for the pin (optional, if pin_name is provided).
///
/// # Returns
///
/// The decrypted wrapping key (32 bytes) that was loaded into ZFS.
pub fn unlock_zfs(dataset: &str, pin_name: Option<&str>, pin_config: Option<&Value>) -> Result<Vec<u8>> {
    crate::klog!(
        module: "zfs",
        level: crate::log::LogLevel::Info,
        "unlock";
        dataset = dataset,
        pin_provided = pin_name.is_some(),
        config_provided = pin_config.is_some()
    );
    // Get the JWE from ZFS property
    let jwe_compact = get_zfs_property(dataset, CLEVIS_PROPERTY)?
        .ok_or_else(|| Error::crypto(format!("No Clevis binding found on dataset {}", dataset)))?;
    crate::klog!(
        module: "zfs",
        level: crate::log::LogLevel::Debug,
        "unlock_jwe";
        jwe_len = jwe_compact.len()
    );

    // Parse the JWE to extract the pin name if not provided
    let (actual_pin_name, actual_pin_config) = if let (Some(name), Some(config)) = (pin_name, pin_config) {
        (name.to_string(), config.clone())
    } else {
        // Extract from JWE protected header
        let parts: Vec<&str> = jwe_compact.split('.').collect();
        if parts.len() != 5 {
            return Err(Error::crypto("Invalid JWE compact format".to_string()));
        }
        let header_b64 = parts[0];
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64)
            .map_err(|e| Error::crypto(format!("Failed to decode JWE header: {}", e)))?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| Error::crypto(format!("Failed to parse JWE header: {}", e)))?;

        let clevis = header.get("clevis")
            .ok_or_else(|| Error::crypto("Missing clevis node in JWE header".to_string()))?;
        let pin_name = clevis.get("pin")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::crypto("Missing pin in clevis node".to_string()))?;

        // Create a minimal config with just the clevis node
        let config = serde_json::json!({
            "clevis": clevis
        });

        (pin_name.to_string(), config)
    };

    crate::klog!(
        module: "zfs",
        level: crate::log::LogLevel::Debug,
        "unlock_pin";
        pin = actual_pin_name.as_str()
    );

    // Create pin registry
    let mut registry = PinRegistry::new();
    registry.register(Box::new(crate::pin::NullPin::new()));
    registry.register(Box::new(crate::pin::SssPin::new()));
    #[cfg(feature = "full")]
    registry.register(Box::new(crate::pin::TangPin::new()));
    registry.register(Box::new(crate::remote::RemotePin::new()));
    registry.register(Box::new(crate::yubikey::YubikeyPin::new()));
    #[cfg(feature = "tpm2")]
    registry.register(Box::new(crate::tpm2::Tpm2Pin::new()));

    let pin = registry
        .get(&actual_pin_name)
        .ok_or_else(|| Error::validation(format!("Pin '{}' not found", actual_pin_name)))?;

    // Convert JWE compact to JSON for decryption
    let jwe_json = convert_jwe_compact_to_json(&jwe_compact)?;
    let jwe_value: Value = serde_json::from_str(&jwe_json)
        .map_err(|e| Error::crypto(format!("Failed to parse JWE JSON: {}", e)))?;

    // Decrypt using the pin
    crate::klog!(
        module: "zfs",
        level: crate::log::LogLevel::Info,
        "unlock_pin_start";
        pin = actual_pin_name.as_str()
    );
    let wrapping_key = pin.decrypt(&actual_pin_config, &jwe_value)?;
    crate::klog!(
        module: "zfs",
        level: crate::log::LogLevel::Info,
        "unlock_pin_ok";
        pin = actual_pin_name.as_str(),
        key_len = wrapping_key.len()
    );

    // Load the key into ZFS
    crate::klog!(
        module: "zfs",
        level: crate::log::LogLevel::Info,
        "unlock_load_key_start";
        dataset = dataset
    );
    load_zfs_key(dataset, &wrapping_key)?;
    crate::klog!(
        module: "zfs",
        level: crate::log::LogLevel::Info,
        "unlock_load_key_ok";
        dataset = dataset
    );

    Ok(wrapping_key)
}

/// Removes a Clevis binding from a ZFS dataset.
///
/// # Arguments
///
/// * `dataset` - Name of the ZFS dataset.
pub fn unbind_zfs(dataset: &str) -> Result<()> {
    // Remove the property
    clear_zfs_property(dataset, CLEVIS_PROPERTY)
}

/// Lists ZFS datasets with Clevis bindings.
///
/// # Returns
///
/// A vector of ZFS dataset information.
pub fn list_zfs() -> Result<Vec<ZfsDataset>> {
    let output = run_zfs_command(&["list", "-H", "-o", "name,encryption"])?;
    
    let mut datasets = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 2 {
            continue;
        }
        
        let name = parts[0].to_string();
        let encryption = if parts[1] == "-" {
            None
        } else {
            Some(parts[1].to_string())
        };
        
        // Check if the dataset is loaded (has key loaded)
        let loaded = is_dataset_loaded(&name)?;
        
        // Get Clevis JWE if present
        let clevis_jwe = get_zfs_property(&name, CLEVIS_PROPERTY).ok().flatten();
        
        datasets.push(ZfsDataset {
            name,
            loaded,
            encryption,
            clevis_jwe,
        });
    }
    
    Ok(datasets)
}

#[cfg(test)]
mod load_key_tests {
    use super::load_zfs_key_args;

    #[test]
    fn test_load_zfs_key_args_uses_prompt() {
        let args = load_zfs_key_args("pool/root");
        assert_eq!(args, vec!["load-key", "-L", "prompt", "pool/root"]);
    }
}

/// Generates a random wrapping key for ZFS encryption.
fn generate_wrapping_key() -> Result<Vec<u8>> {
    use rand_core::OsRng;
    use rand_core::RngCore;
    let mut key = vec![0u8; ZFS_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    Ok(key)
}

/// Runs a ZFS command and returns the output as a string.
fn run_zfs_command(args: &[&str]) -> Result<String> {
    let output = Command::new("zfs")
        .args(args)
        .output()
        .map_err(|e| Error::crypto(format!("Failed to execute zfs: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::crypto(format!("zfs failed: {}", stderr)));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| Error::crypto(format!("Invalid output from zfs: {}", e)))
}

/// Sets a ZFS property.
fn set_zfs_property(dataset: &str, property: &str, value: &str) -> Result<()> {
    run_zfs_command(&["set", &format!("{}={}", property, value), dataset])?;
    Ok(())
}

/// Gets a ZFS property.
fn get_zfs_property(dataset: &str, property: &str) -> Result<Option<String>> {
    let output = run_zfs_command(&["get", "-H", "-o", "value", property, dataset])?;
    let value = output.trim();
    if value.is_empty() || value == "-" {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

/// Clears a ZFS property.
fn clear_zfs_property(dataset: &str, property: &str) -> Result<()> {
    run_zfs_command(&["inherit", property, dataset])?;
    Ok(())
}

/// Checks if a dataset has its key loaded.
fn is_dataset_loaded(dataset: &str) -> Result<bool> {
    let output = run_zfs_command(&["get", "-H", "-o", "value", "keystatus", dataset])?;
    Ok(output.trim() == "available")
}

/// Loads a key into a ZFS dataset.
fn load_zfs_key_args(dataset: &str) -> Vec<String> {
    vec!["load-key", "-L", "prompt", dataset]
        .into_iter()
        .map(String::from)
        .collect()
}

fn change_zfs_key(dataset: &str, key: &[u8]) -> Result<()> {
    if !is_dataset_loaded(dataset)? {
        return Err(Error::crypto(format!(
            "Dataset key not loaded; cannot change key for {}",
            dataset
        )));
    }

    let keyformat = get_zfs_property(dataset, "keyformat")?
        .unwrap_or_else(|| "passphrase".to_string());
    eprintln!("KUNCI_CORE_ZFS_CHANGE_KEY_START {} {}", dataset, keyformat);

    if keyformat != "passphrase" && keyformat != "hex" {
        use std::io::Write;
        use std::fs::{self, File};
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_millis())
            .unwrap_or(0);
        path.push(format!("kunci-zfs-key-{}-{}.bin", std::process::id(), stamp));
        let mut file = File::create(&path)
            .map_err(|e| Error::crypto(format!("Failed to create temp key file: {}", e)))?;
        file.write_all(key)
            .map_err(|e| Error::crypto(format!("Failed to write raw key: {}", e)))?;
        drop(file);
        let keylocation = format!("keylocation=file://{}", path.display());
        let child = Command::new("zfs")
            .args([
                "change-key",
                "-o",
                &keylocation,
                "-o",
                &format!("keyformat={}", keyformat),
                dataset,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::crypto(format!("Failed to spawn zfs change-key: {}", e)))?;
        eprintln!("KUNCI_CORE_ZFS_CHANGE_KEY_SPAWNED {}", dataset);
        eprintln!("KUNCI_CORE_ZFS_CHANGE_KEY_WAIT_START {}", dataset);
        let output = child
            .wait_with_output()
            .map_err(|e| Error::crypto(format!("Failed to wait for zfs change-key: {}", e)))?;
        let _ = fs::remove_file(&path);
        eprintln!(
            "KUNCI_CORE_ZFS_CHANGE_KEY_WAIT_OK {} status={}",
            dataset,
            output.status
        );
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "KUNCI_CORE_ZFS_CHANGE_KEY_FAIL {} {}",
                dataset,
                stderr.trim()
            );
            return Err(Error::crypto(format!(
                "Failed to change key: {}",
                stderr.trim()
            )));
        }
        return Ok(());
    }

    let mut child = Command::new("zfs")
        .args([
            "change-key",
            "-o",
            "keylocation=prompt",
            "-o",
            &format!("keyformat={}", keyformat),
            dataset,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::crypto(format!("Failed to spawn zfs change-key: {}", e)))?;
    eprintln!("KUNCI_CORE_ZFS_CHANGE_KEY_SPAWNED {}", dataset);

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::crypto("Failed to get stdin for zfs change-key".to_string()))?;
    use std::io::Write;

    let mut material: Vec<u8> = Vec::new();
    match keyformat.as_str() {
        "passphrase" => {
            match std::str::from_utf8(key) {
                Ok(passphrase) => {
                    material.extend_from_slice(passphrase.as_bytes());
                }
                Err(_) => {
                    let hex_key = hex::encode(key);
                    material.extend_from_slice(hex_key.as_bytes());
                }
            }
        }
        "hex" => {
            let hex_key = hex::encode(key);
            material.extend_from_slice(hex_key.as_bytes());
        }
        _ => {}
    }

    stdin
        .write_all(&material)
        .map_err(|e| Error::crypto(format!("Failed to write new key to zfs: {}", e)))?;
    stdin
        .write_all(b"\n")
        .map_err(|e| Error::crypto(format!("Failed to write newline to zfs: {}", e)))?;
    stdin
        .write_all(&material)
        .map_err(|e| Error::crypto(format!("Failed to write new key verify to zfs: {}", e)))?;
    stdin
        .write_all(b"\n")
        .map_err(|e| Error::crypto(format!("Failed to write newline to zfs: {}", e)))?;

    stdin
        .flush()
        .map_err(|e| Error::crypto(format!("Failed to flush key to zfs: {}", e)))?;
    drop(stdin);
    eprintln!("KUNCI_CORE_ZFS_CHANGE_KEY_WAIT_START {}", dataset);
    let output = child
        .wait_with_output()
        .map_err(|e| Error::crypto(format!("Failed to wait for zfs change-key: {}", e)))?;
    eprintln!(
        "KUNCI_CORE_ZFS_CHANGE_KEY_WAIT_OK {} status={}",
        dataset,
        output.status
    );

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "KUNCI_CORE_ZFS_CHANGE_KEY_FAIL {} {}",
            dataset,
            stderr.trim()
        );
        return Err(Error::crypto(format!(
            "Failed to change key: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

fn load_zfs_key(dataset: &str, key: &[u8]) -> Result<()> {
    let args = load_zfs_key_args(dataset);
    let keyformat = get_zfs_property(dataset, "keyformat")?
        .unwrap_or_else(|| "passphrase".to_string());
    eprintln!(
        "KUNCI_CORE_ZFS_LOAD_KEY_CMD {} {}",
        dataset,
        args.join(" ")
    );
    eprintln!("KUNCI_CORE_ZFS_LOAD_KEY_FORMAT {} {}", dataset, keyformat);
    let mut child = Command::new("zfs")
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::crypto(format!("Failed to spawn zfs load-key: {}", e)))?;
    eprintln!("KUNCI_CORE_ZFS_LOAD_KEY_SPAWNED {}", dataset);

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::crypto("Failed to get stdin for zfs".to_string()))?;
    use std::io::Write;
    match keyformat.as_str() {
        "passphrase" => {
            match std::str::from_utf8(key) {
                Ok(passphrase) => {
                    stdin
                        .write_all(passphrase.as_bytes())
                        .map_err(|e| {
                            Error::crypto(format!("Failed to write passphrase to zfs: {}", e))
                        })?;
                }
                Err(_) => {
                    let hex_key = hex::encode(key);
                    stdin
                        .write_all(hex_key.as_bytes())
                        .map_err(|e| {
                            Error::crypto(format!("Failed to write hex passphrase to zfs: {}", e))
                        })?;
                }
            }
            stdin
                .write_all(b"\n")
                .map_err(|e| Error::crypto(format!("Failed to write newline to zfs: {}", e)))?;
        }
        "hex" => {
            let hex_key = hex::encode(key);
            stdin
                .write_all(hex_key.as_bytes())
                .map_err(|e| Error::crypto(format!("Failed to write hex key to zfs: {}", e)))?;
            stdin
                .write_all(b"\n")
                .map_err(|e| Error::crypto(format!("Failed to write newline to zfs: {}", e)))?;
        }
        _ => {
            stdin
                .write_all(key)
                .map_err(|e| Error::crypto(format!("Failed to write key to zfs: {}", e)))?;
        }
    }
    stdin
        .flush()
        .map_err(|e| Error::crypto(format!("Failed to flush key to zfs: {}", e)))?;
    drop(stdin);
    eprintln!("KUNCI_CORE_ZFS_LOAD_KEY_WAIT_START {}", dataset);
    let output = child
        .wait_with_output()
        .map_err(|e| Error::crypto(format!("Failed to wait for zfs: {}", e)))?;
    eprintln!(
        "KUNCI_CORE_ZFS_LOAD_KEY_WAIT_OK {} status={}",
        dataset,
        output.status
    );

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("KUNCI_CORE_ZFS_LOAD_KEY_FAIL {} {}", dataset, stderr.trim());
        return Err(Error::crypto(format!("Failed to load key: {}", stderr)));
    }

    Ok(())
}

/// Converts a JWE compact string to JSON format.
pub fn convert_jwe_compact_to_json(jwe_compact: &str) -> Result<String> {
    let parts: Vec<&str> = jwe_compact.split('.').collect();
    if parts.len() != 5 {
        return Err(Error::crypto("Invalid JWE compact format".to_string()));
    }

    let header_b64 = parts[0];
    let encrypted_key_b64 = parts[1];
    let iv_b64 = parts[2];
    let ciphertext_b64 = parts[3];
    let tag_b64 = parts[4];

    let jwe_json = format!(
        r#"{{
            "protected": "{}",
            "encrypted_key": "{}",
            "iv": "{}",
            "ciphertext": "{}",
            "tag": "{}"
        }}"#,
        header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64
    );

    Ok(jwe_json)
}

/// Converts a JWE JSON structure into compact serialization.
pub fn convert_jwe_json_to_compact(jwe_json: &Value) -> Result<String> {
    let protected = jwe_json
        .get("protected")
        .ok_or_else(|| Error::validation("Missing protected header".to_string()))?;
    let protected_b64 = if let Some(b64) = protected.as_str() {
        b64.to_string()
    } else {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(protected)?)
    };

    let encrypted_key = jwe_json
        .get("encrypted_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let iv = jwe_json
        .get("iv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::validation("Missing IV".to_string()))?;

    let ciphertext = jwe_json
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::validation("Missing ciphertext".to_string()))?;

    let tag = jwe_json
        .get("tag")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::validation("Missing tag".to_string()))?;

    Ok(format!(
        "{}.{}.{}.{}.{}",
        protected_b64, encrypted_key, iv, ciphertext, tag
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_wrapping_key() {
        let key = generate_wrapping_key().unwrap();
        assert_eq!(key.len(), ZFS_KEY_LEN);
    }

    #[test]
    fn test_convert_jwe_compact_to_json() {
        // This is a valid 5-part JWE compact string (example from JWE spec)
        let jwe_compact = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rWKEo4Lt0pdiNA4T4CgBA1yWpPSyHjVtKdUFPBcah4cHlUbGtH7ZckRi5N8L6K2p6MlU4evP_JnnLtGq1h6S1BvgkQ8cNgBz8ZcKjK0u7YQ.YcVAPgJ5Frc.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4.4qp1sKS0vTbWk6k8QbqwLw";
        let json = convert_jwe_compact_to_json(jwe_compact).unwrap();
        assert!(json.contains("\"protected\""));
        assert!(json.contains("\"encrypted_key\""));
        assert!(json.contains("\"iv\""));
        assert!(json.contains("\"ciphertext\""));
        assert!(json.contains("\"tag\""));
    }

    #[test]
    fn test_convert_jwe_json_to_compact() {
        let jwe_compact = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rWKEo4Lt0pdiNA4T4CgBA1yWpPSyHjVtKdUFPBcah4cHlUbGtH7ZckRi5N8L6K2p6MlU4evP_JnnLtGq1h6S1BvgkQ8cNgBz8ZcKjK0u7YQ.YcVAPgJ5Frc.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4.4qp1sKS0vTbWk6k8QbqwLw";
        let json_str = convert_jwe_compact_to_json(jwe_compact).unwrap();
        let json_val: Value = serde_json::from_str(&json_str).unwrap();
        let compact_roundtrip = convert_jwe_json_to_compact(&json_val).unwrap();
        assert_eq!(compact_roundtrip, jwe_compact);
    }
}
