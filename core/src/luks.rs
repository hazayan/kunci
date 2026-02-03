//! LUKS (Linux Unified Key Setup) integration for Clevis.
//!
//! This module provides functionality for binding Clevis pins to LUKS volumes,
//! allowing automatic unlocking of encrypted disks during boot.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::pin::PinRegistry;

/// Clevis UUID for LUKS tokens and LUKSMeta.
const CLEVIS_UUID: &str = "cb6e8904-81ff-40da-a84a-07ab9ab5715e";

/// LUKS version (1 or 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuksVersion {
    /// LUKS1 header format.
    Luks1,
    /// LUKS2 header format.
    Luks2,
}

/// LUKS slot information.
#[derive(Debug, Clone)]
pub struct LuksSlot {
    /// Slot number (0-7 for LUKS1, 0-31 for LUKS2).
    pub slot: u32,
    /// Whether the slot is active (contains a key).
    pub active: bool,
    /// Pin configuration if the slot is bound to a Clevis pin.
    pub pin_config: Option<serde_json::Value>,
}

/// LUKS volume information.
#[derive(Debug, Clone)]
pub struct LuksVolume {
    /// Path to the LUKS device (e.g., `/dev/sda1`).
    pub device: String,
    /// LUKS version.
    pub version: LuksVersion,
    /// UUID of the volume.
    pub uuid: String,
    /// Slot information.
    pub slots: Vec<LuksSlot>,
}

/// Runs a cryptsetup command and returns the output as a string.
fn run_cryptsetup(args: &[&str]) -> Result<String> {
    let output = Command::new("cryptsetup")
        .args(args)
        .output()
        .map_err(|e| Error::crypto(format!("Failed to execute cryptsetup: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::crypto(format!("cryptsetup failed: {}", stderr)));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| Error::crypto(format!("Invalid output from cryptsetup: {}", e)))
}

/// Runs a cryptsetup command with stdin input.
fn run_cryptsetup_with_input(args: &[&str], input: &[u8]) -> Result<String> {
    let mut child = Command::new("cryptsetup")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::crypto(format!("Failed to spawn cryptsetup: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(input)
            .map_err(|e| Error::crypto(format!("Failed to write to cryptsetup stdin: {}", e)))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| Error::crypto(format!("Failed to wait for cryptsetup: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::crypto(format!("cryptsetup failed: {}", stderr)));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| Error::crypto(format!("Invalid output from cryptsetup: {}", e)))
}

/// Parses LUKS version from the string (e.g., "LUKS1", "LUKS2", "1", or "2").
fn parse_luks_version(version_str: &str) -> Result<LuksVersion> {
    match version_str {
        "1" | "LUKS1" => Ok(LuksVersion::Luks1),
        "2" | "LUKS2" => Ok(LuksVersion::Luks2),
        _ => Err(Error::crypto(format!(
            "Unknown LUKS version: {}",
            version_str
        ))),
    }
}

/// Gets LUKS version of a device.
fn get_luks_version(device: &Path) -> Result<LuksVersion> {
    // Try LUKS2 first
    let output = run_cryptsetup(&["isLuks", "--type", "luks2", device.to_str().unwrap()]);
    if output.is_ok() {
        return Ok(LuksVersion::Luks2);
    }

    // Try LUKS1
    let output = run_cryptsetup(&["isLuks", "--type", "luks1", device.to_str().unwrap()]);
    if output.is_ok() {
        return Ok(LuksVersion::Luks1);
    }

    Err(Error::crypto(format!(
        "{} is not a LUKS device",
        device.display()
    )))
}

/// Gets the first free LUKS slot.
fn find_free_slot(device: &Path) -> Result<u32> {
    let version = get_luks_version(device)?;
    let max_slots = match version {
        LuksVersion::Luks1 => 8,
        LuksVersion::Luks2 => 32,
    };

    let used_slots = get_used_slots(device)?;
    for slot in 0..max_slots {
        if !used_slots.contains(&slot) {
            return Ok(slot);
        }
    }

    Err(Error::crypto("No free LUKS slots available".to_string()))
}

/// Gets list of used LUKS slots.
fn get_used_slots(device: &Path) -> Result<Vec<u32>> {
    let output = run_cryptsetup(&["luksDump", device.to_str().unwrap()])?;
    let mut slots = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Key Slot") && line.contains("ENABLED") {
            if let Some(slot_str) = line.split_whitespace().nth(2) {
                if let Ok(slot) = slot_str.parse::<u32>() {
                    slots.push(slot);
                }
            }
        }
    }

    Ok(slots)
}

/// Generates a random key for LUKS (40 bytes as in original Clevis).
fn generate_luks_key() -> Result<Vec<u8>> {
    use rand::RngCore;
    let mut key = vec![0u8; 40];
    rand::thread_rng().fill_bytes(&mut key);
    Ok(key)
}

/// Binds a Clevis pin to a LUKS volume.
///
/// # Arguments
///
/// * `device` - Path to the LUKS device.
/// * `slot` - Slot number to use (if None, an empty slot is chosen).
/// * `pin_name` - Name of the pin to bind (e.g., "tang", "sss").
/// * `pin_config` - Configuration for the pin.
/// * `key_file` - Optional key file for the existing LUKS passphrase.
///
/// # Returns
///
/// The slot number that was used.
pub fn bind_luks(
    device: &Path,
    slot: Option<u32>,
    pin_name: &str,
    pin_config: &Value,
    key_file: Option<&Path>,
) -> Result<u32> {
    let version = get_luks_version(device)?;
    let slot = slot.unwrap_or_else(|| find_free_slot(device).unwrap_or(0));

    // Generate a new LUKS key
    let new_key = generate_luks_key()?;

    // Create pin registry and get the pin
    let mut registry = PinRegistry::new();
    registry.register(Box::new(crate::pin::NullPin::new()));
    registry.register(Box::new(crate::pin::SssPin::new()));
    #[cfg(feature = "full")]
    registry.register(Box::new(crate::pin::TangPin::new()));

    let pin = registry
        .get(pin_name)
        .ok_or_else(|| Error::validation(format!("Pin '{}' not found", pin_name)))?;

    // Encrypt the new key with the pin
    let jwe_value = pin.encrypt(pin_config, &new_key)?;
    
    // Extract JWE compact string from the result
    let jwe_compact = jwe_value
        .get("jwe")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::crypto("Pin encryption did not return a JWE string".to_string()))?;

    // Add the new key to LUKS
    let slot_str = slot.to_string();
    let mut args = vec![
        "luksAddKey",
        "--batch-mode",
        "--key-slot",
        &slot_str,
        "--pbkdf",
        "pbkdf2",
        "--pbkdf-force-iterations",
        "1000",
        device.to_str().unwrap(),
    ];

    if let Some(key_file) = key_file {
        args.push("--key-file");
        args.push(key_file.to_str().unwrap());
        // Add the new key via stdin
        run_cryptsetup_with_input(&args, &new_key)?;
    } else {
        // We need to prompt for existing passphrase, but we can't interactively prompt.
        // For now, we'll assume the device is already unlocked or use a key file.
        return Err(Error::crypto(
            "Interactive passphrase entry not yet implemented".to_string(),
        ));
    }

    // Create token for LUKS2 or save to LUKSMeta for LUKS1
    match version {
        LuksVersion::Luks2 => {
            create_luks2_token(device, slot, jwe_compact)?;
        }
        LuksVersion::Luks1 => {
            save_luks1_metadata(device, slot, jwe_compact)?;
        }
    }

    Ok(slot)
}

/// Creates a LUKS2 token for a Clevis binding.
fn create_luks2_token(device: &Path, slot: u32, jwe_compact: &str) -> Result<()> {
    // Convert JWE compact to JSON format for token
    let jwe_json = convert_jwe_compact_to_json(jwe_compact)?;
    
    let token_json = format!(
        r#"{{
            "type": "clevis",
            "keyslots": ["{}"],
            "jwe": {}
        }}"#,
        slot, jwe_json
    );

    // Import the token
    let mut child = Command::new("cryptsetup")
        .args(&["token", "import", device.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::crypto(format!("Failed to spawn cryptsetup token import: {}", e)))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::crypto("Failed to get stdin for cryptsetup".to_string()))?;
    use std::io::Write;
    stdin
        .write_all(token_json.as_bytes())
        .map_err(|e| Error::crypto(format!("Failed to write token JSON: {}", e)))?;

    let output = child
        .wait_with_output()
        .map_err(|e| Error::crypto(format!("Failed to wait for cryptsetup: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::crypto(format!(
            "Failed to import LUKS2 token: {}",
            stderr
        )));
    }

    Ok(())
}

/// Saves LUKS1 metadata using luksmeta.
fn save_luks1_metadata(device: &Path, slot: u32, jwe_compact: &str) -> Result<()> {
    // Check if luksmeta is initialized
    let output = Command::new("luksmeta")
        .args(&["test", "-d", device.to_str().unwrap()])
        .output()
        .map_err(|e| Error::crypto(format!("Failed to check luksmeta: {}", e)))?;

    if !output.status.success() {
        // Initialize luksmeta
        Command::new("luksmeta")
            .args(&["init", "-d", device.to_str().unwrap()])
            .output()
            .map_err(|e| Error::crypto(format!("Failed to initialize luksmeta: {}", e)))?;
    }

    // Save the JWE to luksmeta
    let mut child = Command::new("luksmeta")
        .args(&[
            "save",
            "-d",
            device.to_str().unwrap(),
            "-s",
            &slot.to_string(),
            "-u",
            CLEVIS_UUID,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::crypto(format!("Failed to spawn luksmeta save: {}", e)))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::crypto("Failed to get stdin for luksmeta".to_string()))?;
    use std::io::Write;
    stdin
        .write_all(jwe_compact.as_bytes())
        .map_err(|e| Error::crypto(format!("Failed to write JWE to luksmeta: {}", e)))?;

    let output = child
        .wait_with_output()
        .map_err(|e| Error::crypto(format!("Failed to wait for luksmeta: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::crypto(format!(
            "Failed to save LUKS1 metadata: {}",
            stderr
        )));
    }

    Ok(())
}

/// Converts a JWE compact string to JSON format.
fn convert_jwe_compact_to_json(jwe_compact: &str) -> Result<String> {
    // Parse the compact JWE to extract parts
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

/// Unbinds a Clevis pin from a LUKS volume.
///
/// # Arguments
///
/// * `device` - Path to the LUKS device.
/// * `slot` - Slot number to unbind.
/// * `key_file` - Optional key file for the existing LUKS passphrase.
pub fn unbind_luks(_device: &Path, _slot: u32, _key_file: Option<&Path>) -> Result<()> {
    // TODO: Implement actual LUKS unbinding using cryptsetup.
    eprintln!("Warning: LUKS unbinding is not yet implemented");
    Ok(())
}

/// Lists Clevis bindings on a LUKS volume.
///
/// # Arguments
///
/// * `device` - Path to the LUKS device.
///
/// # Returns
///
/// Information about the LUKS volume and its slots.
pub fn list_luks(device: &Path) -> Result<LuksVolume> {
    let device_str = device.to_string_lossy();
    let output = run_cryptsetup(&["luksDump", &device_str])?;

    let mut version = LuksVersion::Luks2;
    let mut uuid = String::new();

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Version:") {
            let ver_str = line.split(':').nth(1).unwrap().trim();
            version = parse_luks_version(ver_str)?;
        } else if line.starts_with("UUID:") {
            uuid = line.split(':').nth(1).unwrap().trim().to_string();
        }
    }

    // TODO: parse slots and tokens to fill the slots vector.

    Ok(LuksVolume {
        device: device_str.to_string(),
        version,
        uuid,
        slots: vec![],
    })
}

/// Unlocks a LUKS volume using a Clevis pin.
///
/// # Arguments
///
/// * `device` - Path to the LUKS device.
/// * `name` - Name for the unlocked device (e.g., "myvolume").
/// * `pin_name` - Name of the pin to use for unlocking.
/// * `pin_config` - Configuration for the pin.
///
/// # Returns
///
/// The path to the unlocked device (e.g., `/dev/mapper/myvolume`).
pub fn unlock_luks(
    _device: &Path,
    name: &str,
    _pin_name: &str,
    _pin_config: &Value,
) -> Result<String> {
    // TODO: Implement actual LUKS unlocking using cryptsetup.
    // This is a placeholder that returns a dummy path.
    eprintln!("Warning: LUKS unlocking is not yet implemented");
    Ok(format!("/dev/mapper/{}", name))
}

/// Changes the pin configuration for an existing binding.
///
/// # Arguments
///
/// * `device` - Path to the LUKS device.
/// * `slot` - Slot number to edit.
/// * `pin_config` - New configuration for the pin.
/// * `key_file` - Optional key file for the existing LUKS passphrase.
pub fn edit_luks(
    _device: &Path,
    _slot: u32,
    _pin_config: &Value,
    _key_file: Option<&Path>,
) -> Result<()> {
    // TODO: Implement actual LUKS edit using cryptsetup.
    eprintln!("Warning: LUKS edit is not yet implemented");
    Ok(())
}

/// Regenerates the pin binding (e.g., after a Tang key rotation).
///
/// # Arguments
///
/// * `device` - Path to the LUKS device.
/// * `slot` - Slot number to regenerate.
/// * `key_file` - Optional key file for the existing LUKS passphrase.
pub fn regen_luks(_device: &Path, _slot: u32, _key_file: Option<&Path>) -> Result<()> {
    // TODO: Implement actual LUKS regeneration using cryptsetup.
    eprintln!("Warning: LUKS regeneration is not yet implemented");
    Ok(())
}

/// Reports the pin configuration for a slot.
///
/// # Arguments
///
/// * `device` - Path to the LUKS device.
/// * `slot` - Slot number to report.
///
/// # Returns
///
/// The pin configuration for the slot.
pub fn report_luks(_device: &Path, _slot: u32) -> Result<Value> {
    // TODO: Implement actual LUKS reporting using cryptsetup.
    eprintln!("Warning: LUKS reporting is not yet implemented");
    Ok(serde_json::json!({"pin": "placeholder"}))
}
