//! JOSE (JSON Object Signing and Encryption) operations for Tang and Clevis.
//!
//! This module provides functionality for working with JOSE standards:
//! - JSON Web Signature (JWS) creation and verification
//! - JSON Web Encryption (JWE) compact serialization for direct encryption
//! - Advertisement creation (JWS-signed JWK Set)
//!
//! # Features
//!
//! - `full`: Enables all JOSE operations using RustCrypto crates.

use crate::error::{Error, Result};
use crate::jwk::Jwk;

#[cfg(feature = "full")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "full")]
use base64::Engine;
#[cfg(feature = "full")]
use p256::ecdsa::signature::{Signer, Verifier};

/// JOSE-related errors.
#[derive(Debug, thiserror::Error)]
pub enum JoseError {
    /// JWS signing error.
    #[error("JWS signing error: {0}")]
    JwsSigning(String),

    /// JWS verification error.
    #[error("JWS verification error: {0}")]
    JwsVerification(String),

    /// Invalid JOSE object.
    #[error("Invalid JOSE object: {0}")]
    InvalidObject(String),

    /// Unsupported algorithm.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// JWE error.
    #[error("JWE error: {0}")]
    Jwe(String),
}

impl From<JoseError> for Error {
    fn from(err: JoseError) -> Self {
        Error::Crypto(err.to_string())
    }
}

#[cfg(feature = "full")]
fn infer_alg(jwk: &Jwk) -> Result<String> {
    if let Some(alg) = jwk.alg() {
        return Ok(alg.to_string());
    }

    match jwk {
        Jwk::EC(ec_jwk) => match ec_jwk.crv.as_str() {
            "P-256" => Ok("ES256".to_string()),
            "P-384" => Ok("ES384".to_string()),
            "P-521" => Ok("ES512".to_string()),
            _ => Err(JoseError::UnsupportedAlgorithm(format!(
                "Unsupported curve: {}",
                ec_jwk.crv
            ))
            .into()),
        },
        _ => Err(JoseError::UnsupportedAlgorithm(
            "Unsupported key type for signing".to_string(),
        )
        .into()),
    }
}

#[cfg(feature = "full")]
fn decode_ec_private_key(jwk: &Jwk) -> Result<Vec<u8>> {
    let Jwk::EC(ec_jwk) = jwk else {
        return Err(JoseError::JwsSigning("Key must be EC".to_string()).into());
    };

    let d = ec_jwk.d.as_ref().ok_or_else(|| {
        JoseError::JwsSigning("Signing key must include private key".to_string())
    })?;

    URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|e| JoseError::JwsSigning(format!("Invalid private key: {}", e)).into())
}

#[cfg(feature = "full")]
fn decode_ec_public_key(jwk: &Jwk) -> Result<Vec<u8>> {
    let Jwk::EC(ec_jwk) = jwk else {
        return Err(JoseError::JwsVerification("Key must be EC".to_string()).into());
    };

    let x = URL_SAFE_NO_PAD
        .decode(&ec_jwk.x)
        .map_err(|e| JoseError::JwsVerification(format!("Invalid x: {}", e)))?;
    let y = URL_SAFE_NO_PAD
        .decode(&ec_jwk.y)
        .map_err(|e| JoseError::JwsVerification(format!("Invalid y: {}", e)))?;

    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    Ok(sec1)
}

#[cfg(feature = "full")]
fn sign_input(alg: &str, jwk: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    let d_bytes = decode_ec_private_key(jwk)?;

    match alg {
        "ES256" => {
            let key = p256::ecdsa::SigningKey::from_bytes(d_bytes.as_slice().into())
                .map_err(|e| JoseError::JwsSigning(format!("Invalid ES256 key: {}", e)))?;
            let sig: p256::ecdsa::Signature = key.sign(signing_input);
            Ok(sig.to_bytes().to_vec())
        }
        "ES384" => {
            let key = p384::ecdsa::SigningKey::from_bytes(d_bytes.as_slice().into())
                .map_err(|e| JoseError::JwsSigning(format!("Invalid ES384 key: {}", e)))?;
            let sig: p384::ecdsa::Signature = key.sign(signing_input);
            Ok(sig.to_bytes().to_vec())
        }
        "ES512" => {
            let key = p521::ecdsa::SigningKey::from_bytes(d_bytes.as_slice().into())
                .map_err(|e| JoseError::JwsSigning(format!("Invalid ES512 key: {}", e)))?;
            let sig: p521::ecdsa::Signature = key.sign(signing_input);
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(JoseError::UnsupportedAlgorithm(alg.to_string()).into()),
    }
}

#[cfg(feature = "full")]
fn verify_input(alg: &str, jwk: &Jwk, signing_input: &[u8], signature: &[u8]) -> Result<()> {
    let sec1 = decode_ec_public_key(jwk)?;

    match alg {
        "ES256" => {
            let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| JoseError::JwsVerification(format!("Invalid ES256 key: {}", e)))?;
            let sig = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|e| JoseError::JwsVerification(format!("Invalid ES256 signature: {}", e)))?;
            verifying_key
                .verify(signing_input, &sig)
                .map_err(|e| JoseError::JwsVerification(format!("Invalid ES256 signature: {}", e)).into())
        }
        "ES384" => {
            let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| JoseError::JwsVerification(format!("Invalid ES384 key: {}", e)))?;
            let sig = p384::ecdsa::Signature::from_slice(signature)
                .map_err(|e| JoseError::JwsVerification(format!("Invalid ES384 signature: {}", e)))?;
            verifying_key
                .verify(signing_input, &sig)
                .map_err(|e| JoseError::JwsVerification(format!("Invalid ES384 signature: {}", e)).into())
        }
        "ES512" => {
            let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| JoseError::JwsVerification(format!("Invalid ES512 key: {}", e)))?;
            let sig = p521::ecdsa::Signature::from_slice(signature)
                .map_err(|e| JoseError::JwsVerification(format!("Invalid ES512 signature: {}", e)))?;
            verifying_key
                .verify(signing_input, &sig)
                .map_err(|e| JoseError::JwsVerification(format!("Invalid ES512 signature: {}", e)).into())
        }
        _ => Err(JoseError::UnsupportedAlgorithm(alg.to_string()).into()),
    }
}

/// Creates a JWS signed by one or more signing keys.
///
/// This is used for Tang advertisements, where the payload is a JWK Set
/// and it is signed by all available signing keys.
///
/// # Arguments
///
/// * `payload` - The JSON payload to sign (must be a JWK Set for advertisements).
/// * `signing_keys` - List of signing keys to use for signatures.
/// * `content_type` - Optional content type for the JWS protected header.
///
/// # Returns
///
/// A JWS JSON serialization as a string.
#[cfg(feature = "full")]
pub fn create_jws(
    payload: &serde_json::Value,
    signing_keys: &[Jwk],
    content_type: Option<&str>,
) -> Result<String> {
    if signing_keys.is_empty() {
        return Err(JoseError::JwsSigning("No signing keys provided".to_string()).into());
    }
    crate::klog!(
        module: "jose",
        level: crate::log::LogLevel::Debug,
        "create_jws_start";
        signing_keys = signing_keys.len(),
        content_type = content_type.unwrap_or("")
    );

    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|e| JoseError::JwsSigning(format!("Failed to serialize payload: {}", e)))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_bytes);

    let mut signatures = Vec::new();

    for key in signing_keys {
        let alg = infer_alg(key)?;
        let mut protected_map = serde_json::Map::new();
        protected_map.insert("alg".to_string(), serde_json::Value::String(alg.clone()));
        if let Some(cty) = content_type {
            protected_map.insert("cty".to_string(), serde_json::Value::String(cty.to_string()));
        }
        if let Some(kid) = key.kid() {
            protected_map.insert("kid".to_string(), serde_json::Value::String(kid.to_string()));
        }

        let protected_bytes = serde_json::to_vec(&serde_json::Value::Object(protected_map))
            .map_err(|e| JoseError::JwsSigning(format!("Failed to serialize header: {}", e)))?;
        let protected_b64 = URL_SAFE_NO_PAD.encode(protected_bytes);

        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let signature = sign_input(&alg, key, signing_input.as_bytes())?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

        signatures.push(serde_json::json!({
            "protected": protected_b64,
            "signature": signature_b64,
        }));
    }

    let jws = serde_json::json!({
        "payload": payload_b64,
        "signatures": signatures,
    });

    let out = serde_json::to_string(&jws)
        .map_err(|e| JoseError::JwsSigning(format!("Failed to serialize JWS: {}", e)))?;
    crate::klog!(
        module: "jose",
        level: crate::log::LogLevel::Debug,
        "create_jws_ok";
        jws_len = out.len()
    );
    Ok(out)
}

/// Creates a Tang advertisement JWS.
///
/// The advertisement is a JWS-signed JWK Set containing all public keys
/// that can be used for signing or key exchange.
///
/// # Arguments
///
/// * `payload` - The JSON payload to sign (must be a JWK Set for advertisements).
/// * `signing_keys` - The signing keys to use for the JWS signature(s).
///
/// # Returns
///
/// A JWS JSON serialization as a string.
#[cfg(feature = "full")]
pub fn create_advertisement(
    payload: &serde_json::Value,
    signing_keys: &[Jwk],
) -> Result<String> {
    // Create JWS with content type "jwk-set+json"
    create_jws(payload, signing_keys, Some("jwk-set+json"))
}

/// Verifies a JWS using the provided verification key and returns the payload.
#[cfg(feature = "full")]
pub fn verify_jws(jws: &str, verification_key: &Jwk) -> Result<serde_json::Value> {
    use serde_json::Value as JsonValue;

    crate::klog!(
        module: "jose",
        level: crate::log::LogLevel::Debug,
        "verify_jws_start";
        jws_len = jws.len(),
        key_has_kid = verification_key.kid().is_some()
    );
    if let Ok(json) = serde_json::from_str::<JsonValue>(jws) {
        let payload_b64 = json
            .get("payload")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JoseError::InvalidObject("Missing payload field in JWS".to_string()))?;

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| JoseError::InvalidObject(format!("Failed to decode payload: {}", e)))?;

        let signatures = json
            .get("signatures")
            .and_then(|v| v.as_array())
            .ok_or_else(|| JoseError::InvalidObject("Missing signatures".to_string()))?;

        let expected_alg = infer_alg(verification_key)?;

        for sig in signatures {
            let protected_b64 = sig
                .get("protected")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JoseError::InvalidObject("Missing protected header".to_string()))?;
            let signature_b64 = sig
                .get("signature")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JoseError::InvalidObject("Missing signature".to_string()))?;

            let protected_bytes = URL_SAFE_NO_PAD
                .decode(protected_b64)
                .map_err(|e| JoseError::InvalidObject(format!("Invalid protected header: {}", e)))?;
            let protected_json: JsonValue = serde_json::from_slice(&protected_bytes)
                .map_err(|e| JoseError::InvalidObject(format!("Invalid protected header: {}", e)))?;
            let alg = protected_json
                .get("alg")
                .and_then(|v| v.as_str())
                .unwrap_or(&expected_alg);
            if alg != expected_alg {
                continue;
            }

            let signature = URL_SAFE_NO_PAD
                .decode(signature_b64)
                .map_err(|e| JoseError::InvalidObject(format!("Invalid signature: {}", e)))?;

            let signing_input = format!("{}.{}", protected_b64, payload_b64);
            if verify_input(alg, verification_key, signing_input.as_bytes(), &signature).is_ok() {
                let payload = serde_json::from_slice(&payload_bytes)
                    .map_err(|e| JoseError::JwsVerification(format!("Invalid payload: {}", e)))?;
                crate::klog!(
                    module: "jose",
                    level: crate::log::LogLevel::Debug,
                    "verify_jws_ok"
                );
                return Ok(payload);
            }
        }

        Err(JoseError::JwsVerification("No valid signature found".to_string()).into())
    } else {
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err(JoseError::InvalidObject(
                "Invalid JWS: not compact serialization and not JSON".to_string(),
            )
            .into());
        }

        let protected_b64 = parts[0];
        let payload_b64 = parts[1];
        let signature_b64 = parts[2];

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| JoseError::InvalidObject(format!("Failed to decode payload: {}", e)))?;

        let protected_bytes = URL_SAFE_NO_PAD
            .decode(protected_b64)
            .map_err(|e| JoseError::InvalidObject(format!("Invalid protected header: {}", e)))?;
        let protected_json: JsonValue = serde_json::from_slice(&protected_bytes)
            .map_err(|e| JoseError::InvalidObject(format!("Invalid protected header: {}", e)))?;
        let alg = protected_json
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("ES256");

        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|e| JoseError::InvalidObject(format!("Invalid signature: {}", e)))?;

        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        verify_input(alg, verification_key, signing_input.as_bytes(), &signature)?;

        let payload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| JoseError::JwsVerification(format!("Invalid payload: {}", e)))?;
        crate::klog!(
            module: "jose",
            level: crate::log::LogLevel::Debug,
            "verify_jws_ok"
        );
        Ok(payload)
    }
}

/// Extracts the payload from a JWS without verification.
#[cfg(feature = "full")]
pub fn extract_jws_payload(jws: &str) -> Result<serde_json::Value> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::Value as JsonValue;

    crate::klog!(
        module: "jose",
        level: crate::log::LogLevel::Debug,
        "extract_jws_payload";
        jws_len = jws.len()
    );

    // Try to parse as JSON (general or flattened serialization)
    if let Ok(json) = serde_json::from_str::<JsonValue>(jws) {
        match json {
            JsonValue::Object(map) => {
                if let Some(payload_val) = map.get("payload") {
                    let payload_b64 = payload_val
                        .as_str()
                        .ok_or_else(|| {
                            JoseError::InvalidObject("Payload must be a string".to_string())
                        })?;

                    let payload_bytes = URL_SAFE_NO_PAD
                        .decode(payload_b64)
                        .map_err(|e| {
                            JoseError::InvalidObject(format!("Failed to decode base64 payload: {}", e))
                        })?;

                    serde_json::from_slice(&payload_bytes)
                        .map_err(|e| JoseError::InvalidObject(format!("Failed to parse payload: {}", e)))
                        .map_err(Into::into)
                } else if map.contains_key("keys") {
                    Ok(JsonValue::Object(map))
                } else {
                    Err(JoseError::InvalidObject(
                        "Missing payload field in JWS".to_string(),
                    )
                    .into())
                }
            }
            JsonValue::String(inner) => extract_jws_payload(&inner),
            _ => Err(JoseError::InvalidObject(
                "Invalid JWS: not compact serialization and not JSON".to_string(),
            )
            .into()),
        }
    } else {
        // Try compact serialization
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() == 3 {
            let payload_b64 = parts[1];
            let payload_bytes = URL_SAFE_NO_PAD
                .decode(payload_b64)
                .map_err(|e| JoseError::InvalidObject(format!("Failed to decode base64 payload: {}", e)))?;

            serde_json::from_slice(&payload_bytes)
                .map_err(|e| JoseError::InvalidObject(format!("Failed to parse payload: {}", e)))
                .map_err(Into::into)
        } else {
            Err(JoseError::InvalidObject(
                "Invalid JWS: not compact serialization and not JSON".to_string(),
            )
            .into())
        }
    }
}

/// Encrypts data using direct JWE (alg=dir, enc=A256GCM).
#[cfg(feature = "full")]
pub fn jwe_encrypt_dir_a256gcm(
    plaintext: &[u8],
    key: &[u8],
    protected_header: &serde_json::Value,
) -> Result<String> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use rand_core::RngCore;

    crate::klog!(
        module: "jose",
        level: crate::log::LogLevel::Debug,
        "jwe_encrypt";
        plaintext_len = plaintext.len(),
        key_len = key.len()
    );

    if key.len() != 32 {
        return Err(JoseError::Jwe("A256GCM key must be 32 bytes".to_string()).into());
    }

    let protected_bytes = serde_json::to_vec(protected_header)
        .map_err(|e| JoseError::Jwe(format!("Failed to serialize JWE header: {}", e)))?;
    let protected_b64 = URL_SAFE_NO_PAD.encode(&protected_bytes);

    let mut iv = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut iv);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&iv);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| JoseError::Jwe(format!("Failed to create cipher: {}", e)))?;

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: protected_b64.as_bytes(),
            },
        )
        .map_err(|e| JoseError::Jwe(format!("JWE encryption failed: {}", e)))?;

    if ciphertext.len() < 16 {
        return Err(JoseError::Jwe("Ciphertext too short".to_string()).into());
    }

    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);

    let iv_b64 = URL_SAFE_NO_PAD.encode(iv);
    let ct_b64 = URL_SAFE_NO_PAD.encode(ct);
    let tag_b64 = URL_SAFE_NO_PAD.encode(tag);

    Ok(format!("{}..{}.{}.{}", protected_b64, iv_b64, ct_b64, tag_b64))
}

/// Decrypts data using direct JWE (alg=dir, enc=A256GCM).
#[cfg(feature = "full")]
pub fn jwe_decrypt_dir_a256gcm(compact: &str, key: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    crate::klog!(
        module: "jose",
        level: crate::log::LogLevel::Debug,
        "jwe_decrypt";
        jwe_len = compact.len(),
        key_len = key.len()
    );

    if key.len() != 32 {
        return Err(JoseError::Jwe("A256GCM key must be 32 bytes".to_string()).into());
    }

    let parts: Vec<&str> = compact.split('.').collect();
    if parts.len() != 5 {
        return Err(JoseError::Jwe("Invalid JWE compact format".to_string()).into());
    }

    let protected_b64 = parts[0];
    let iv = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| JoseError::Jwe(format!("Invalid IV: {}", e)))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|e| JoseError::Jwe(format!("Invalid ciphertext: {}", e)))?;
    let tag = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|e| JoseError::Jwe(format!("Invalid tag: {}", e)))?;

    if iv.len() != 12 {
        return Err(JoseError::Jwe("Invalid IV length".to_string()).into());
    }

    let mut ct_and_tag = Vec::with_capacity(ciphertext.len() + tag.len());
    ct_and_tag.extend_from_slice(&ciphertext);
    ct_and_tag.extend_from_slice(&tag);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| JoseError::Jwe(format!("Failed to create cipher: {}", e)))?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&iv);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct_and_tag,
                aad: protected_b64.as_bytes(),
            },
        )
        .map_err(|e| JoseError::Jwe(format!("JWE decryption failed: {}", e)).into())
}

/// Placeholder implementations when full feature is disabled.
#[cfg(not(feature = "full"))]
pub fn create_jws(
    _payload: &serde_json::Value,
    _signing_keys: &[Jwk],
    _content_type: Option<&str>,
) -> Result<String> {
    Err(Error::crypto("JOSE features not enabled"))
}

#[cfg(not(feature = "full"))]
pub fn create_advertisement(
    _payload_keys: &serde_json::Value,
    _signing_keys: &[Jwk],
) -> Result<String> {
    Err(Error::crypto("JOSE features not enabled"))
}

#[cfg(not(feature = "full"))]
pub fn verify_jws(_jws: &str, _verification_key: &Jwk) -> Result<serde_json::Value> {
    Err(Error::crypto("JOSE features not enabled"))
}

#[cfg(not(feature = "full"))]
pub fn extract_jws_payload(_jws: &str) -> Result<serde_json::Value> {
    Err(Error::crypto("JOSE features not enabled"))
}

#[cfg(not(feature = "full"))]
pub fn jwe_encrypt_dir_a256gcm(
    _plaintext: &[u8],
    _key: &[u8],
    _protected_header: &serde_json::Value,
) -> Result<String> {
    Err(Error::crypto("JOSE features not enabled"))
}

#[cfg(not(feature = "full"))]
pub fn jwe_decrypt_dir_a256gcm(_compact: &str, _key: &[u8]) -> Result<Vec<u8>> {
    Err(Error::crypto("JOSE features not enabled"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_placeholder() {
        // Test that placeholder functions compile
        let _ = create_jws(&serde_json::json!({}), &[], None);
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_create_and_extract_jws() {
        let key = crate::crypto::generate_key("ES256").unwrap();
        let payload = json!({ "keys": [] });

        let jws = create_jws(&payload, &[key.clone()], Some("jwk-set+json")).unwrap();
        let extracted = extract_jws_payload(&jws).unwrap();
        assert_eq!(extracted, payload);

        let verified = verify_jws(&jws, &key.to_public()).unwrap();
        assert_eq!(verified, payload);
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_extract_jws_payload_raw_jwk_set() {
        let payload = json!({ "keys": [] });
        let payload_str = serde_json::to_string(&payload).unwrap();
        let extracted = extract_jws_payload(&payload_str).unwrap();
        assert_eq!(extracted, payload);
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_extract_jws_payload_json_string() {
        let payload = json!({ "keys": [{"kty": "EC"}] });
        let inner = serde_json::to_string(&payload).unwrap();
        let wrapped = serde_json::to_string(&inner).unwrap();
        let extracted = extract_jws_payload(&wrapped).unwrap();
        assert_eq!(extracted, payload);
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_jwe_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let header = json!({ "alg": "dir", "enc": "A256GCM" });
        let plaintext = b"hello";

        let compact = jwe_encrypt_dir_a256gcm(plaintext, &key, &header).unwrap();
        let decrypted = jwe_decrypt_dir_a256gcm(&compact, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
