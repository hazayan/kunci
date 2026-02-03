//! Shared Tang protocol functions used by multiple pins.
//!
//! This module provides the core Tang encryption and recovery logic that
//! is shared between the Tang pin and the Remote pin.

use serde_json::Value;

use crate::error::{Error, Result};
use crate::jose;
use crate::jwk::{Jwk, JwkSet};
use crate::tang::{RecoveryRequest, TangPolicy};
use crate::tang::util::{enforce_advertisement_trust, validate_advertisement, verify_advertisement_signatures};

fn parse_and_verify_advertisement(
    advertisement: &str,
    thumbprint: Option<&str>,
    allow_tofu: bool,
) -> Result<JwkSet> {
    let payload = jose::extract_jws_payload(advertisement)?;
    let jwk_set: JwkSet = serde_json::from_value(payload)
        .map_err(|e| Error::validation(format!("Failed to deserialize JWK set: {}", e)))?;
    validate_advertisement(&jwk_set)?;
    verify_advertisement_signatures(advertisement, &jwk_set)?;
    enforce_advertisement_trust(advertisement, &jwk_set, thumbprint, allow_tofu)?;
    Ok(jwk_set)
}

/// Encrypts data using the Tang protocol.
///
/// This function implements the common encryption logic used by both
/// Tang and Remote pins. It performs the following steps:
///
/// 1. Parses and validates the advertisement (JWS-signed JWK Set)
/// 2. Selects an exchange key (by thumbprint if provided, or the first ECMR key)
/// 3. Generates a client ephemeral key pair
/// 4. Computes the shared secret using ECDH
/// 5. Encrypts the plaintext using the shared secret
/// 6. Includes the clevis node in the JWE header
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt.
/// * `advertisement` - The advertisement (JWS compact serialization).
/// * `thumbprint` - Optional thumbprint of a specific exchange key to use.
/// * `clevis_node` - Additional data to include in the JWE's "clevis" header.
///
/// # Returns
///
/// The encrypted data as a JWE compact serialization.
#[cfg(feature = "full")]
pub fn encrypt_with_tang_protocol(
    plaintext: &[u8],
    advertisement: &str,
    thumbprint: Option<&str>,
    clevis_node: Value,
    allow_tofu: bool,
) -> Result<String> {
    use crate::jose::jwe_encrypt_dir_a256gcm;

    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "encrypt_start";
        plaintext_len = plaintext.len(),
        adv_len = advertisement.len(),
        thp_present = thumbprint.is_some()
    );

    // Parse advertisement and extract JWK set
    let jwk_set = parse_and_verify_advertisement(advertisement, thumbprint, allow_tofu)?;
    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "encrypt_adv_keys";
        jwk_count = jwk_set.keys.len()
    );

    // Select exchange key
    let exchange_key = jwk_set
        .keys
        .iter()
        .find(|jwk| jwk.has_op("deriveKey") && jwk.alg() == Some("ECMR"))
        .ok_or_else(|| Error::validation("No ECMR exchange key found in advertisement".to_string()))?;
    if let Ok(kid) = exchange_key.thumbprint("S256") {
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "encrypt_selected_key";
            kid = kid
        );
    }

    // Generate client key pair
    let client_key = crate::crypto::generate_key("ECMR")
        .map_err(|e| Error::crypto(format!("Failed to generate client key: {}", e)))?;

    // Compute shared secret
    let shared_secret = crate::crypto::compute_shared_secret(exchange_key, &client_key)
        .map_err(|e| Error::crypto(format!("Failed to compute shared secret: {}", e)))?;

    let kid = exchange_key
        .thumbprint("S256")
        .map_err(|e| Error::crypto(format!("Failed to compute thumbprint: {}", e)))?;

    let client_pub = client_key.to_public();
    let client_pub_json = serde_json::to_value(&client_pub)
        .map_err(|e| Error::crypto(format!("Failed to serialize client key: {}", e)))?;

    let header = serde_json::json!({
        "alg": "ECDH-ES",
        "enc": "A256GCM",
        "kid": kid,
        "epk": client_pub_json,
        "clevis": clevis_node,
    });

    let derived_key = derive_key_from_shared_secret(&shared_secret, &header)?;
    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "encrypt_derived_key";
        derived_key_len = derived_key.len()
    );

    jwe_encrypt_dir_a256gcm(plaintext, &derived_key, &header)
        .map_err(|e| Error::crypto(format!("JWE encryption failed: {}", e)))
}

#[cfg(not(feature = "full"))]
pub fn encrypt_with_tang_protocol(
    _plaintext: &[u8],
    _advertisement: &str,
    _thumbprint: Option<&str>,
    _clevis_node: Value,
    _allow_tofu: bool,
) -> Result<String> {
    Err(Error::crypto("Cryptographic features not enabled"))
}

/// Callback function for key recovery exchange.
///
/// This trait is implemented by pins that need to perform custom exchange
/// during key recovery (e.g., Remote pin which uses network communication).
pub trait ExchangeCallback: Send + Sync {
    /// Performs the exchange with the server.
    ///
    /// # Arguments
    ///
    /// * `server_key_id` - The thumbprint of the server's exchange key.
    /// * `advertized_keys` - The JWK Set from the server's advertisement.
    /// * `request_data` - The recovery request data (serialized RecoveryRequest).
    ///
    /// # Returns
    ///
    /// The recovery response data (serialized RecoveryResponse).
    fn exchange(
        &self,
        server_key_id: &str,
        advertized_keys: &JwkSet,
        request_data: &[u8],
        allow_tofu: bool,
    ) -> Result<Vec<u8>>;
}

/// Recovers a key using the Tang protocol.
///
/// This function implements the common key recovery logic used by both
/// Tang and Remote pins. It performs the following steps:
///
/// 1. Parses the JWE message to extract the server key ID and client public key
/// 2. Parses the advertisement (provided by the pin)
/// 3. Uses the exchange callback to perform the recovery exchange
/// 4. Computes the shared secret from the recovery response
///
/// # Arguments
///
/// * `jwe_message` - The JWE message (compact serialization).
/// * `advertisement` - The advertisement (JSON string).
/// * `exchange_callback` - Callback to perform the exchange with the server.
///
/// # Returns
///
/// The recovered key (shared secret).
#[cfg(feature = "full")]
pub fn recover_key_with_tang_protocol(
    jwe_message: &str,
    advertisement: &str,
    thumbprint: Option<&str>,
    exchange_callback: &dyn ExchangeCallback,
    allow_tofu: bool,
) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::{PublicKey, EncodedPoint, SecretKey};
    use std::time::Instant;

    let start = Instant::now();
    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "recover_start";
        jwe_len = jwe_message.len(),
        adv_len = advertisement.len()
    );

    // Parse the JWE compact string to get the header
    let parts: Vec<&str> = jwe_message.split('.').collect();
    if parts.len() != 5 {
        return Err(Error::validation("Invalid JWE compact format".to_string()));
    }
    let header_b64 = parts[0];
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64)
        .map_err(|e| Error::crypto(format!("Failed to decode JWE header: {}", e)))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| Error::crypto(format!("Failed to parse JWE header: {}", e)))?;

    // Extract server key ID (thumbprint) and client public key (epk)
    let server_key_id = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::validation("Missing key ID (thumbprint) in JWE header".to_string()))?;
    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "recover_kid";
        kid = server_key_id
    );

    // Get the ephemeral public key (epk) from the JWE header
    let epk_json = header
        .get("epk")
        .ok_or_else(|| Error::validation("Missing ephemeral public key (epk) in JWE header".to_string()))?;
    let epk: Jwk = serde_json::from_value(epk_json.clone())
        .map_err(|e| Error::crypto(format!("Failed to parse epk from header: {}", e)))?;

    // Parse advertisement and extract JWK set
    let jwk_set = parse_and_verify_advertisement(advertisement, thumbprint, allow_tofu)?;
    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "recover_adv_keys";
        jwk_count = jwk_set.keys.len()
    );

    // Find the server key by thumbprint
    let server_key = jwk_set.keys.iter()
        .find(|jwk| jwk.has_op("deriveKey") && jwk.alg() == Some("ECMR") && 
               jwk.thumbprint("S256").map(|t| t == server_key_id).unwrap_or(false))
        .ok_or_else(|| Error::validation(format!("No exchange key found with thumbprint {}", server_key_id)))?;
    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "recover_server_key";
        found = true
    );

    // Generate ephemeral key pair for blinding
    let ephemeral_secret = SecretKey::random(&mut rand_core::OsRng);
    let ephemeral_public = ephemeral_secret.public_key();

    // Convert epk (client public key) to PublicKey
    let Jwk::EC(epk_ec) = epk else {
        return Err(Error::validation("Ephemeral public key must be an EC key".to_string()));
    };
    if epk_ec.crv != "P-256" {
        return Err(Error::validation("Only P-256 curve is supported for ECMR".to_string()));
    }
    
    let epk_x = URL_SAFE_NO_PAD.decode(&epk_ec.x)
        .map_err(|e| Error::crypto(format!("Failed to decode epk x: {}", e)))?;
    let epk_y = URL_SAFE_NO_PAD.decode(&epk_ec.y)
        .map_err(|e| Error::crypto(format!("Failed to decode epk y: {}", e)))?;
    
    // Convert Vec<u8> to [u8; 32]
    let epk_x_array: [u8; 32] = epk_x.try_into().map_err(|_| Error::crypto("Invalid epk x coordinate length".to_string()))?;
    let epk_y_array: [u8; 32] = epk_y.try_into().map_err(|_| Error::crypto("Invalid epk y coordinate length".to_string()))?;
    // Build uncompressed point (0x04 || x || y)
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&epk_x_array);
    uncompressed.extend_from_slice(&epk_y_array);
    let epk_point = EncodedPoint::from_bytes(&uncompressed)
        .map_err(|e| Error::crypto(format!("Failed to create encoded point: {}", e)))?;
    let client_public = PublicKey::from_sec1_bytes(epk_point.as_bytes())
        .map_err(|e| Error::crypto(format!("Failed to parse client public key: {}", e)))?;

    // Compute xfrKey = client_public + ephemeral_public (point addition)
    let client_point = client_public.to_projective();
    let ephemeral_point = ephemeral_public.to_projective();
    let xfr_point = client_point + ephemeral_point;

    // Convert xfr_point to JWK for request
    let xfr_affine = xfr_point.to_affine();
    let xfr_encoded = EncodedPoint::from(xfr_affine);
    let (xfr_x, xfr_y) = match xfr_encoded.coordinates() {
        p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (x, y),
        _ => return Err(Error::crypto("Unexpected compressed point".to_string())),
    };

    let xfr_jwk = Jwk::EC(crate::jwk::EcJwk {
        crv: "P-256".to_string(),
        x: URL_SAFE_NO_PAD.encode(xfr_x),
        y: URL_SAFE_NO_PAD.encode(xfr_y),
        d: None,
        alg: Some("ECMR".to_string()),
        use_: Some("enc".to_string()),
        key_ops: Some(vec!["deriveKey".to_string()]),
        kid: None,
    });

    // Create recovery request from xfr_jwk
    let request = RecoveryRequest { jwk: xfr_jwk };
    let request_json = serde_json::to_value(&request)
        .map_err(|e| Error::crypto(format!("Failed to serialize recovery request: {}", e)))?;
    let request_bytes = serde_json::to_vec(&request_json)
        .map_err(|e| Error::crypto(format!("Failed to serialize request to bytes: {}", e)))?;

    // Use the exchange callback to get the recovery response
    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "recover_exchange_start";
        request_len = request_bytes.len()
    );
    let response_bytes =
        exchange_callback.exchange(server_key_id, &jwk_set, &request_bytes, allow_tofu)?;
    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "recover_response";
        response_len = response_bytes.len(),
        elapsed_ms = start.elapsed().as_millis()
    );
    let response_jwk: Jwk = serde_json::from_slice(&response_bytes)
        .map_err(|e| Error::crypto(format!("Failed to parse recovery response: {}", e)))?;

    // Convert ephemeral secret to JWK for client_mccallum_relyea_exchange
    let ephemeral_jwk = {
        let ephemeral_secret_bytes = ephemeral_secret.to_bytes(); // FieldBytes
        let ephemeral_public = ephemeral_secret.public_key();
        let ephemeral_encoded = EncodedPoint::from(ephemeral_public);
        let (ephemeral_x, ephemeral_y) = match ephemeral_encoded.coordinates() {
            p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (x, y),
            _ => return Err(Error::crypto("Unexpected compressed point".to_string())),
        };

        Jwk::EC(crate::jwk::EcJwk {
            crv: "P-256".to_string(),
            x: URL_SAFE_NO_PAD.encode(ephemeral_x),
            y: URL_SAFE_NO_PAD.encode(ephemeral_y),
            d: Some(URL_SAFE_NO_PAD.encode(ephemeral_secret_bytes)),
            alg: Some("ECMR".to_string()),
            use_: Some("enc".to_string()),
            key_ops: Some(vec!["deriveKey".to_string()]),
            kid: None,
        })
    };

    // Use client_mccallum_relyea_exchange to compute shared secret
    let shared_secret_x = crate::crypto::client_mccallum_relyea_exchange(
        server_key,
        &ephemeral_jwk,
        &response_jwk,
    ).map_err(|e| Error::crypto(format!("Failed to compute shared secret: {}", e)))?;

    let derived_key = derive_key_from_shared_secret(&shared_secret_x, &header)?;
    crate::klog!(
        module: "tang",
        level: crate::log::LogLevel::Debug,
        "recover_derived_key";
        derived_key_len = derived_key.len()
    );
    Ok(derived_key)
}

#[cfg(not(feature = "full"))]
pub fn recover_key_with_tang_protocol(
    _jwe_message: &str,
    _advertisement: &str,
    _thumbprint: Option<&str>,
    _exchange_callback: &dyn ExchangeCallback,
    _allow_tofu: bool,
) -> Result<Vec<u8>> {
    Err(Error::crypto("Cryptographic features not enabled"))
}

/// Simple exchange callback for direct Tang server communication.
///
/// This implementation performs the recovery by making an HTTP POST request
/// to the Tang server's recovery endpoint.
#[derive(Debug)]
pub struct HttpExchangeCallback {
    /// Base URL of the Tang server.
    server_url: String,
}

impl HttpExchangeCallback {
    /// Creates a new HTTP exchange callback.
    pub fn new(server_url: impl Into<String>) -> Self {
        let server_url = server_url.into();
        Self { server_url }
    }

    /// Normalize URL by adding "http://" scheme if missing.
    fn normalize_url(&self, url: &str) -> String {
        if !url.contains("://") {
            format!("http://{}", url)
        } else {
            url.to_string()
        }
    }

    /// Fetch advertisement from the Tang server.
    #[cfg(feature = "full")]
    pub fn fetch_advertisement(&self, thumbprint: Option<&str>) -> Result<String> {
        use reqwest::blocking::Client;

        let base_url = self.normalize_url(&self.server_url);
        let fetch_url = if let Some(thp) = thumbprint {
            format!("{}/adv/{}", base_url, thp)
        } else {
            format!("{}/adv", base_url)
        };
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "fetch_adv_start";
            url = fetch_url.as_str()
        );
        let client = Client::new();
        let response = client
            .get(&fetch_url)
            .send()
            .map_err(|e| Error::http(format!("Failed to fetch advertisement: {}", e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(Error::http(format!(
                "Server returned error: {} (url={}, body={})",
                status, fetch_url, body
            )));
        }
        let bytes = response
            .bytes()
            .map_err(|e| Error::http(format!("Failed to read response: {}", e)))?
            .to_vec();
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "fetch_adv_ok";
            url = fetch_url.as_str(),
            bytes_len = bytes.len()
        );
        String::from_utf8(bytes)
            .map_err(|e| Error::http(format!("Invalid UTF-8 in advertisement: {}", e)))
    }

    /// Fetch server policy from the Tang server.
    #[cfg(feature = "full")]
    pub fn fetch_policy(&self) -> Result<TangPolicy> {
        use reqwest::blocking::Client;

        let base_url = self.normalize_url(&self.server_url);
        let fetch_url = format!("{}/policy", base_url);
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "fetch_policy_start";
            url = fetch_url.as_str()
        );
        let client = Client::new();
        let response = client
            .get(&fetch_url)
            .send()
            .map_err(|e| Error::http(format!("Failed to fetch policy: {}", e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(Error::http(format!(
                "Server returned error: {} (url={}, body={})",
                status, fetch_url, body
            )));
        }
        response
            .json()
            .map_err(|e| Error::http(format!("Failed to parse policy: {}", e)))
    }
}

impl ExchangeCallback for HttpExchangeCallback {
    #[cfg(feature = "full")]
    fn exchange(
        &self,
        server_key_id: &str,
        advertized_keys: &JwkSet,
        request_data: &[u8],
        allow_tofu: bool,
    ) -> Result<Vec<u8>> {
        use reqwest::blocking::Client;
        use reqwest::header::CONTENT_TYPE;
        use std::time::Instant;

        let base_url = self.normalize_url(&self.server_url);
        let url = format!("{}/rec/{}", base_url, server_key_id);
        let client = Client::new();
        let start = Instant::now();

        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "exchange_start";
            url = url.as_str(),
            kid = server_key_id,
            request_len = request_data.len()
        );
        let request: RecoveryRequest = serde_json::from_slice(request_data)
            .map_err(|e| Error::http(format!("Failed to parse recovery request: {}", e)))?;

        let mut request_builder = client.post(&url);
        if allow_tofu {
            request_builder = request_builder.header("X-Kunci-Trust", "tofu");
        }
        let response = request_builder
            .json(&request)
            .send()
            .map_err(|e| Error::http(format!("Failed to send recovery request: {}", e)))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "exchange_status";
            url = url.as_str(),
            kid = server_key_id,
            status = status.as_u16(),
            content_type = content_type,
            elapsed_ms = start.elapsed().as_millis()
        );

        if !status.is_success() {
            let adv_exchange_keys: Vec<String> = advertized_keys
                .keys
                .iter()
                .filter(|jwk| jwk.has_op("deriveKey") && jwk.alg() == Some("ECMR"))
                .filter_map(|jwk| jwk.thumbprint("S256").ok())
                .collect();
            let body = response.text().unwrap_or_default();
            return Err(Error::http(format!(
                "Server returned error: {} (url={}, kid={}, adv_exchange_keys={:?}, body={})",
                status, url, server_key_id, adv_exchange_keys, body
            )));
        }

        let response_bytes = response
            .bytes()
            .map_err(|e| Error::http(format!("Failed to read response: {}", e)))?
            .to_vec();
        crate::klog!(
            module: "tang",
            level: crate::log::LogLevel::Debug,
            "exchange_ok";
            url = url.as_str(),
            kid = server_key_id,
            response_len = response_bytes.len()
        );

        Ok(response_bytes)
    }

    #[cfg(not(feature = "full"))]
    fn exchange(
        &self,
        _server_key_id: &str,
        _advertized_keys: &JwkSet,
        _request_data: &[u8],
        _allow_tofu: bool,
    ) -> Result<Vec<u8>> {
        Err(Error::http("HTTP client features not enabled"))
    }
}

/// ConcatKDF (Concatenation Key Derivation Function) from RFC 7518.
///
/// # Arguments
///
/// * `shared_secret` - The shared secret (Z).
/// * `other_info` - The OtherInfo parameter (concatenated as per RFC 7518).
/// * `keydatalen` - The length of the derived key in bytes.
///
/// # Returns
///
/// The derived key.
fn concat_kdf(shared_secret: &[u8], other_info: &[u8], keydatalen: usize) -> Vec<u8> {
    use sha2::{Sha256, Digest};

    let hash_len = 32; // SHA-256 output length
    let n = (keydatalen + hash_len - 1) / hash_len; // ceil(keydatalen / hash_len)

    let mut derived_key = Vec::with_capacity(n * hash_len);

    for i in 1..=n {
        let mut hasher = Sha256::new();
        hasher.update(&(i as u32).to_be_bytes()); // counter as 4-byte big-endian
        hasher.update(shared_secret);
        hasher.update(other_info);
        derived_key.extend_from_slice(&hasher.finalize());
    }

    derived_key.truncate(keydatalen);
    derived_key
}

fn derive_key_from_shared_secret(shared_secret: &[u8], header: &Value) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Derive key using ConcatKDF (RFC 7518).
    let cealg = header
        .get("enc")
        .and_then(|v| v.as_str())
        .unwrap_or("A256GCM");

    let keysize = match cealg {
        "A128GCM" => 16,
        "A192GCM" => 24,
        "A256GCM" => 32,
        "A128CBC-HS256" => 16,
        "A192CBC-HS384" => 24,
        "A256CBC-HS512" => 32,
        _ => return Err(Error::crypto(format!("Unsupported encryption algorithm: {}", cealg))),
    };

    // Prepare ConcatKDF data.
    let mut data = Vec::new();

    // Algorithm ID
    let alg_bytes = cealg.as_bytes();
    data.extend_from_slice(&(alg_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(alg_bytes);

    // PartyUInfo (apu) - optional, from header
    if let Some(apu) = header.get("apu").and_then(|v| v.as_str()) {
        let apu_bytes = URL_SAFE_NO_PAD
            .decode(apu)
            .map_err(|e| Error::crypto(format!("Failed to decode apu: {}", e)))?;
        data.extend_from_slice(&(apu_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(&apu_bytes);
    } else {
        data.extend_from_slice(&0u32.to_be_bytes());
    }

    // PartyVInfo (apv) - optional, from header
    if let Some(apv) = header.get("apv").and_then(|v| v.as_str()) {
        let apv_bytes = URL_SAFE_NO_PAD
            .decode(apv)
            .map_err(|e| Error::crypto(format!("Failed to decode apv: {}", e)))?;
        data.extend_from_slice(&(apv_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(&apv_bytes);
    } else {
        data.extend_from_slice(&0u32.to_be_bytes());
    }

    // PubInfo (key length in bits)
    let pubinfo = (keysize * 8) as u32;
    data.extend_from_slice(&pubinfo.to_be_bytes());

    Ok(concat_kdf(shared_secret, &data, keysize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn test_encrypt_with_tang_protocol_placeholder() {
        // This test is just to ensure the function compiles.
        // Actual tests require the "full" feature and a mock advertisement.
        let result = encrypt_with_tang_protocol(
            b"test",
            "dummy.advertisement",
            None,
            json!({"pin": "tang"}),
            false,
        );
        // With "full" feature, it will attempt to parse the advertisement and fail.
        // Without "full", it returns an error.
        assert!(result.is_err());
    }

    #[cfg(not(feature = "full"))]
    #[test]
    fn test_recover_key_with_tang_protocol_placeholder() {
        struct MockCallback;
        impl ExchangeCallback for MockCallback {
            fn exchange(
                &self,
                _server_key_id: &str,
                _advertized_keys: &JwkSet,
                _request_data: &[u8],
                _allow_tofu: bool,
            ) -> Result<Vec<u8>> {
                Ok(vec![])
            }
        }

        let callback = MockCallback;
        let result = recover_key_with_tang_protocol("dummy.jwe", "{}", None, &callback, false);
        assert!(result.is_err());
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_recover_key_with_tang_protocol_roundtrip() {
        use std::sync::Arc;

        let tempdir = TempDir::new().unwrap();
        let config = crate::tang::TangConfig::new(tempdir.path().to_string_lossy().into_owned());
        let server = Arc::new(crate::tang::TangServer::new(config).unwrap());
        let adv = server.get_advertisement().unwrap().jws;
        let thp = server
            .key_store()
            .signing_keys
            .first()
            .and_then(|key| key.thumbprint("S256").ok())
            .expect("signing key thumbprint");

        let clevis_node = json!({
            "pin": "tang",
            "tang": {
                "adv": adv
            }
        });

        let plaintext = b"roundtrip-secret";
        let jwe =
            encrypt_with_tang_protocol(plaintext, &adv, Some(&thp), clevis_node, false).unwrap();

        struct LocalExchange {
            server: Arc<crate::tang::TangServer>,
        }

        impl ExchangeCallback for LocalExchange {
            fn exchange(
                &self,
                server_key_id: &str,
                _advertized_keys: &JwkSet,
                request_data: &[u8],
                _allow_tofu: bool,
            ) -> Result<Vec<u8>> {
                let request: crate::tang::RecoveryRequest = serde_json::from_slice(request_data)
                    .map_err(|e| Error::validation(format!("Invalid recovery request: {}", e)))?;
                let response = self.server.recover(server_key_id, &request)?;
                serde_json::to_vec(&response)
                    .map_err(|e| Error::crypto(format!("Failed to serialize recovery response: {}", e)))
            }
        }

        let exchange = LocalExchange { server };
        let key =
            recover_key_with_tang_protocol(&jwe, &adv, Some(&thp), &exchange, false).unwrap();
        let recovered = crate::jose::jwe_decrypt_dir_a256gcm(&jwe, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_encrypt_with_tang_protocol_header_fields() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let tempdir = TempDir::new().unwrap();
        let store = crate::keys::KeyStore::load(tempdir.path()).unwrap();
        let adv = store.advertisement(None).unwrap();
        let thp = store
            .signing_keys
            .first()
            .and_then(|key| key.thumbprint("S256").ok())
            .expect("signing key thumbprint");

        let clevis_node = json!({
            "pin": "tang",
            "tang": {
                "adv": adv
            }
        });

        let jwe =
            encrypt_with_tang_protocol(b"secret", &adv, Some(&thp), clevis_node, false).unwrap();
        let header_b64 = jwe.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: Value = serde_json::from_slice(&header_bytes).unwrap();

        assert!(header.get("epk").is_some());
        assert!(header.get("clevis").is_some());
        assert!(header.get("client_jwk").is_none());
        let kid = header.get("kid").and_then(|v| v.as_str()).unwrap();

        let payload = jose::extract_jws_payload(&adv).unwrap();
        let jwk_set: JwkSet = serde_json::from_value(payload).unwrap();
        let mut kid_matches = false;
        for jwk in &jwk_set.keys {
            if jwk.has_op("deriveKey") && jwk.alg() == Some("ECMR") {
                if let Ok(tp) = jwk.thumbprint("S256") {
                    if tp == kid {
                        kid_matches = true;
                        break;
                    }
                }
            }
        }
        assert!(kid_matches);
    }

    #[test]
    fn test_concat_kdf() {
        // Test vector from Go test
        let shared_secret = b"input";
        let other_info = &[];
        let keydatalen = 48;
        let expected = hex::decode("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0700f1ab918a5f0413b8140f9940d6955").unwrap();
        let result = concat_kdf(shared_secret, other_info, keydatalen);
        assert_eq!(result, expected);

        let keydatalen = 64;
        let expected = hex::decode("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0700f1ab918a5f0413b8140f9940d6955f3467fd6672cce1024c5b1effccc0f61").unwrap();
        let result = concat_kdf(shared_secret, other_info, keydatalen);
        assert_eq!(result, expected);

        // RFC 7518 Appendix C test vector
        let shared_secret = hex::decode("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4").unwrap();
        let other_info = hex::decode("000000074131323847434d00000005416c69636500000003426f6200000080").unwrap();
        let keydatalen = 16;
        let expected = hex::decode("56aa8deaf8236d205c2228cd71a7101a").unwrap();
        let result = concat_kdf(&shared_secret, &other_info, keydatalen);
        assert_eq!(result, expected);
    }
}
