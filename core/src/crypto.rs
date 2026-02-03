//! Cryptographic primitives and operations for Tang and Clevis.
//!
//! This module provides cryptographic functionality used by both the Tang server
//! and Clevis client, including:
//!
//! - ECDH key exchange (McCallum-Relyea exchange)
//! - JWS signing and verification
//! - Key generation and validation
//! - Cryptographic utilities

use std::fmt;

use crate::jwk::{EcJwk, Jwk};

#[cfg(feature = "full")]
use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "full")]
use elliptic_curve::SecretKey;
#[cfg(feature = "full")]
use p256::NistP256;
#[cfg(feature = "full")]
use p384::NistP384;
#[cfg(feature = "full")]
use p521::NistP521;
#[cfg(feature = "full")]
use rand_core::OsRng;

/// Cryptographic algorithm errors.
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// Unsupported algorithm or curve.
    UnsupportedAlgorithm(String),
    /// Invalid key for operation.
    InvalidKey(String),
    /// Key exchange failure.
    ExchangeFailed(String),
    /// Signing failure.
    SigningFailed(String),
    /// Verification failure.
    VerificationFailed(String),
    /// Key generation failure.
    KeyGenFailed(String),
    /// Hash computation failure.
    HashFailed(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::UnsupportedAlgorithm(msg) => write!(f, "Unsupported algorithm: {}", msg),
            CryptoError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            CryptoError::ExchangeFailed(msg) => write!(f, "Key exchange failed: {}", msg),
            CryptoError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            CryptoError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            CryptoError::KeyGenFailed(msg) => write!(f, "Key generation failed: {}", msg),
            CryptoError::HashFailed(msg) => write!(f, "Hash computation failed: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Result type for cryptographic operations.
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

/// Elliptic curve identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    /// P-256 curve (secp256r1)
    P256,
    /// P-384 curve (secp384r1)
    P384,
    /// P-521 curve (secp521r1)
    P521,
}

impl Curve {
    /// Returns the curve name as used in JWK "crv" field.
    pub fn as_jwk_crv(&self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
            Curve::P521 => "P-521",
        }
    }

    /// Creates a curve from JWK "crv" field value.
    pub fn from_jwk_crv(crv: &str) -> CryptoResult<Self> {
        match crv {
            "P-256" => Ok(Curve::P256),
            "P-384" => Ok(Curve::P384),
            "P-521" => Ok(Curve::P521),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "Unsupported curve: {}",
                crv
            ))),
        }
    }
}

/// Key exchange algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeAlgorithm {
    /// McCallum-Relyea exchange (ECMR)
    ECMR,
    /// Elliptic Curve Diffie-Hellman
    ECDH,
}

impl ExchangeAlgorithm {
    /// Returns the algorithm name as used in JWK "alg" field.
    pub fn as_jwk_alg(&self) -> &'static str {
        match self {
            ExchangeAlgorithm::ECMR => "ECMR",
            ExchangeAlgorithm::ECDH => "ECDH",
        }
    }

    /// Creates an algorithm from JWK "alg" field value.
    pub fn from_jwk_alg(alg: &str) -> CryptoResult<Self> {
        match alg {
            "ECMR" => Ok(ExchangeAlgorithm::ECMR),
            "ECDH" => Ok(ExchangeAlgorithm::ECDH),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "Unsupported exchange algorithm: {}",
                alg
            ))),
        }
    }
}

/// Signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// ECDSA with SHA-256
    ES256,
    /// ECDSA with SHA-384
    ES384,
    /// ECDSA with SHA-512
    ES512,
}

impl SigningAlgorithm {
    /// Returns the algorithm name as used in JWK "alg" field.
    pub fn as_jwk_alg(&self) -> &'static str {
        match self {
            SigningAlgorithm::ES256 => "ES256",
            SigningAlgorithm::ES384 => "ES384",
            SigningAlgorithm::ES512 => "ES512",
        }
    }

    /// Creates an algorithm from JWK "alg" field value.
    pub fn from_jwk_alg(alg: &str) -> CryptoResult<Self> {
        match alg {
            "ES256" => Ok(SigningAlgorithm::ES256),
            "ES384" => Ok(SigningAlgorithm::ES384),
            "ES512" => Ok(SigningAlgorithm::ES512),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "Unsupported signing algorithm: {}",
                alg
            ))),
        }
    }

    /// Returns the recommended curve for this algorithm.
    pub fn recommended_curve(&self) -> Curve {
        match self {
            SigningAlgorithm::ES256 => Curve::P256,
            SigningAlgorithm::ES384 => Curve::P384,
            SigningAlgorithm::ES512 => Curve::P521,
        }
    }

    /// Returns the hash output size in bits.
    pub fn hash_size_bits(&self) -> usize {
        match self {
            SigningAlgorithm::ES256 => 256,
            SigningAlgorithm::ES384 => 384,
            SigningAlgorithm::ES512 => 512,
        }
    }
}

/// Performs McCallum-Relyea key exchange (server side).
///
/// This implements the exchange described in the Tang specification:
/// 1. Server has key `s` (private) and advertises `sJWK = g * S`
/// 2. Client generates `cJWK = g * C` during provisioning
/// 3. Shared secret `K = s * C = c * S` is used to encrypt data
/// 4. During recovery, client blinds request with ephemeral key `eJWK = g * E`
/// 5. Client sends `xJWK = cJWK + eJWK` to server
/// 6. Server computes `yJWK = xJWK * S`
/// 7. Client computes `zJWK = sJWK * E`
/// 8. Client recovers `K = yJWK - zJWK`
///
/// This function implements the server-side computation (step 6).
#[cfg(feature = "full")]
pub fn mccallum_relyea_exchange(server_jwk: &Jwk, client_jwk: &Jwk) -> CryptoResult<Jwk> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::{EncodedPoint, PublicKey, SecretKey};

    crate::klog!(
        module: "crypto",
        level: crate::log::LogLevel::Debug,
        "mccallum_relyea_exchange";
        server_alg = server_jwk.alg().unwrap_or(""),
        client_alg = client_jwk.alg().unwrap_or("")
    );

    // Validate input JWKs are EC keys
    let Jwk::EC(server_ec) = server_jwk else {
        return Err(CryptoError::InvalidKey("Server JWK must be an EC key".to_string()));
    };
    
    let Jwk::EC(client_ec) = client_jwk else {
        return Err(CryptoError::InvalidKey("Client JWK must be an EC key".to_string()));
    };

    // Check curves match and are P-256 (ECMR uses P-256)
    if server_ec.crv != "P-256" || client_ec.crv != "P-256" {
        return Err(CryptoError::UnsupportedAlgorithm(
            "Only P-256 curve is supported for McCallum-Relyea exchange".to_string(),
        ));
    }

    // Get server's private key (d)
    let server_d = server_ec.d.as_ref().ok_or_else(|| {
        CryptoError::InvalidKey("Server JWK must contain private key (d) for exchange".to_string())
    })?;

    // Decode base64url coordinates
    let server_d_bytes = URL_SAFE_NO_PAD.decode(server_d).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode server private key: {}", e))
    })?;
    
    let client_x_bytes = URL_SAFE_NO_PAD.decode(&client_ec.x).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode client x coordinate: {}", e))
    })?;
    
    let client_y_bytes = URL_SAFE_NO_PAD.decode(&client_ec.y).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode client y coordinate: {}", e))
    })?;

    // Convert to fixed-size arrays (P-256 uses 32-byte coordinates)
    let server_d_array: [u8; 32] = server_d_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Server private key must be 32 bytes".to_string())
    })?;
    let client_x_array: [u8; 32] = client_x_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Client x coordinate must be 32 bytes".to_string())
    })?;
    let client_y_array: [u8; 32] = client_y_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Client y coordinate must be 32 bytes".to_string())
    })?;

    // Create server secret key
    let server_secret_key = SecretKey::from_slice(&server_d_array).map_err(|e| {
        CryptoError::InvalidKey(format!("Invalid server private key: {}", e))
    })?;

    // Create client public key from coordinates
    // Build uncompressed SEC1 format: 0x04 || x || y
    let mut uncompressed_point = Vec::with_capacity(65);
    uncompressed_point.push(0x04); // uncompressed point tag
    uncompressed_point.extend_from_slice(&client_x_array);
    uncompressed_point.extend_from_slice(&client_y_array);
    
    let encoded_point = EncodedPoint::from_bytes(&uncompressed_point)
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to create encoded point: {}", e)))?;
    
    let client_public_key = PublicKey::from_sec1_bytes(encoded_point.as_bytes())
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid public key: {}", e)))?;

    // Compute shared point: yJWK = xJWK * s (server private scalar)
    use p256::{ProjectivePoint, Scalar};
    let server_scalar: Scalar = *server_secret_key.to_nonzero_scalar();
    let client_point: ProjectivePoint = client_public_key.to_projective();
    let shared_point = client_point * server_scalar;

    // Convert to affine coordinates
    let shared_affine = shared_point.to_affine();

    // Extract coordinates from the resulting point
    let shared_encoded = EncodedPoint::from(shared_affine);
    let (shared_x, shared_y) = match shared_encoded.coordinates() {
        p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (x, y),
        _ => return Err(CryptoError::ExchangeFailed(
            "Unexpected compressed point after multiplication".to_string(),
        )),
    };

    // Encode coordinates as base64url
    let x_b64 = URL_SAFE_NO_PAD.encode(shared_x);
    let y_b64 = URL_SAFE_NO_PAD.encode(shared_y);

    // Create resulting JWK (public key only, for exchange)
    Ok(Jwk::EC(EcJwk {
        crv: "P-256".to_string(),
        x: x_b64,
        y: y_b64,
        d: None, // Never return private key
        alg: Some("ECMR".to_string()),
        use_: Some("enc".to_string()),
        key_ops: Some(vec!["deriveKey".to_string()]),
        kid: None,
    }))
}

/// Computes a shared secret using ECDH (client side for provisioning).
///
/// This function computes the shared secret K = c * S where:
/// - `c` is the client's private scalar (from `client_private_jwk`)
/// - `S` is the server's public point (from `server_public_jwk`)
///
/// This is used during Tang encryption (provisioning) to derive the
/// encryption key without contacting the server.
///
/// # Arguments
///
/// * `server_public_jwk` - Server's public key (sJWK) from advertisement.
/// * `client_private_jwk` - Client's private key (cJWK with `d` field).
///
/// # Returns
///
/// The x-coordinate of the shared secret point K as bytes.
#[cfg(feature = "full")]
pub fn compute_shared_secret(server_public_jwk: &Jwk, client_private_jwk: &Jwk) -> CryptoResult<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::{EncodedPoint, ProjectivePoint, PublicKey, Scalar, SecretKey};

    crate::klog!(
        module: "crypto",
        level: crate::log::LogLevel::Debug,
        "compute_shared_secret";
        server_alg = server_public_jwk.alg().unwrap_or(""),
        client_alg = client_private_jwk.alg().unwrap_or("")
    );

    // Validate input JWKs are EC keys
    let Jwk::EC(server_ec) = server_public_jwk else {
        return Err(CryptoError::InvalidKey("Server JWK must be an EC key".to_string()));
    };
    
    let Jwk::EC(client_ec) = client_private_jwk else {
        return Err(CryptoError::InvalidKey("Client JWK must be an EC key".to_string()));
    };

    // Check curves match and are P-256 (ECMR uses P-256)
    if server_ec.crv != "P-256" || client_ec.crv != "P-256" {
        return Err(CryptoError::UnsupportedAlgorithm(
            "Only P-256 curve is supported for McCallum-Relyea exchange".to_string(),
        ));
    }

    // Get client's private key (d)
    let client_d = client_ec.d.as_ref().ok_or_else(|| {
        CryptoError::InvalidKey("Client JWK must contain private key (d) for shared secret computation".to_string())
    })?;

    // Decode base64url coordinates
    let server_x_bytes = URL_SAFE_NO_PAD.decode(&server_ec.x).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode server x coordinate: {}", e))
    })?;
    let server_y_bytes = URL_SAFE_NO_PAD.decode(&server_ec.y).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode server y coordinate: {}", e))
    })?;
    
    let client_d_bytes = URL_SAFE_NO_PAD.decode(client_d).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode client private key: {}", e))
    })?;

    // Convert to fixed-size arrays (P-256 uses 32-byte coordinates)
    let server_x_array: [u8; 32] = server_x_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Server x coordinate must be 32 bytes".to_string())
    })?;
    let server_y_array: [u8; 32] = server_y_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Server y coordinate must be 32 bytes".to_string())
    })?;
    
    let client_d_array: [u8; 32] = client_d_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Client private key must be 32 bytes".to_string())
    })?;

    // Create client secret key
    let client_secret_key = SecretKey::from_slice(&client_d_array).map_err(|e| {
        CryptoError::InvalidKey(format!("Invalid client private key: {}", e))
    })?;

    // Create server public key from coordinates
    // Build uncompressed SEC1 format: 0x04 || x || y
    let mut server_point_bytes = Vec::with_capacity(65);
    server_point_bytes.push(0x04);
    server_point_bytes.extend_from_slice(&server_x_array);
    server_point_bytes.extend_from_slice(&server_y_array);
    
    let server_encoded_point = EncodedPoint::from_bytes(&server_point_bytes)
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to create encoded point: {}", e)))?;
    
    let server_public_key = PublicKey::from_sec1_bytes(server_encoded_point.as_bytes())
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid public key: {}", e)))?;

    // Compute shared point: K = c * S (client private scalar times server public point)
    let client_scalar: Scalar = *client_secret_key.to_nonzero_scalar();
    let server_point: ProjectivePoint = server_public_key.to_projective();
    let shared_point = server_point * client_scalar;

    // Convert to affine coordinates
    let shared_affine = shared_point.to_affine();

    // Extract x-coordinate from the resulting point
    let shared_encoded = EncodedPoint::from(shared_affine);
    let (shared_x, _shared_y) = match shared_encoded.coordinates() {
        p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (x, y),
        _ => return Err(CryptoError::ExchangeFailed(
            "Unexpected compressed point after multiplication".to_string(),
        )),
    };

    // Return x-coordinate as bytes
    Ok(shared_x.to_vec())
}

/// Performs client-side McCallum-Relyea key exchange.
///
/// This implements the client-side computation for Tang decryption:
/// 1. Client has original key `cJWK` (private) and server's public key `sJWK`
/// 2. Client generates ephemeral key `eJWK` (private) for blinding
/// 3. Client sends `xJWK = cJWK + eJWK` to server
/// 4. Server returns `yJWK = xJWK * S` (server private scalar)
/// 5. Client computes `zJWK = sJWK * E` (ephemeral private scalar)
/// 6. Client recovers `K = yJWK - zJWK`
///
/// This function computes steps 5-6 to recover the shared secret.
///
/// # Arguments
///
/// * `server_public_key` - Server's public key (sJWK) from advertisement.
/// * `ephemeral_private_key` - Client's ephemeral private key (eJWK with `d`).
/// * `server_response` - Server's response (yJWK) from recovery endpoint.
///
/// # Returns
///
/// The x-coordinate of the shared secret point K as bytes.
#[cfg(feature = "full")]
pub fn client_mccallum_relyea_exchange(
    server_public_key: &Jwk,
    ephemeral_private_key: &Jwk,
    server_response: &Jwk,
) -> CryptoResult<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::{EncodedPoint, ProjectivePoint, PublicKey, Scalar, SecretKey};

    crate::klog!(
        module: "crypto",
        level: crate::log::LogLevel::Debug,
        "client_mccallum_relyea_exchange";
        server_alg = server_public_key.alg().unwrap_or(""),
        response_alg = server_response.alg().unwrap_or("")
    );

    // Validate all JWKs are EC keys with P-256 curve
    let Jwk::EC(server_ec) = server_public_key else {
        return Err(CryptoError::InvalidKey("Server public key must be an EC key".to_string()));
    };
    
    let Jwk::EC(ephemeral_ec) = ephemeral_private_key else {
        return Err(CryptoError::InvalidKey("Ephemeral key must be an EC key".to_string()));
    };
    
    let Jwk::EC(response_ec) = server_response else {
        return Err(CryptoError::InvalidKey("Server response must be an EC key".to_string()));
    };

    // Check curves are P-256
    if server_ec.crv != "P-256" || ephemeral_ec.crv != "P-256" || response_ec.crv != "P-256" {
        return Err(CryptoError::UnsupportedAlgorithm(
            "Only P-256 curve is supported for McCallum-Relyea exchange".to_string(),
        ));
    }

    // Get ephemeral private key (d)
    let ephemeral_d = ephemeral_ec.d.as_ref().ok_or_else(|| {
        CryptoError::InvalidKey("Ephemeral key must contain private key (d)".to_string())
    })?;

    // Decode base64url coordinates
    let server_x_bytes = URL_SAFE_NO_PAD.decode(&server_ec.x).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode server x coordinate: {}", e))
    })?;
    let server_y_bytes = URL_SAFE_NO_PAD.decode(&server_ec.y).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode server y coordinate: {}", e))
    })?;
    
    let ephemeral_d_bytes = URL_SAFE_NO_PAD.decode(ephemeral_d).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode ephemeral private key: {}", e))
    })?;
    
    let response_x_bytes = URL_SAFE_NO_PAD.decode(&response_ec.x).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode response x coordinate: {}", e))
    })?;
    let response_y_bytes = URL_SAFE_NO_PAD.decode(&response_ec.y).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to decode response y coordinate: {}", e))
    })?;

    // Convert to fixed-size arrays
    let server_x_array: [u8; 32] = server_x_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Server x coordinate must be 32 bytes".to_string())
    })?;
    let server_y_array: [u8; 32] = server_y_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Server y coordinate must be 32 bytes".to_string())
    })?;
    
    let ephemeral_d_array: [u8; 32] = ephemeral_d_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Ephemeral private key must be 32 bytes".to_string())
    })?;
    
    let response_x_array: [u8; 32] = response_x_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Response x coordinate must be 32 bytes".to_string())
    })?;
    let response_y_array: [u8; 32] = response_y_bytes.try_into().map_err(|_| {
        CryptoError::InvalidKey("Response y coordinate must be 32 bytes".to_string())
    })?;

    // Create ephemeral secret key
    let ephemeral_secret_key = SecretKey::from_slice(&ephemeral_d_array).map_err(|e| {
        CryptoError::InvalidKey(format!("Invalid ephemeral private key: {}", e))
    })?;

    // Create server public key from coordinates
    let mut server_point_bytes = Vec::with_capacity(65);
    server_point_bytes.push(0x04);
    server_point_bytes.extend_from_slice(&server_x_array);
    server_point_bytes.extend_from_slice(&server_y_array);
    
    let server_encoded_point = EncodedPoint::from_bytes(&server_point_bytes)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid server public key: {}", e)))?;
    let server_public_key = PublicKey::from_sec1_bytes(server_encoded_point.as_bytes())
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid server public key: {}", e)))?;

    // Create response point from coordinates
    let mut response_point_bytes = Vec::with_capacity(65);
    response_point_bytes.push(0x04);
    response_point_bytes.extend_from_slice(&response_x_array);
    response_point_bytes.extend_from_slice(&response_y_array);
    
    let response_encoded_point = EncodedPoint::from_bytes(&response_point_bytes)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid response point: {}", e)))?;
    let response_public_key = PublicKey::from_sec1_bytes(response_encoded_point.as_bytes())
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid response point: {}", e)))?;

    // Compute zJWK = sJWK * e (server public key * ephemeral private scalar)
    let ephemeral_scalar: Scalar = *ephemeral_secret_key.to_nonzero_scalar();
    let server_point: ProjectivePoint = server_public_key.to_projective();
    let z_point = server_point * ephemeral_scalar;

    // Convert response point to projective
    let response_point: ProjectivePoint = response_public_key.to_projective();

    // Compute K = yJWK - zJWK
    let k_point = response_point - z_point;

    // Extract x-coordinate of K
    let k_affine = k_point.to_affine();
    let k_encoded = EncodedPoint::from(k_affine);
    let (k_x, _k_y) = match k_encoded.coordinates() {
        p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (x, y),
        _ => return Err(CryptoError::ExchangeFailed(
            "Unexpected compressed point after subtraction".to_string(),
        )),
    };

    // Return x-coordinate as bytes
    Ok(k_x.to_vec())
}

/// Generates a new EC key pair for the given algorithm.
///
/// # Arguments
///
/// * `algorithm` - The algorithm to generate a key for (ES256, ES384, ES512, or ECMR).
///
/// # Returns
///
/// A JWK containing both public and private key material.
#[cfg(feature = "full")]
pub fn generate_key(algorithm: &str) -> CryptoResult<Jwk> {
    crate::klog!(
        module: "crypto",
        level: crate::log::LogLevel::Debug,
        "generate_key";
        algorithm = algorithm
    );
    match algorithm {
        "ES256" => generate_ec_key(Curve::P256, SigningAlgorithm::ES256),
        "ES384" => generate_ec_key(Curve::P384, SigningAlgorithm::ES384),
        "ES512" => generate_ec_key(Curve::P521, SigningAlgorithm::ES512),
        "ECMR" => generate_ec_key(Curve::P256, ExchangeAlgorithm::ECMR),
        _ => Err(CryptoError::UnsupportedAlgorithm(format!(
            "Unsupported algorithm: {}",
            algorithm
        ))),
    }
}

#[cfg(feature = "full")]
fn generate_ec_key<T>(curve: Curve, algorithm: T) -> CryptoResult<Jwk>
where
    T: KeyAlgorithm,
{
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use elliptic_curve::sec1::ToEncodedPoint;

    let (use_, key_ops) = algorithm.key_usage();
    let alg = algorithm.as_jwk_alg();

    match curve {
        Curve::P256 => {
            let secret_key = SecretKey::<NistP256>::random(&mut OsRng);
            let public_key = secret_key.public_key();
            let encoded_point = public_key.to_encoded_point(false);
            let x = encoded_point
                .x()
                .ok_or_else(|| CryptoError::KeyGenFailed("No x coordinate".to_string()))?;
            let y = encoded_point
                .y()
                .ok_or_else(|| CryptoError::KeyGenFailed("No y coordinate".to_string()))?;

            let x_b64 = URL_SAFE_NO_PAD.encode(x);
            let y_b64 = URL_SAFE_NO_PAD.encode(y);
            let d = secret_key.to_bytes();
            let d_b64 = URL_SAFE_NO_PAD.encode(&d);

            Ok(Jwk::EC(EcJwk {
                crv: curve.as_jwk_crv().to_string(),
                x: x_b64,
                y: y_b64,
                d: Some(d_b64),
                alg: Some(alg.to_string()),
                use_: Some(use_),
                key_ops: Some(key_ops),
                kid: None,
            }))
        }
        Curve::P384 => {
            let secret_key = SecretKey::<NistP384>::random(&mut OsRng);
            let public_key = secret_key.public_key();
            let encoded_point = public_key.to_encoded_point(false);
            let x = encoded_point
                .x()
                .ok_or_else(|| CryptoError::KeyGenFailed("No x coordinate".to_string()))?;
            let y = encoded_point
                .y()
                .ok_or_else(|| CryptoError::KeyGenFailed("No y coordinate".to_string()))?;

            let x_b64 = URL_SAFE_NO_PAD.encode(x);
            let y_b64 = URL_SAFE_NO_PAD.encode(y);
            let d = secret_key.to_bytes();
            let d_b64 = URL_SAFE_NO_PAD.encode(&d);

            Ok(Jwk::EC(EcJwk {
                crv: curve.as_jwk_crv().to_string(),
                x: x_b64,
                y: y_b64,
                d: Some(d_b64),
                alg: Some(alg.to_string()),
                use_: Some(use_),
                key_ops: Some(key_ops),
                kid: None,
            }))
        }
        Curve::P521 => {
            let secret_key = SecretKey::<NistP521>::random(&mut OsRng);
            let public_key = secret_key.public_key();
            let encoded_point = public_key.to_encoded_point(false);
            let x = encoded_point
                .x()
                .ok_or_else(|| CryptoError::KeyGenFailed("No x coordinate".to_string()))?;
            let y = encoded_point
                .y()
                .ok_or_else(|| CryptoError::KeyGenFailed("No y coordinate".to_string()))?;

            let x_b64 = URL_SAFE_NO_PAD.encode(x);
            let y_b64 = URL_SAFE_NO_PAD.encode(y);
            let d = secret_key.to_bytes();
            let d_b64 = URL_SAFE_NO_PAD.encode(&d);

            Ok(Jwk::EC(EcJwk {
                crv: curve.as_jwk_crv().to_string(),
                x: x_b64,
                y: y_b64,
                d: Some(d_b64),
                alg: Some(alg.to_string()),
                use_: Some(use_),
                key_ops: Some(key_ops),
                kid: None,
            }))
        }
    }
}

/// Trait for key algorithms to provide metadata.
trait KeyAlgorithm {
    /// Returns the JWK algorithm string.
    fn as_jwk_alg(&self) -> &'static str;

    /// Returns the (use, key_ops) tuple for the key.
    fn key_usage(&self) -> (String, Vec<String>);
}

impl KeyAlgorithm for SigningAlgorithm {
    fn as_jwk_alg(&self) -> &'static str {
        self.as_jwk_alg()
    }

    fn key_usage(&self) -> (String, Vec<String>) {
        (
            "sig".to_string(),
            vec!["sign".to_string(), "verify".to_string()],
        )
    }
}

impl KeyAlgorithm for ExchangeAlgorithm {
    fn as_jwk_alg(&self) -> &'static str {
        self.as_jwk_alg()
    }

    fn key_usage(&self) -> (String, Vec<String>) {
        ("enc".to_string(), vec!["deriveKey".to_string()])
    }
}

/// Creates a JWS signed by the given signing keys.
///
/// This corresponds to the `jwk_sign` function in the original Tang code.
/// Note: This functionality is implemented in the `jose` module.
#[cfg(feature = "full")]
pub fn create_jws(
    _payload: &serde_json::Value,
    _signing_keys: &[Jwk],
) -> CryptoResult<serde_json::Value> {
    Err(CryptoError::UnsupportedAlgorithm(
        "Use jose::create_jws instead".to_string(),
    ))
}

/// Placeholder implementations when full feature is disabled
#[cfg(not(feature = "full"))]
pub fn mccallum_relyea_exchange(_server_jwk: &Jwk, _client_jwk: &Jwk) -> CryptoResult<Jwk> {
    Err(CryptoError::UnsupportedAlgorithm(
        "Cryptographic features not enabled".to_string(),
    ))
}

#[cfg(not(feature = "full"))]
pub fn compute_shared_secret(_server_public_jwk: &Jwk, _client_private_jwk: &Jwk) -> CryptoResult<Vec<u8>> {
    Err(CryptoError::UnsupportedAlgorithm(
        "Cryptographic features not enabled".to_string(),
    ))
}

#[cfg(not(feature = "full"))]
pub fn client_mccallum_relyea_exchange(
    _server_public_key: &Jwk,
    _ephemeral_private_key: &Jwk,
    _server_response: &Jwk,
) -> CryptoResult<Vec<u8>> {
    Err(CryptoError::UnsupportedAlgorithm(
        "Cryptographic features not enabled".to_string(),
    ))
}

#[cfg(not(feature = "full"))]
pub fn generate_key(_algorithm: &str) -> CryptoResult<Jwk> {
    Err(CryptoError::UnsupportedAlgorithm(
        "Cryptographic features not enabled".to_string(),
    ))
}

#[cfg(not(feature = "full"))]
pub fn create_jws(
    _payload: &serde_json::Value,
    _signing_keys: &[Jwk],
) -> CryptoResult<serde_json::Value> {
    Err(CryptoError::UnsupportedAlgorithm(
        "Cryptographic features not enabled".to_string(),
    ))
}

/// Computes SHA-256 hash of data.
#[cfg(feature = "full")]
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Computes SHA-512 hash of data.
#[cfg(feature = "full")]
pub fn sha512_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_from_jwk_crv() {
        assert_eq!(Curve::from_jwk_crv("P-256").unwrap(), Curve::P256);
        assert_eq!(Curve::from_jwk_crv("P-384").unwrap(), Curve::P384);
        assert_eq!(Curve::from_jwk_crv("P-521").unwrap(), Curve::P521);
        assert!(Curve::from_jwk_crv("invalid").is_err());
    }

    #[test]
    fn test_signing_algorithm_from_jwk_alg() {
        assert_eq!(
            SigningAlgorithm::from_jwk_alg("ES256").unwrap(),
            SigningAlgorithm::ES256
        );
        assert_eq!(
            SigningAlgorithm::from_jwk_alg("ES384").unwrap(),
            SigningAlgorithm::ES384
        );
        assert_eq!(
            SigningAlgorithm::from_jwk_alg("ES512").unwrap(),
            SigningAlgorithm::ES512
        );
        assert!(SigningAlgorithm::from_jwk_alg("invalid").is_err());
    }

    #[test]
    fn test_exchange_algorithm_from_jwk_alg() {
        assert_eq!(
            ExchangeAlgorithm::from_jwk_alg("ECMR").unwrap(),
            ExchangeAlgorithm::ECMR
        );
        assert_eq!(
            ExchangeAlgorithm::from_jwk_alg("ECDH").unwrap(),
            ExchangeAlgorithm::ECDH
        );
        assert!(ExchangeAlgorithm::from_jwk_alg("invalid").is_err());
    }

    #[test]
    fn test_signing_algorithm_recommended_curve() {
        assert_eq!(SigningAlgorithm::ES256.recommended_curve(), Curve::P256);
        assert_eq!(SigningAlgorithm::ES384.recommended_curve(), Curve::P384);
        assert_eq!(SigningAlgorithm::ES512.recommended_curve(), Curve::P521);
    }

    #[test]
    #[cfg(feature = "full")]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
    }
}
