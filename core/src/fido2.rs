//! FIDO2 hmac-secret wrapping-key provider.

use std::fs;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::keys::WrappingKeyProvider;
use crate::{Error, Result};

const METADATA_VERSION: u8 = 1;
const DEFAULT_RP_ID: &str = "kunci-server.local";
const DEFAULT_RP_NAME: &str = "Kunci Server";
const DEFAULT_USER_NAME: &str = "kunci-server";
const DEFAULT_USER_DISPLAY_NAME: &str = "Kunci Server";
const DEFAULT_DERIVE_INFO: &[u8] = b"kunci server keystore fido2 v1";
#[cfg(feature = "fido2")]
const FIDO2_CLIENT_DATA: &[u8] = b"kunci-server-fido2-wrapping-key";
#[cfg(feature = "fido2")]
const FIDO2_USER_ID: &[u8] = b"kunci-server";
#[cfg(feature = "fido2")]
const FIDO2_MAX_DEVICES: usize = 16;
const FIDO2_SALT_LEN: usize = 32;
const WRAPPING_KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// FIDO2 user-verification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fido2UserVerification {
    /// Let the authenticator and libfido2 choose their default behavior.
    Omit,
    /// Require user verification.
    Required,
    /// Do not request user verification.
    Discouraged,
}

impl Default for Fido2UserVerification {
    fn default() -> Self {
        Self::Discouraged
    }
}

impl Fido2UserVerification {
    /// Parses a CLI/config user-verification policy.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "omit" => Ok(Self::Omit),
            "required" | "true" => Ok(Self::Required),
            "discouraged" | "false" => Ok(Self::Discouraged),
            _ => Err(Error::config(format!(
                "Unsupported FIDO2 user verification policy: {}",
                value
            ))),
        }
    }
}

/// Stored FIDO2 credential metadata for deriving the server wrapping key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fido2CredentialMetadata {
    /// Metadata schema version.
    pub version: u8,
    /// Relying-party ID used for the credential.
    pub rp_id: String,
    /// Base64url credential ID.
    pub credential_id: String,
    /// Base64url 32-byte hmac-secret salt.
    pub salt: String,
    /// User-verification policy used for enrollment and unlock.
    #[serde(default)]
    pub uv: Fido2UserVerification,
    /// User-presence policy used for unlock.
    #[serde(default = "default_user_presence")]
    pub up: bool,
    /// Label used for deriving the AES wrapping key from hmac-secret output.
    #[serde(default = "default_derive_info")]
    pub derive_info: String,
}

impl Fido2CredentialMetadata {
    /// Loads FIDO2 metadata from JSON.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            Error::config(format!(
                "Failed to read FIDO2 metadata {}: {}",
                path.display(),
                e
            ))
        })?;
        let metadata: Self = serde_json::from_str(&content).map_err(|e| {
            Error::config(format!(
                "Failed to parse FIDO2 metadata {}: {}",
                path.display(),
                e
            ))
        })?;
        metadata.validate()?;
        Ok(metadata)
    }

    /// Writes FIDO2 metadata as JSON.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::config(format!("Failed to serialize FIDO2 metadata: {}", e)))?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Decodes the credential ID.
    pub fn credential_id_bytes(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(&self.credential_id)
            .map_err(|e| Error::config(format!("Invalid FIDO2 credential ID: {}", e)))
    }

    /// Decodes the hmac-secret salt.
    pub fn salt_bytes(&self) -> Result<[u8; FIDO2_SALT_LEN]> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.salt)
            .map_err(|e| Error::config(format!("Invalid FIDO2 hmac-secret salt: {}", e)))?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            Error::config(format!(
                "FIDO2 hmac-secret salt must be {} bytes, got {}",
                FIDO2_SALT_LEN,
                bytes.len()
            ))
        })
    }

    fn validate(&self) -> Result<()> {
        if self.version != METADATA_VERSION {
            return Err(Error::config(format!(
                "Unsupported FIDO2 metadata version: {}",
                self.version
            )));
        }
        if self.rp_id.is_empty() {
            return Err(Error::config("FIDO2 metadata rp_id must not be empty"));
        }
        if self.derive_info.is_empty() {
            return Err(Error::config(
                "FIDO2 metadata derive_info must not be empty",
            ));
        }
        let _ = self.credential_id_bytes()?;
        let _ = self.salt_bytes()?;
        Ok(())
    }
}

/// Options used to enroll a new FIDO2 hmac-secret credential.
#[derive(Debug, Clone)]
pub struct Fido2EnrollOptions {
    /// Device path or `auto`.
    pub device: Option<String>,
    /// Relying-party ID.
    pub rp_id: String,
    /// Relying-party display name.
    pub rp_name: String,
    /// Credential user name.
    pub user_name: String,
    /// Credential user display name.
    pub user_display_name: String,
    /// User-verification policy.
    pub uv: Fido2UserVerification,
    /// User-presence policy for future unlock operations.
    pub up: bool,
    /// Optional PIN.
    pub pin: Option<String>,
}

impl Default for Fido2EnrollOptions {
    fn default() -> Self {
        Self {
            device: None,
            rp_id: DEFAULT_RP_ID.to_string(),
            rp_name: DEFAULT_RP_NAME.to_string(),
            user_name: DEFAULT_USER_NAME.to_string(),
            user_display_name: DEFAULT_USER_DISPLAY_NAME.to_string(),
            uv: Fido2UserVerification::default(),
            up: true,
            pin: None,
        }
    }
}

/// FIDO2 hmac-secret wrapping key provider.
#[derive(Debug, Clone)]
pub struct Fido2WrappingKeyProvider {
    metadata: Fido2CredentialMetadata,
    device: Option<String>,
    pin: Option<String>,
}

impl Fido2WrappingKeyProvider {
    /// Creates a provider from stored metadata.
    pub fn new(
        metadata: Fido2CredentialMetadata,
        device: Option<String>,
        pin: Option<String>,
    ) -> Self {
        Self {
            metadata,
            device,
            pin,
        }
    }

    /// Creates a provider from a metadata file.
    pub fn from_metadata_file(
        metadata_file: &Path,
        device: Option<String>,
        pin: Option<String>,
    ) -> Result<Self> {
        Ok(Self::new(
            Fido2CredentialMetadata::load(metadata_file)?,
            device,
            pin,
        ))
    }
}

impl WrappingKeyProvider for Fido2WrappingKeyProvider {
    fn wrapping_key(&self) -> Result<[u8; WRAPPING_KEY_LEN]> {
        let credential_id = self.metadata.credential_id_bytes()?;
        let salt = self.metadata.salt_bytes()?;
        let secret = fido2_hmac_secret(
            self.device.as_deref(),
            &self.metadata.rp_id,
            &credential_id,
            &salt,
            self.metadata.uv,
            self.metadata.up,
            self.pin.as_deref(),
        )?;
        derive_wrapping_key(&secret, self.metadata.derive_info.as_bytes())
    }
}

/// Enrolls a new FIDO2 credential and returns its metadata.
pub fn enroll_fido2_credential(options: &Fido2EnrollOptions) -> Result<Fido2CredentialMetadata> {
    let mut salt = [0u8; FIDO2_SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    let credential_id = make_hmac_secret_credential(options)?;

    Ok(Fido2CredentialMetadata {
        version: METADATA_VERSION,
        rp_id: options.rp_id.clone(),
        credential_id: URL_SAFE_NO_PAD.encode(credential_id),
        salt: URL_SAFE_NO_PAD.encode(salt),
        uv: options.uv,
        up: options.up,
        derive_info: default_derive_info(),
    })
}

fn derive_wrapping_key(secret: &[u8], info: &[u8]) -> Result<[u8; WRAPPING_KEY_LEN]> {
    if secret.is_empty() {
        return Err(Error::crypto("FIDO2 hmac-secret output was empty"));
    }
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| Error::crypto(format!("Invalid FIDO2 hmac-secret output: {}", e)))?;
    mac.update(info);
    Ok(mac.finalize().into_bytes().into())
}

fn default_user_presence() -> bool {
    true
}

fn default_derive_info() -> String {
    String::from_utf8(DEFAULT_DERIVE_INFO.to_vec()).expect("derive info is valid UTF-8")
}

#[cfg(feature = "fido2")]
fn make_hmac_secret_credential(options: &Fido2EnrollOptions) -> Result<Vec<u8>> {
    use fido2_rs::credentials::{CoseType, Credential, Extensions, Opt};

    let device = open_fido2_device(options.device.as_deref())?;
    let mut credential = Credential::new();
    credential
        .set_client_data(FIDO2_CLIENT_DATA)
        .map_err(fido2_error)?;
    credential
        .set_rp(&options.rp_id, &options.rp_name)
        .map_err(fido2_error)?;
    credential
        .set_user(
            FIDO2_USER_ID,
            &options.user_name,
            Some(&options.user_display_name),
            None,
        )
        .map_err(fido2_error)?;
    credential
        .set_cose_type(CoseType::ES256)
        .map_err(fido2_error)?;
    credential
        .set_extension(Extensions::HMAC_SECRET)
        .map_err(fido2_error)?;
    credential.set_rk(Opt::False).map_err(fido2_error)?;
    credential
        .set_uv(fido2_uv_opt(options.uv))
        .map_err(fido2_error)?;
    device
        .make_credential(&mut credential, options.pin.as_deref())
        .map_err(fido2_error)?;
    let id = credential.id();
    if id.is_empty() {
        return Err(Error::crypto(
            "FIDO2 credential enrollment did not return a credential ID",
        ));
    }
    Ok(id.to_vec())
}

#[cfg(not(feature = "fido2"))]
fn make_hmac_secret_credential(_options: &Fido2EnrollOptions) -> Result<Vec<u8>> {
    Err(Error::config(
        "FIDO2 support is not compiled in; rebuild kunci-core with the fido2 feature",
    ))
}

#[cfg(feature = "fido2")]
fn fido2_hmac_secret(
    device_path: Option<&str>,
    rp_id: &str,
    credential_id: &[u8],
    salt: &[u8; FIDO2_SALT_LEN],
    uv: Fido2UserVerification,
    up: bool,
    pin: Option<&str>,
) -> Result<Vec<u8>> {
    use fido2_rs::assertion::AssertRequest;
    use fido2_rs::credentials::{Extensions, Opt};

    let device = open_fido2_device(device_path)?;
    let mut request = AssertRequest::new();
    request
        .set_client_data(FIDO2_CLIENT_DATA)
        .map_err(fido2_error)?;
    request.set_rp(rp_id).map_err(fido2_error)?;
    request
        .set_allow_credential(credential_id)
        .map_err(fido2_error)?;
    request
        .set_extensions(Extensions::HMAC_SECRET)
        .map_err(fido2_error)?;
    request.set_hmac_salt(salt).map_err(fido2_error)?;
    request.set_uv(fido2_uv_opt(uv)).map_err(fido2_error)?;
    request
        .set_up(if up { Opt::True } else { Opt::False })
        .map_err(fido2_error)?;

    let assertions = device.get_assertion(request, pin).map_err(fido2_error)?;
    let mut iter = assertions.iter();
    let assertion = iter
        .next()
        .ok_or_else(|| Error::crypto("FIDO2 hmac-secret assertion returned no results"))?;
    let secret = assertion.hmac_secret();
    if secret.is_empty() {
        return Err(Error::crypto(
            "FIDO2 authenticator did not return hmac-secret output",
        ));
    }
    Ok(secret.to_vec())
}

#[cfg(not(feature = "fido2"))]
fn fido2_hmac_secret(
    _device_path: Option<&str>,
    _rp_id: &str,
    _credential_id: &[u8],
    _salt: &[u8; FIDO2_SALT_LEN],
    _uv: Fido2UserVerification,
    _up: bool,
    _pin: Option<&str>,
) -> Result<Vec<u8>> {
    Err(Error::config(
        "FIDO2 support is not compiled in; rebuild kunci-core with the fido2 feature",
    ))
}

#[cfg(feature = "fido2")]
fn open_fido2_device(device_path: Option<&str>) -> Result<fido2_rs::device::Device> {
    use fido2_rs::device::{Device, DeviceList};

    match device_path {
        Some(path) if path != "auto" => Device::open(path).map_err(fido2_error),
        _ => {
            let mut devices = DeviceList::list_devices(FIDO2_MAX_DEVICES);
            let first = devices.next().ok_or_else(|| {
                Error::config("No FIDO2 authenticator found; provide --fido2-device")
            })?;
            if devices.next().is_some() {
                return Err(Error::config(
                    "Multiple FIDO2 authenticators found; provide --fido2-device",
                ));
            }
            first.open().map_err(fido2_error)
        }
    }
}

#[cfg(feature = "fido2")]
fn fido2_uv_opt(uv: Fido2UserVerification) -> fido2_rs::credentials::Opt {
    match uv {
        Fido2UserVerification::Omit => fido2_rs::credentials::Opt::Omit,
        Fido2UserVerification::Required => fido2_rs::credentials::Opt::True,
        Fido2UserVerification::Discouraged => fido2_rs::credentials::Opt::False,
    }
}

#[cfg(feature = "fido2")]
fn fido2_error(error: fido2_rs::error::Error) -> Error {
    Error::crypto(format!("FIDO2 operation failed: {}", error))
}

/// Reads a PIN from a file, trimming one trailing line ending.
pub fn read_pin_file(path: &Path) -> Result<String> {
    let mut pin = fs::read_to_string(path).map_err(|e| {
        Error::config(format!(
            "Failed to read FIDO2 PIN file {}: {}",
            path.display(),
            e
        ))
    })?;
    if pin.ends_with('\n') {
        pin.pop();
        if pin.ends_with('\r') {
            pin.pop();
        }
    }
    if pin.is_empty() {
        return Err(Error::config("FIDO2 PIN file must not be empty"));
    }
    Ok(pin)
}

/// Returns a default metadata file path under the key directory.
pub fn default_metadata_file(directory: &Path) -> PathBuf {
    directory.join("fido2-credential.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fido2_metadata_roundtrip_and_validation() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("fido2.json");
        let metadata = Fido2CredentialMetadata {
            version: 1,
            rp_id: "kunci-server.local".to_string(),
            credential_id: URL_SAFE_NO_PAD.encode([1u8; 16]),
            salt: URL_SAFE_NO_PAD.encode([2u8; 32]),
            uv: Fido2UserVerification::Discouraged,
            up: true,
            derive_info: "kunci test".to_string(),
        };

        metadata.save(&path).expect("save metadata");
        let parsed = Fido2CredentialMetadata::load(&path).expect("load metadata");
        assert_eq!(parsed, metadata);
        assert_eq!(parsed.credential_id_bytes().unwrap(), vec![1u8; 16]);
        assert_eq!(parsed.salt_bytes().unwrap(), [2u8; 32]);
    }

    #[test]
    fn test_fido2_metadata_rejects_bad_salt_len() {
        let metadata = Fido2CredentialMetadata {
            version: 1,
            rp_id: "kunci-server.local".to_string(),
            credential_id: URL_SAFE_NO_PAD.encode([1u8; 16]),
            salt: URL_SAFE_NO_PAD.encode([2u8; 31]),
            uv: Fido2UserVerification::Discouraged,
            up: true,
            derive_info: "kunci test".to_string(),
        };

        let err = metadata.validate().expect_err("bad salt should fail");
        assert!(err.to_string().contains("salt must be 32 bytes"));
    }

    #[test]
    fn test_fido2_user_verification_parse() {
        assert_eq!(
            Fido2UserVerification::parse("required").unwrap(),
            Fido2UserVerification::Required
        );
        assert_eq!(
            Fido2UserVerification::parse("discouraged").unwrap(),
            Fido2UserVerification::Discouraged
        );
        assert_eq!(
            Fido2UserVerification::parse("omit").unwrap(),
            Fido2UserVerification::Omit
        );
        assert!(Fido2UserVerification::parse("bad").is_err());
    }

    #[test]
    fn test_derive_wrapping_key_is_stable_and_domain_separated() {
        let key_a = derive_wrapping_key(&[7u8; 32], b"info-a").unwrap();
        let key_b = derive_wrapping_key(&[7u8; 32], b"info-a").unwrap();
        let key_c = derive_wrapping_key(&[7u8; 32], b"info-b").unwrap();

        assert_eq!(key_a, key_b);
        assert_ne!(key_a, key_c);
    }
}
