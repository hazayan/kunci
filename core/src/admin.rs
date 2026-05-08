//! Admin protocol types for local Unix socket requests.

use serde::{Deserialize, Serialize};

/// Requests supported by the admin socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminRequest {
    /// Return signing key thumbprints using the requested hash.
    ShowKeys {
        /// Hash algorithm for thumbprints (S1, S224, S256, S384, S512).
        hash: String,
    },
    /// Return an encrypted key backup artifact.
    BackupKeys {
        /// Backend used to encrypt the backup artifact.
        backend: String,
        /// Raw 32-byte wrapping key file for the raw-file backend.
        wrapping_key_file: String,
        /// FIDO2 credential metadata file for the fido2 backend.
        fido2_metadata_file: Option<String>,
        /// FIDO2 device path or auto.
        fido2_device: Option<String>,
        /// FIDO2 PIN file.
        fido2_pin_file: Option<String>,
    },
}

/// Admin responses returned to the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminResponse {
    /// Whether the request succeeded.
    pub ok: bool,
    /// Optional list of thumbprints when successful.
    pub thumbprints: Option<Vec<String>>,
    /// Optional encrypted backup artifact when successful.
    pub backup: Option<Vec<u8>>,
    /// Optional error message on failure.
    pub error: Option<String>,
    /// Optional machine-readable error code.
    pub code: Option<String>,
}

impl AdminResponse {
    /// Convenience constructor for a successful key response.
    pub fn ok_keys(keys: Vec<String>) -> Self {
        Self {
            ok: true,
            thumbprints: Some(keys),
            backup: None,
            error: None,
            code: None,
        }
    }

    /// Convenience constructor for a successful encrypted backup response.
    pub fn ok_backup(backup: Vec<u8>) -> Self {
        Self {
            ok: true,
            thumbprints: None,
            backup: Some(backup),
            error: None,
            code: None,
        }
    }

    /// Convenience constructor for an error response.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            thumbprints: None,
            backup: None,
            error: Some(message.into()),
            code: Some(code.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_request_roundtrip() {
        let req = AdminRequest::ShowKeys {
            hash: "S256".to_string(),
        };
        let data = serde_json::to_vec(&req).unwrap();
        let parsed: AdminRequest = serde_json::from_slice(&data).unwrap();
        assert_eq!(req, parsed);

        let req = AdminRequest::BackupKeys {
            backend: "raw-file".to_string(),
            wrapping_key_file: "/tmp/wrap.key".to_string(),
            fido2_metadata_file: None,
            fido2_device: None,
            fido2_pin_file: None,
        };
        let data = serde_json::to_vec(&req).unwrap();
        let parsed: AdminRequest = serde_json::from_slice(&data).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_admin_response_roundtrip() {
        let resp = AdminResponse::ok_keys(vec!["abc".to_string()]);
        let data = serde_json::to_vec(&resp).unwrap();
        let parsed: AdminResponse = serde_json::from_slice(&data).unwrap();
        assert_eq!(resp, parsed);

        let resp = AdminResponse::ok_backup(vec![1, 2, 3]);
        let data = serde_json::to_vec(&resp).unwrap();
        let parsed: AdminResponse = serde_json::from_slice(&data).unwrap();
        assert_eq!(resp, parsed);
    }
}
