use std::io;

/// The error type for the kunci-core library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error.
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Hexadecimal decoding error.
    #[error("Hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// Cryptographic operation error.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Key not found error.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Invalid key error.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Unsupported algorithm error.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Invalid thumbprint error.
    #[error("Invalid thumbprint: {0}")]
    InvalidThumbprint(String),

    /// Validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// HTTP error.
    #[error("HTTP error: {0}")]
    Http(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Network error.
    #[error("Network error: {0}")]
    Network(String),

    /// External command error.
    #[error("External command error: {0}")]
    External(String),

    /// Unknown error.
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl Error {
    /// Create a new cryptographic error with a message.
    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    /// Create a new key not found error.
    pub fn key_not_found(msg: impl Into<String>) -> Self {
        Self::KeyNotFound(msg.into())
    }

    /// Create a new invalid key error.
    pub fn invalid_key(msg: impl Into<String>) -> Self {
        Self::InvalidKey(msg.into())
    }

    /// Create a new unsupported algorithm error.
    pub fn unsupported_algorithm(msg: impl Into<String>) -> Self {
        Self::UnsupportedAlgorithm(msg.into())
    }

    /// Create a new validation error.
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    /// Create a new protocol error.
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Create a new HTTP error.
    pub fn http(msg: impl Into<String>) -> Self {
        Self::Http(msg.into())
    }

    /// Create a new configuration error.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create a new network error.
    pub fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }

    /// Create a new external command error.
    pub fn external(msg: impl Into<String>) -> Self {
        Self::External(msg.into())
    }
}

/// A specialized `Result` type for kunci-core operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn test_error_constructors() {
        assert!(Error::crypto("x").to_string().contains("Cryptographic error"));
        assert!(Error::key_not_found("x").to_string().contains("Key not found"));
        assert!(Error::invalid_key("x").to_string().contains("Invalid key"));
        assert!(Error::unsupported_algorithm("x").to_string().contains("Unsupported algorithm"));
        assert!(Error::validation("x").to_string().contains("Validation error"));
        assert!(Error::protocol("x").to_string().contains("Protocol error"));
        assert!(Error::http("x").to_string().contains("HTTP error"));
        assert!(Error::config("x").to_string().contains("Configuration error"));
        assert!(Error::network("x").to_string().contains("Network error"));
        assert!(Error::external("x").to_string().contains("External command error"));
    }
}
