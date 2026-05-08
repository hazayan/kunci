//! Tang server implementation in Rust.
//!
//! This is a reimplementation of the Tang server in Rust.
//! It provides HTTP endpoints for key advertisement and recovery
//! using the McCallum-Relyea exchange.
//!
//! # Endpoints
//!
//! - `GET /adv` - Get advertisement (JWS-signed JWK Set)
//! - `GET /adv/{thumbprint}` - Get advertisement signed with specific key
//! - `POST /rec/{thumbprint}` - Perform recovery (McCallum-Relyea exchange)
//!
//! # Usage
//!
//! ```sh
//! kunci-server --port 8080 --directory /var/db/tang
//! ```

use std::os::unix::fs::PermissionsExt;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::{fs, net::ToSocketAddrs};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use kunci_core::{
    Result,
    admin::{AdminRequest, AdminResponse},
    fido2::{
        Fido2CredentialMetadata, Fido2EnrollOptions, Fido2UserVerification,
        Fido2WrappingKeyProvider, default_metadata_file, enroll_fido2_credential, read_pin_file,
    },
    keys::{
        EncryptedBundleKeyBackend, FilesystemKeyBackend, RawFileWrappingKeyProvider,
        ServerKeyBackend,
    },
    tang::{RecoveryRequest, TangConfig, TangPolicy, TangServer},
};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tracing::info;

/// Command-line arguments for the Tang server.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// JSON configuration file path
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,

    /// Address to bind to (e.g., 127.0.0.1 or 0.0.0.0)
    #[arg(short = 'b', long)]
    bind: Option<String>,

    /// Port to listen on
    #[arg(short, long)]
    port: Option<u16>,

    /// Directory containing JWK files
    #[arg(short, long)]
    directory: Option<PathBuf>,

    /// Allow clients to request TOFU
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = false)]
    allow_tofu: Option<bool>,

    /// Path to the local admin Unix socket (enables admin commands)
    #[arg(long)]
    admin_sock: Option<PathBuf>,

    /// GID allowed to access the admin socket
    #[arg(long)]
    admin_gid: Option<u32>,

    /// Core log level (trace|debug|info|warn|error)
    #[arg(long)]
    log_level: Option<String>,

    /// Comma-separated list of core modules to log (e.g., tang,zfs,remote)
    #[arg(long)]
    log_modules: Option<String>,

    /// Emit JSON logs for server tracing output
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = false)]
    log_json: Option<bool>,

    /// Server key backend (filesystem, encrypted-bundle, or fido2)
    #[arg(long)]
    key_backend: Option<String>,

    /// Raw 32-byte wrapping key file for encrypted-bundle backend
    #[arg(long)]
    wrapping_key_file: Option<PathBuf>,

    /// FIDO2 credential metadata file
    #[arg(long)]
    fido2_metadata_file: Option<PathBuf>,

    /// FIDO2 device path or auto
    #[arg(long)]
    fido2_device: Option<String>,

    /// FIDO2 PIN file
    #[arg(long)]
    fido2_pin_file: Option<PathBuf>,

    /// Command to execute
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Server key management commands.
    Key {
        /// Key command to execute.
        #[command(subcommand)]
        command: KeyCommands,
    },
}

#[derive(Subcommand, Debug)]
enum KeyCommands {
    /// Initialize an empty key backend.
    Init(KeyCommandArgs),
    /// Migrate keys from one backend to another.
    Migrate(KeyMigrateArgs),
    /// Validate that a key backend can be unlocked and loaded.
    UnlockTest(KeyCommandArgs),
    /// Restore a key backend from an encrypted backup artifact.
    Restore(KeyRestoreArgs),
    /// Enroll a FIDO2 hmac-secret credential.
    Fido2Enroll(Fido2EnrollArgs),
}

#[derive(clap::Args, Debug)]
struct KeyCommandArgs {
    /// Backend to operate on (filesystem, encrypted-bundle, or fido2)
    #[arg(long)]
    backend: Option<String>,

    /// Key directory or encrypted bundle directory
    #[arg(long)]
    directory: Option<PathBuf>,

    /// Raw 32-byte wrapping key file for encrypted-bundle backend
    #[arg(long)]
    wrapping_key_file: Option<PathBuf>,

    /// FIDO2 credential metadata file
    #[arg(long)]
    fido2_metadata_file: Option<PathBuf>,

    /// FIDO2 device path or auto
    #[arg(long)]
    fido2_device: Option<String>,

    /// FIDO2 PIN file
    #[arg(long)]
    fido2_pin_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct KeyMigrateArgs {
    /// Source backend (currently filesystem)
    #[arg(long)]
    from: String,

    /// Destination backend (currently encrypted-bundle)
    #[arg(long)]
    to: String,

    /// Source key directory
    #[arg(long)]
    source_directory: PathBuf,

    /// Destination key directory or encrypted bundle directory
    #[arg(long)]
    directory: Option<PathBuf>,

    /// Raw 32-byte wrapping key file for encrypted-bundle backend
    #[arg(long)]
    wrapping_key_file: Option<PathBuf>,

    /// FIDO2 credential metadata file for destination backend
    #[arg(long)]
    fido2_metadata_file: Option<PathBuf>,

    /// FIDO2 device path or auto
    #[arg(long)]
    fido2_device: Option<String>,

    /// FIDO2 PIN file
    #[arg(long)]
    fido2_pin_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct KeyRestoreArgs {
    /// Backup artifact to restore.
    #[arg(long)]
    input: PathBuf,

    /// Destination key directory or encrypted bundle directory.
    #[arg(long)]
    directory: Option<PathBuf>,

    /// Raw 32-byte wrapping key file for encrypted-bundle backend.
    #[arg(long)]
    wrapping_key_file: Option<PathBuf>,

    /// FIDO2 credential metadata file for destination backend.
    #[arg(long)]
    fido2_metadata_file: Option<PathBuf>,

    /// FIDO2 device path or auto.
    #[arg(long)]
    fido2_device: Option<String>,

    /// FIDO2 PIN file.
    #[arg(long)]
    fido2_pin_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct Fido2EnrollArgs {
    /// Output FIDO2 credential metadata file.
    #[arg(long)]
    metadata_file: Option<PathBuf>,

    /// Key directory used to resolve the default metadata file.
    #[arg(long)]
    directory: Option<PathBuf>,

    /// FIDO2 device path or auto.
    #[arg(long)]
    device: Option<String>,

    /// Relying-party ID.
    #[arg(long, default_value = "kunci-server.local")]
    rp_id: String,

    /// Relying-party display name.
    #[arg(long, default_value = "Kunci Server")]
    rp_name: String,

    /// Credential user name.
    #[arg(long, default_value = "kunci-server")]
    user_name: String,

    /// Credential user display name.
    #[arg(long, default_value = "Kunci Server")]
    user_display_name: String,

    /// User verification policy (discouraged, required, or omit).
    #[arg(long, default_value = "discouraged")]
    uv: String,

    /// Require user presence for unlock.
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = false)]
    up: Option<bool>,

    /// FIDO2 PIN file.
    #[arg(long)]
    pin_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    bind: Option<String>,
    port: Option<u16>,
    directory: Option<PathBuf>,
    #[serde(alias = "allow-tofu")]
    allow_tofu: Option<bool>,
    #[serde(alias = "admin-sock")]
    admin_sock: Option<PathBuf>,
    #[serde(alias = "admin-gid")]
    admin_gid: Option<u32>,
    #[serde(alias = "log-level")]
    log_level: Option<String>,
    #[serde(alias = "log-modules")]
    log_modules: Option<String>,
    #[serde(alias = "log-json")]
    log_json: Option<bool>,
    #[serde(alias = "key-backend")]
    key_backend: Option<String>,
    #[serde(alias = "wrapping-key-file")]
    wrapping_key_file: Option<PathBuf>,
    encrypted_bundle: Option<EncryptedBundleFileConfig>,
    fido2: Option<Fido2FileConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct EncryptedBundleFileConfig {
    #[serde(alias = "wrapping-key-file")]
    wrapping_key_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct Fido2FileConfig {
    #[serde(alias = "metadata-file")]
    metadata_file: Option<PathBuf>,
    device: Option<String>,
    #[serde(alias = "pin-file")]
    pin_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyBackendKind {
    Filesystem,
    EncryptedBundle,
    Fido2,
}

impl KeyBackendKind {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "filesystem" => Ok(Self::Filesystem),
            "encrypted-bundle" | "encrypted_bundle" => Ok(Self::EncryptedBundle),
            "fido2" => Ok(Self::Fido2),
            _ => Err(kunci_core::Error::config(format!(
                "Unsupported key backend: {}",
                value
            ))),
        }
    }
}

#[derive(Debug, Clone)]
struct ServerConfig {
    bind: String,
    port: u16,
    directory: PathBuf,
    key_backend: KeyBackendKind,
    wrapping_key_file: Option<PathBuf>,
    fido2_metadata_file: Option<PathBuf>,
    fido2_device: Option<String>,
    fido2_pin_file: Option<PathBuf>,
    allow_tofu: bool,
    admin_sock: Option<PathBuf>,
    admin_gid: Option<u32>,
    log_level: Option<String>,
    log_modules: Option<String>,
    log_json: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".to_string(),
            port: 8080,
            directory: PathBuf::from("/var/db/tang"),
            key_backend: KeyBackendKind::Filesystem,
            wrapping_key_file: None,
            fido2_metadata_file: None,
            fido2_device: None,
            fido2_pin_file: None,
            allow_tofu: false,
            admin_sock: None,
            admin_gid: None,
            log_level: None,
            log_modules: None,
            log_json: false,
        }
    }
}

impl ServerConfig {
    fn from_args(args: &Args) -> Result<Self> {
        let mut config = if let Some(path) = &args.config {
            Self::from_file(path)?
        } else {
            Self::default()
        };

        if let Some(bind) = &args.bind {
            config.bind = bind.clone();
        }
        if let Some(port) = args.port {
            config.port = port;
        }
        if let Some(directory) = &args.directory {
            config.directory = directory.clone();
        }
        if let Some(key_backend) = &args.key_backend {
            config.key_backend = KeyBackendKind::parse(key_backend)?;
        }
        if let Some(wrapping_key_file) = &args.wrapping_key_file {
            config.wrapping_key_file = Some(wrapping_key_file.clone());
        }
        if let Some(fido2_metadata_file) = &args.fido2_metadata_file {
            config.fido2_metadata_file = Some(fido2_metadata_file.clone());
        }
        if let Some(fido2_device) = &args.fido2_device {
            config.fido2_device = Some(fido2_device.clone());
        }
        if let Some(fido2_pin_file) = &args.fido2_pin_file {
            config.fido2_pin_file = Some(fido2_pin_file.clone());
        }
        if let Some(allow_tofu) = args.allow_tofu {
            config.allow_tofu = allow_tofu;
        }
        if let Some(admin_sock) = &args.admin_sock {
            config.admin_sock = Some(admin_sock.clone());
        }
        if let Some(admin_gid) = args.admin_gid {
            config.admin_gid = Some(admin_gid);
        }
        if let Some(log_level) = &args.log_level {
            config.log_level = Some(log_level.clone());
        }
        if let Some(log_modules) = &args.log_modules {
            config.log_modules = Some(log_modules.clone());
        }
        if let Some(log_json) = args.log_json {
            config.log_json = log_json;
        }

        Ok(config)
    }

    fn from_file(path: &FsPath) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            kunci_core::Error::config(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        let file_config: FileConfig = serde_json::from_str(&content).map_err(|e| {
            kunci_core::Error::config(format!(
                "Failed to parse config file {}: {}",
                path.display(),
                e
            ))
        })?;

        let mut config = Self::default();
        if let Some(bind) = file_config.bind {
            config.bind = bind;
        }
        if let Some(port) = file_config.port {
            config.port = port;
        }
        if let Some(directory) = file_config.directory {
            config.directory = directory;
        }
        if let Some(key_backend) = file_config.key_backend {
            config.key_backend = KeyBackendKind::parse(&key_backend)?;
        }
        if let Some(wrapping_key_file) = file_config.wrapping_key_file {
            config.wrapping_key_file = Some(wrapping_key_file);
        }
        if let Some(encrypted_bundle) = file_config.encrypted_bundle {
            if let Some(wrapping_key_file) = encrypted_bundle.wrapping_key_file {
                config.wrapping_key_file = Some(wrapping_key_file);
            }
        }
        if let Some(fido2) = file_config.fido2 {
            if let Some(metadata_file) = fido2.metadata_file {
                config.fido2_metadata_file = Some(metadata_file);
            }
            if let Some(device) = fido2.device {
                config.fido2_device = Some(device);
            }
            if let Some(pin_file) = fido2.pin_file {
                config.fido2_pin_file = Some(pin_file);
            }
        }
        if let Some(allow_tofu) = file_config.allow_tofu {
            config.allow_tofu = allow_tofu;
        }
        if let Some(admin_sock) = file_config.admin_sock {
            config.admin_sock = Some(admin_sock);
        }
        if let Some(admin_gid) = file_config.admin_gid {
            config.admin_gid = Some(admin_gid);
        }
        if let Some(log_level) = file_config.log_level {
            config.log_level = Some(log_level);
        }
        if let Some(log_modules) = file_config.log_modules {
            config.log_modules = Some(log_modules);
        }
        if let Some(log_json) = file_config.log_json {
            config.log_json = log_json;
        }

        Ok(config)
    }
}

/// Server state shared across all handlers.
#[derive(Clone)]
struct AppState {
    tang_server: Arc<TangServer>,
}

/// HTTP response type for errors.
#[derive(Debug)]
struct HttpError {
    status: StatusCode,
    message: String,
    code: Option<String>,
}

impl HttpError {
    fn with_code(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            code: Some(code.into()),
        }
    }

    fn internal_error(message: impl Into<String>) -> Self {
        Self::with_code(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("tang http error: {} {}", self.status, self.message);
        let body = Json(json!({
            "error": self.message,
            "code": self.code,
        }));
        (self.status, body).into_response()
    }
}

impl From<kunci_core::Error> for HttpError {
    fn from(err: kunci_core::Error) -> Self {
        match err {
            kunci_core::Error::KeyNotFound(_) => {
                HttpError::with_code(StatusCode::NOT_FOUND, "KEY_NOT_FOUND", err.to_string())
            }
            kunci_core::Error::InvalidKey(_) => {
                HttpError::with_code(StatusCode::BAD_REQUEST, "INVALID_KEY", err.to_string())
            }
            kunci_core::Error::Validation(_) => {
                HttpError::with_code(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", err.to_string())
            }
            kunci_core::Error::Protocol(_) => {
                HttpError::with_code(StatusCode::BAD_REQUEST, "PROTOCOL_ERROR", err.to_string())
            }
            kunci_core::Error::UnsupportedAlgorithm(_) => HttpError::with_code(
                StatusCode::BAD_REQUEST,
                "UNSUPPORTED_ALGORITHM",
                err.to_string(),
            ),
            kunci_core::Error::Http(_) => {
                HttpError::with_code(StatusCode::BAD_GATEWAY, "HTTP_ERROR", err.to_string())
            }
            kunci_core::Error::Config(_) => HttpError::with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CONFIG_ERROR",
                err.to_string(),
            ),
            kunci_core::Error::Network(_) => {
                HttpError::with_code(StatusCode::BAD_GATEWAY, "NETWORK_ERROR", err.to_string())
            }
            kunci_core::Error::External(_) => HttpError::with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "EXTERNAL_ERROR",
                err.to_string(),
            ),
            kunci_core::Error::Crypto(_) => HttpError::with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CRYPTO_ERROR",
                err.to_string(),
            ),
            _ => HttpError::internal_error(err.to_string()),
        }
    }
}

/// Handler for GET /adv
async fn get_advertisement(
    State(state): State<AppState>,
) -> std::result::Result<impl IntoResponse, HttpError> {
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Info,
        "get_adv";
        path = "/adv"
    );
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Debug,
        "get_adv_start"
    );
    let advertisement = state.tang_server.get_advertisement()?;
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Debug,
        "get_adv_ok";
        jws_len = advertisement.jws.len()
    );
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "application/jose+json".parse().unwrap());
    Ok((headers, advertisement.jws))
}

/// Handler for GET /adv/{thumbprint}
async fn get_advertisement_with_key(
    State(state): State<AppState>,
    Path(thumbprint): Path<String>,
) -> std::result::Result<impl IntoResponse, HttpError> {
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Info,
        "get_adv_key";
        kid = thumbprint.clone()
    );
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Debug,
        "get_adv_key_start";
        kid = thumbprint.clone()
    );
    let advertisement = state.tang_server.get_advertisement_with_key(&thumbprint)?;
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Debug,
        "get_adv_key_ok";
        kid = thumbprint.clone(),
        jws_len = advertisement.jws.len()
    );
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "application/jose+json".parse().unwrap());
    Ok((headers, advertisement.jws))
}

/// Handler for POST /rec/{thumbprint}
async fn post_recovery(
    State(state): State<AppState>,
    Path(thumbprint): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RecoveryRequest>,
) -> std::result::Result<impl IntoResponse, HttpError> {
    // Validate the request before processing
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Debug,
        "post_rec_start";
        kid = thumbprint.clone()
    );
    request.validate()?;

    let tofu_requested = headers
        .get("X-Kunci-Trust")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("tofu"))
        .unwrap_or(false);
    if tofu_requested && !state.tang_server.config().allow_tofu {
        kunci_core::klog!(
            module: "http",
            level: kunci_core::log::LogLevel::Warn,
            "post_rec_tofu_refused";
            kid = thumbprint.clone()
        );
        return Err(HttpError::with_code(
            StatusCode::FORBIDDEN,
            "TOFU_DISALLOWED",
            "TOFU request refused by server policy",
        ));
    }

    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Info,
        "post_rec";
        kid = thumbprint.clone()
    );

    let has_key = state
        .tang_server
        .key_store()
        .find_exchange_key(&thumbprint)?
        .is_some();
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Debug,
        "post_rec_key";
        kid = thumbprint.clone(),
        exchange_key_present = has_key
    );

    let response = state.tang_server.recover(&thumbprint, &request)?;
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "application/jwk+json".parse().unwrap());
    let response_len = serde_json::to_vec(&response)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Debug,
        "post_rec_ok";
        kid = thumbprint.clone(),
        response_len = response_len
    );
    Ok((headers, Json(response)))
}

/// Handler for GET /policy
async fn get_policy(
    State(state): State<AppState>,
) -> std::result::Result<impl IntoResponse, HttpError> {
    let policy = TangPolicy {
        allow_tofu: state.tang_server.config().allow_tofu,
    };
    Ok(Json(policy))
}

async fn fallback(req: Request<Body>) -> impl IntoResponse {
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Warn,
        "fallback";
        method = req.method().to_string(),
        path = req.uri().to_string()
    );
    (StatusCode::NOT_FOUND, Json(json!({ "error": "Not Found" })))
}

async fn request_log(req: Request<Body>, next: Next) -> impl IntoResponse {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let content_length = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    kunci_core::klog!(
        module: "http",
        level: kunci_core::log::LogLevel::Info,
        "request";
        method = req.method().to_string(),
        path = req.uri().to_string(),
        host = host,
        content_type = content_type,
        content_length = content_length
    );
    next.run(req).await
}

/// Handler for GET / (root)
async fn root() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Not Found")
}

/// Create the Tang router.
fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/adv", get(get_advertisement))
        .route("/adv/{thumbprint}", get(get_advertisement_with_key))
        .route("/rec/{thumbprint}", post(post_recovery))
        .route("/policy", get(get_policy))
        .route("/", get(root))
        .fallback(fallback)
        .with_state(state)
        .layer(middleware::from_fn(request_log))
}

fn encrypted_bundle_backend(
    directory: &FsPath,
    wrapping_key_file: &FsPath,
) -> EncryptedBundleKeyBackend<RawFileWrappingKeyProvider> {
    EncryptedBundleKeyBackend::new(
        directory.to_path_buf(),
        RawFileWrappingKeyProvider::new(wrapping_key_file.to_path_buf()),
    )
}

fn fido2_bundle_backend(
    directory: &FsPath,
    metadata_file: &FsPath,
    device: Option<String>,
    pin_file: Option<&FsPath>,
) -> Result<EncryptedBundleKeyBackend<Fido2WrappingKeyProvider>> {
    let pin = pin_file.map(read_pin_file).transpose()?;
    let provider = Fido2WrappingKeyProvider::from_metadata_file(metadata_file, device, pin)?;
    Ok(EncryptedBundleKeyBackend::new(
        directory.to_path_buf(),
        provider,
    ))
}

fn encrypted_backup_artifact(
    tang_server: &TangServer,
    backend: &str,
    wrapping_key_file: Option<&FsPath>,
    fido2_metadata_file: Option<&FsPath>,
    fido2_device: Option<String>,
    fido2_pin_file: Option<&FsPath>,
) -> Result<Vec<u8>> {
    match backend {
        "raw-file" => {
            let wrapping_key_file = wrapping_key_file.ok_or_else(|| {
                kunci_core::Error::config("Missing wrapping_key_file for raw-file backup backend")
            })?;
            let backend = encrypted_bundle_backend(FsPath::new("."), wrapping_key_file);
            backend.backup_store(tang_server.key_store())
        }
        "fido2" => {
            let metadata_file = fido2_metadata_file.ok_or_else(|| {
                kunci_core::Error::config("Missing fido2_metadata_file for fido2 backup backend")
            })?;
            let backend = fido2_bundle_backend(
                FsPath::new("."),
                metadata_file,
                fido2_device,
                fido2_pin_file,
            )?;
            backend.backup_store(tang_server.key_store())
        }
        _ => Err(kunci_core::Error::config(format!(
            "Unsupported backup backend: {}",
            backend
        ))),
    }
}

fn load_tang_server(config: &ServerConfig) -> Result<TangServer> {
    let tang_config = TangConfig::new(config.directory.to_string_lossy().into_owned())
        .with_allow_tofu(config.allow_tofu);

    match config.key_backend {
        KeyBackendKind::Filesystem => TangServer::new(tang_config),
        KeyBackendKind::EncryptedBundle => {
            let wrapping_key_file = config.wrapping_key_file.as_deref().ok_or_else(|| {
                kunci_core::Error::config(
                    "Missing wrapping_key_file for encrypted-bundle key backend",
                )
            })?;
            let backend = encrypted_bundle_backend(&config.directory, wrapping_key_file);
            TangServer::from_backend(tang_config, &backend)
        }
        KeyBackendKind::Fido2 => {
            let metadata_file = config.fido2_metadata_file.as_deref().ok_or_else(|| {
                kunci_core::Error::config("Missing fido2_metadata_file for fido2 key backend")
            })?;
            let backend = fido2_bundle_backend(
                &config.directory,
                metadata_file,
                config.fido2_device.clone(),
                config.fido2_pin_file.as_deref(),
            )?;
            TangServer::from_backend(tang_config, &backend)
        }
    }
}

fn run_key_command(base_config: &ServerConfig, command: &KeyCommands) -> Result<()> {
    match command {
        KeyCommands::Init(args) => {
            let config = key_command_config(base_config, args)?;
            match config.key_backend {
                KeyBackendKind::Filesystem => {
                    let backend = FilesystemKeyBackend::new(&config.directory);
                    backend.create_if_empty()?;
                }
                KeyBackendKind::EncryptedBundle => {
                    let wrapping_key_file =
                        config.wrapping_key_file.as_deref().ok_or_else(|| {
                            kunci_core::Error::config(
                                "Missing --wrapping-key-file for encrypted-bundle key init",
                            )
                        })?;
                    let backend = encrypted_bundle_backend(&config.directory, wrapping_key_file)
                        .with_auto_create(true);
                    backend.create_if_empty()?;
                }
                KeyBackendKind::Fido2 => {
                    let metadata_file = fido2_metadata_file_or_default(&config);
                    let backend = fido2_bundle_backend(
                        &config.directory,
                        &metadata_file,
                        config.fido2_device.clone(),
                        config.fido2_pin_file.as_deref(),
                    )?
                    .with_auto_create(true);
                    backend.create_if_empty()?;
                }
            }
            println!("initialized key backend at {}", config.directory.display());
            Ok(())
        }
        KeyCommands::UnlockTest(args) => {
            let config = key_command_config(base_config, args)?;
            let server = load_tang_server(&config)?;
            println!(
                "loaded key backend at {} with {} active keys and {} signing keys",
                config.directory.display(),
                server.key_store().key_count(),
                server.key_store().signing_key_count()
            );
            Ok(())
        }
        KeyCommands::Migrate(args) => run_key_migrate(base_config, args),
        KeyCommands::Restore(args) => run_key_restore(base_config, args),
        KeyCommands::Fido2Enroll(args) => run_fido2_enroll(base_config, args),
    }
}

fn key_command_config(base_config: &ServerConfig, args: &KeyCommandArgs) -> Result<ServerConfig> {
    let mut config = base_config.clone();
    if let Some(backend) = &args.backend {
        config.key_backend = KeyBackendKind::parse(backend)?;
    }
    if let Some(directory) = &args.directory {
        config.directory = directory.clone();
    }
    if let Some(wrapping_key_file) = &args.wrapping_key_file {
        config.wrapping_key_file = Some(wrapping_key_file.clone());
    }
    if let Some(fido2_metadata_file) = &args.fido2_metadata_file {
        config.fido2_metadata_file = Some(fido2_metadata_file.clone());
    }
    if let Some(fido2_device) = &args.fido2_device {
        config.fido2_device = Some(fido2_device.clone());
    }
    if let Some(fido2_pin_file) = &args.fido2_pin_file {
        config.fido2_pin_file = Some(fido2_pin_file.clone());
    }
    Ok(config)
}

fn run_key_migrate(base_config: &ServerConfig, args: &KeyMigrateArgs) -> Result<()> {
    let from = KeyBackendKind::parse(&args.from)?;
    let to = KeyBackendKind::parse(&args.to)?;
    if from != KeyBackendKind::Filesystem {
        return Err(kunci_core::Error::config(
            "Only filesystem source migration is currently supported",
        ));
    }

    let directory = args
        .directory
        .clone()
        .unwrap_or_else(|| base_config.directory.clone());
    match to {
        KeyBackendKind::Filesystem => {
            return Err(kunci_core::Error::config(
                "Filesystem destination migration is not supported",
            ));
        }
        KeyBackendKind::EncryptedBundle => {
            let wrapping_key_file = args
                .wrapping_key_file
                .as_deref()
                .or(base_config.wrapping_key_file.as_deref())
                .ok_or_else(|| {
                    kunci_core::Error::config(
                        "Missing --wrapping-key-file for encrypted-bundle key migration",
                    )
                })?;
            let backend = encrypted_bundle_backend(&directory, wrapping_key_file);
            backend.migrate_from_filesystem(&args.source_directory)?;
        }
        KeyBackendKind::Fido2 => {
            let metadata_file = args
                .fido2_metadata_file
                .as_deref()
                .or(base_config.fido2_metadata_file.as_deref())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_metadata_file(&directory));
            let device = args
                .fido2_device
                .clone()
                .or_else(|| base_config.fido2_device.clone());
            let pin_file = args
                .fido2_pin_file
                .as_deref()
                .or(base_config.fido2_pin_file.as_deref());
            let backend = fido2_bundle_backend(&directory, &metadata_file, device, pin_file)?;
            backend.migrate_from_filesystem(&args.source_directory)?;
        }
    }
    println!(
        "migrated filesystem keys from {} to {:?} backend at {}",
        args.source_directory.display(),
        to,
        directory.display()
    );
    Ok(())
}

fn run_key_restore(base_config: &ServerConfig, args: &KeyRestoreArgs) -> Result<()> {
    let directory = args
        .directory
        .clone()
        .unwrap_or_else(|| base_config.directory.clone());
    let artifact = fs::read(&args.input).map_err(|e| {
        kunci_core::Error::config(format!(
            "Failed to read backup artifact {}: {}",
            args.input.display(),
            e
        ))
    })?;
    match base_config.key_backend {
        KeyBackendKind::Filesystem | KeyBackendKind::EncryptedBundle => {
            let wrapping_key_file = args
                .wrapping_key_file
                .as_deref()
                .or(base_config.wrapping_key_file.as_deref())
                .ok_or_else(|| {
                    kunci_core::Error::config(
                        "Missing --wrapping-key-file for encrypted-bundle restore",
                    )
                })?;
            let backend = encrypted_bundle_backend(&directory, wrapping_key_file);
            backend.restore_backup_to_bundle(&artifact)?;
        }
        KeyBackendKind::Fido2 => {
            let metadata_file = args
                .fido2_metadata_file
                .as_deref()
                .or(base_config.fido2_metadata_file.as_deref())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_metadata_file(&directory));
            let device = args
                .fido2_device
                .clone()
                .or_else(|| base_config.fido2_device.clone());
            let pin_file = args
                .fido2_pin_file
                .as_deref()
                .or(base_config.fido2_pin_file.as_deref());
            let backend = fido2_bundle_backend(&directory, &metadata_file, device, pin_file)?;
            backend.restore_backup_to_bundle(&artifact)?;
        }
    }
    println!(
        "restored encrypted backup {} to encrypted bundle at {}",
        args.input.display(),
        directory.display()
    );
    Ok(())
}

fn run_fido2_enroll(base_config: &ServerConfig, args: &Fido2EnrollArgs) -> Result<()> {
    let directory = args
        .directory
        .clone()
        .unwrap_or_else(|| base_config.directory.clone());
    let metadata_file = args
        .metadata_file
        .clone()
        .or_else(|| base_config.fido2_metadata_file.clone())
        .unwrap_or_else(|| default_metadata_file(&directory));
    let pin = args.pin_file.as_deref().map(read_pin_file).transpose()?;
    let options = Fido2EnrollOptions {
        device: args
            .device
            .clone()
            .or_else(|| base_config.fido2_device.clone()),
        rp_id: args.rp_id.clone(),
        rp_name: args.rp_name.clone(),
        user_name: args.user_name.clone(),
        user_display_name: args.user_display_name.clone(),
        uv: Fido2UserVerification::parse(&args.uv)?,
        up: args.up.unwrap_or(true),
        pin,
    };
    let metadata: Fido2CredentialMetadata = enroll_fido2_credential(&options)?;
    metadata.save(&metadata_file)?;
    println!(
        "enrolled FIDO2 hmac-secret credential metadata at {}",
        metadata_file.display()
    );
    Ok(())
}

fn fido2_metadata_file_or_default(config: &ServerConfig) -> PathBuf {
    config
        .fido2_metadata_file
        .clone()
        .unwrap_or_else(|| default_metadata_file(&config.directory))
}

const ADMIN_MAX_REQUEST_BYTES: usize = 64 * 1024;

async fn run_admin_socket(path: PathBuf, allowed_gid: u32, state: AppState) -> Result<()> {
    if path.exists() {
        tokio::fs::remove_file(&path).await.map_err(|e| {
            kunci_core::Error::config(format!("Failed to remove admin socket: {}", e))
        })?;
    }
    let listener = UnixListener::bind(&path)
        .map_err(|e| kunci_core::Error::config(format!("Failed to bind admin socket: {}", e)))?;

    let mut perms = std::fs::metadata(&path)
        .map_err(|e| kunci_core::Error::config(format!("Failed to stat admin socket: {}", e)))?
        .permissions();
    perms.set_mode(0o660);
    std::fs::set_permissions(&path, perms).map_err(|e| {
        kunci_core::Error::config(format!("Failed to set admin socket perms: {}", e))
    })?;

    let gid = nix::unistd::Gid::from_raw(allowed_gid);
    nix::unistd::chown(&path, None, Some(gid))
        .map_err(|e| kunci_core::Error::config(format!("Failed to chown admin socket: {}", e)))?;

    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .map_err(|e| kunci_core::Error::config(format!("Admin socket accept failed: {}", e)))?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_admin_client(stream, allowed_gid, state).await {
                tracing::error!("admin socket error: {}", err);
            }
        });
    }
}

async fn handle_admin_client(
    mut stream: UnixStream,
    allowed_gid: u32,
    state: AppState,
) -> Result<()> {
    let peer_gid = peer_gid(&stream)?;
    if peer_gid != allowed_gid {
        let response = AdminResponse::error(
            "ADMIN_FORBIDDEN",
            format!("Peer GID {} not allowed", peer_gid),
        );
        let bytes = serde_json::to_vec(&response).map_err(|e| {
            kunci_core::Error::config(format!("Admin response encode failed: {}", e))
        })?;
        stream.write_all(&bytes).await.map_err(|e| {
            kunci_core::Error::config(format!("Admin response write failed: {}", e))
        })?;
        return Ok(());
    }

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| kunci_core::Error::config(format!("Admin read failed: {}", e)))?;
    if buf.len() > ADMIN_MAX_REQUEST_BYTES {
        let response = AdminResponse::error("ADMIN_REQUEST_TOO_LARGE", "Admin request too large");
        let bytes = serde_json::to_vec(&response).map_err(|e| {
            kunci_core::Error::config(format!("Admin response encode failed: {}", e))
        })?;
        stream.write_all(&bytes).await.map_err(|e| {
            kunci_core::Error::config(format!("Admin response write failed: {}", e))
        })?;
        return Ok(());
    }

    let request: AdminRequest = match serde_json::from_slice(&buf) {
        Ok(req) => req,
        Err(_) => {
            let response =
                AdminResponse::error("ADMIN_BAD_REQUEST", "Failed to parse admin request");
            let bytes = serde_json::to_vec(&response).map_err(|e| {
                kunci_core::Error::config(format!("Admin response encode failed: {}", e))
            })?;
            stream.write_all(&bytes).await.map_err(|e| {
                kunci_core::Error::config(format!("Admin response write failed: {}", e))
            })?;
            return Ok(());
        }
    };

    let response = match request {
        AdminRequest::ShowKeys { hash } => {
            let hash = hash.as_str();
            match hash {
                "S1" | "S224" | "S256" | "S384" | "S512" => {
                    let mut keys = Vec::new();
                    for key in &state.tang_server.key_store().signing_keys {
                        if let Ok(tp) = key.thumbprint(hash) {
                            keys.push(tp);
                        }
                    }
                    AdminResponse::ok_keys(keys)
                }
                _ => AdminResponse::error(
                    "ADMIN_UNSUPPORTED_HASH",
                    format!("Unsupported hash algorithm: {}", hash),
                ),
            }
        }
        AdminRequest::BackupKeys {
            backend,
            wrapping_key_file,
            fido2_metadata_file,
            fido2_device,
            fido2_pin_file,
        } => match encrypted_backup_artifact(
            &state.tang_server,
            &backend,
            if wrapping_key_file.is_empty() {
                None
            } else {
                Some(FsPath::new(&wrapping_key_file))
            },
            fido2_metadata_file.as_deref().map(FsPath::new),
            fido2_device,
            fido2_pin_file.as_deref().map(FsPath::new),
        ) {
            Ok(artifact) => AdminResponse::ok_backup(artifact),
            Err(err) => AdminResponse::error("ADMIN_BACKUP_FAILED", err.to_string()),
        },
    };

    let bytes = serde_json::to_vec(&response)
        .map_err(|e| kunci_core::Error::config(format!("Admin response encode failed: {}", e)))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| kunci_core::Error::config(format!("Admin response write failed: {}", e)))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn peer_gid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let creds = getsockopt(stream, PeerCredentials)
        .map_err(|e| kunci_core::Error::config(format!("Failed to read peer creds: {}", e)))?;
    Ok(creds.gid())
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
fn peer_gid(stream: &UnixStream) -> Result<u32> {
    use std::os::unix::io::AsRawFd;

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(kunci_core::Error::config(format!(
            "Failed to read peer creds: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(gid as u32)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "macos"
)))]
fn peer_gid(_stream: &UnixStream) -> Result<u32> {
    Err(kunci_core::Error::config(
        "Peer credential lookup not supported on this platform",
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();
    let config = ServerConfig::from_args(&args)?;

    if let Some(Commands::Key { command }) = &args.command {
        return run_key_command(&config, command);
    }

    // Initialize logging
    let tracing_level = config
        .log_level
        .as_deref()
        .unwrap_or("info")
        .parse::<kunci_core::log::LogLevel>()
        .map_err(|e| kunci_core::Error::config(format!("Invalid --log-level: {}", e)))?;
    let use_json = config.log_json || std::env::var_os("KUNCI_LOG_JSON").is_some();
    if use_json {
        tracing_subscriber::fmt()
            .with_max_level(map_tracing_level(tracing_level))
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(map_tracing_level(tracing_level))
            .init();
    }

    init_core_logging(&config)?;

    info!("Starting Kunci Tang server");
    info!("Bind address: {}", config.bind);
    info!("Port: {}", config.port);
    info!("Key directory: {:?}", config.directory);
    info!("Key backend: {:?}", config.key_backend);
    info!("Allow TOFU: {}", config.allow_tofu);
    // Create Tang server instance
    let tang_server = load_tang_server(&config)?;
    let exchange_keys: Vec<String> = tang_server
        .key_store()
        .keys
        .iter()
        .filter(|jwk| jwk.has_op("deriveKey") && jwk.alg() == Some("ECMR"))
        .filter_map(|jwk| jwk.thumbprint("S256").ok())
        .collect();
    info!("Exchange key thumbprints: {:?}", exchange_keys);
    let state = AppState {
        tang_server: Arc::new(tang_server),
    };

    if let Some(admin_sock) = config.admin_sock.clone() {
        let admin_gid = config
            .admin_gid
            .ok_or_else(|| kunci_core::Error::config("Missing --admin-gid for admin socket"))?;
        let state_clone = state.clone();
        info!("Admin socket: {:?}", admin_sock);
        info!("Admin GID: {}", admin_gid);
        tokio::spawn(async move {
            if let Err(err) = run_admin_socket(admin_sock, admin_gid, state_clone).await {
                tracing::error!("admin socket failed: {}", err);
            }
        });
    }

    // Create router
    let router = create_router(state);

    // Resolve socket address (allows IPs or hostnames).
    let bind_addr = format!("{}:{}", config.bind, config.port);
    let addr = bind_addr
        .to_socket_addrs()
        .map_err(|e| kunci_core::Error::config(format!("Failed to resolve {}: {}", bind_addr, e)))?
        .next()
        .ok_or_else(|| {
            kunci_core::Error::config(format!("No socket addresses for {}", bind_addr))
        })?;

    info!("Server listening on {}", addr);

    // Start server
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| kunci_core::Error::config(format!("Failed to bind to {}: {}", addr, e)))?;

    axum::serve(listener, router)
        .await
        .map_err(|e| kunci_core::Error::config(format!("Server error: {}", e)))?;

    Ok(())
}

fn init_core_logging(config: &ServerConfig) -> Result<()> {
    use kunci_core::log::{LogConfig, LogLevel};
    use std::collections::HashSet;

    if config.log_level.is_none() && config.log_modules.is_none() {
        return Ok(());
    }

    let level = config
        .log_level
        .as_deref()
        .unwrap_or("info")
        .parse::<LogLevel>()
        .map_err(|e| kunci_core::Error::config(format!("Invalid --log-level: {}", e)))?;
    let modules = config.log_modules.as_ref().map(|value| {
        value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>()
    });
    let config = LogConfig::new(true, level, modules);
    kunci_core::log::init(config);
    Ok(())
}

fn map_tracing_level(level: kunci_core::log::LogLevel) -> tracing::Level {
    match level {
        kunci_core::log::LogLevel::Trace => tracing::Level::TRACE,
        kunci_core::log::LogLevel::Debug => tracing::Level::DEBUG,
        kunci_core::log::LogLevel::Info => tracing::Level::INFO,
        kunci_core::log::LogLevel::Warn => tracing::Level::WARN,
        kunci_core::log::LogLevel::Error => tracing::Level::ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kunci_core::{crypto, jwk::Jwk};
    use reqwest::Client;
    use serde_json::Value;
    use std::net::SocketAddr;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UnixStream};
    use tokio::task::JoinHandle;

    struct TestServer {
        addr: SocketAddr,
        handle: JoinHandle<()>,
        _tempdir: TempDir,
        tang_server: Arc<TangServer>,
    }

    fn network_tests_enabled() -> bool {
        std::env::var("KUNCI_TEST_NETWORK").is_ok()
    }

    fn is_exchange_key(jwk: &Jwk) -> bool {
        match jwk {
            Jwk::EC(ec_jwk) => ec_jwk
                .key_ops
                .as_ref()
                .map(|ops| ops.iter().any(|op| op == "deriveKey"))
                .unwrap_or(false),
            _ => false,
        }
    }

    #[test]
    fn test_server_config_defaults() {
        let args = Args::parse_from(["kunci-server"]);
        let config = ServerConfig::from_args(&args).expect("config");

        assert_eq!(config.bind, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert_eq!(config.directory, PathBuf::from("/var/db/tang"));
        assert_eq!(config.key_backend, KeyBackendKind::Filesystem);
        assert!(config.wrapping_key_file.is_none());
        assert!(config.fido2_metadata_file.is_none());
        assert!(config.fido2_device.is_none());
        assert!(config.fido2_pin_file.is_none());
        assert!(!config.allow_tofu);
        assert!(config.admin_sock.is_none());
        assert!(config.admin_gid.is_none());
        assert!(config.log_level.is_none());
        assert!(config.log_modules.is_none());
        assert!(!config.log_json);
    }

    #[test]
    fn test_server_config_from_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config_path = tempdir.path().join("kunci-server.json");
        std::fs::write(
            &config_path,
            r#"{
                "bind": "0.0.0.0",
                "port": 7420,
                "directory": "/tmp/kunci-keys",
                "key_backend": "encrypted-bundle",
                "encrypted_bundle": {
                    "wrapping_key_file": "/tmp/kunci-wrap.key"
                },
                "allow_tofu": true,
                "admin_sock": "/run/kunci/admin.sock",
                "admin_gid": 42,
                "log_level": "debug",
                "log_modules": "tang,zfs",
                "log_json": true
            }"#,
        )
        .expect("write config");

        let args = Args::parse_from(["kunci-server", "--config", config_path.to_str().unwrap()]);
        let config = ServerConfig::from_args(&args).expect("config");

        assert_eq!(config.bind, "0.0.0.0");
        assert_eq!(config.port, 7420);
        assert_eq!(config.directory, PathBuf::from("/tmp/kunci-keys"));
        assert_eq!(config.key_backend, KeyBackendKind::EncryptedBundle);
        assert_eq!(
            config.wrapping_key_file,
            Some(PathBuf::from("/tmp/kunci-wrap.key"))
        );
        assert!(config.allow_tofu);
        assert_eq!(
            config.admin_sock,
            Some(PathBuf::from("/run/kunci/admin.sock"))
        );
        assert_eq!(config.admin_gid, Some(42));
        assert_eq!(config.log_level.as_deref(), Some("debug"));
        assert_eq!(config.log_modules.as_deref(), Some("tang,zfs"));
        assert!(config.log_json);
    }

    #[test]
    fn test_server_config_file_accepts_kebab_case() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config_path = tempdir.path().join("kunci-server.json");
        std::fs::write(
            &config_path,
            r#"{
                "allow-tofu": true,
                "admin-sock": "/run/kunci/admin.sock",
                "admin-gid": 42,
                "log-level": "trace",
                "log-modules": "tang",
                "log-json": true,
                "key-backend": "encrypted-bundle",
                "wrapping-key-file": "/tmp/kunci-wrap.key"
            }"#,
        )
        .expect("write config");

        let args = Args::parse_from(["kunci-server", "--config", config_path.to_str().unwrap()]);
        let config = ServerConfig::from_args(&args).expect("config");

        assert!(config.allow_tofu);
        assert_eq!(
            config.admin_sock,
            Some(PathBuf::from("/run/kunci/admin.sock"))
        );
        assert_eq!(config.admin_gid, Some(42));
        assert_eq!(config.log_level.as_deref(), Some("trace"));
        assert_eq!(config.log_modules.as_deref(), Some("tang"));
        assert!(config.log_json);
        assert_eq!(config.key_backend, KeyBackendKind::EncryptedBundle);
        assert_eq!(
            config.wrapping_key_file,
            Some(PathBuf::from("/tmp/kunci-wrap.key"))
        );
    }

    #[test]
    fn test_server_config_accepts_fido2_config() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config_path = tempdir.path().join("kunci-server.json");
        std::fs::write(
            &config_path,
            r#"{
                "directory": "/tmp/kunci-keys",
                "key_backend": "fido2",
                "fido2": {
                    "metadata-file": "/etc/kunci/fido2-credential.json",
                    "device": "auto",
                    "pin-file": "/run/kunci/fido2.pin"
                }
            }"#,
        )
        .expect("write config");

        let args = Args::parse_from(["kunci-server", "--config", config_path.to_str().unwrap()]);
        let config = ServerConfig::from_args(&args).expect("config");

        assert_eq!(config.directory, PathBuf::from("/tmp/kunci-keys"));
        assert_eq!(config.key_backend, KeyBackendKind::Fido2);
        assert_eq!(
            config.fido2_metadata_file,
            Some(PathBuf::from("/etc/kunci/fido2-credential.json"))
        );
        assert_eq!(config.fido2_device.as_deref(), Some("auto"));
        assert_eq!(
            config.fido2_pin_file,
            Some(PathBuf::from("/run/kunci/fido2.pin"))
        );
    }

    #[test]
    fn test_server_config_cli_overrides_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config_path = tempdir.path().join("kunci-server.json");
        std::fs::write(
            &config_path,
            r#"{
                "bind": "0.0.0.0",
                "port": 7420,
                "directory": "/tmp/file-keys",
                "log_level": "info"
            }"#,
        )
        .expect("write config");

        let args = Args::parse_from([
            "kunci-server",
            "--config",
            config_path.to_str().unwrap(),
            "--bind",
            "127.0.0.2",
            "--port",
            "9000",
            "--directory",
            "/tmp/cli-keys",
            "--key-backend",
            "encrypted-bundle",
            "--wrapping-key-file",
            "/tmp/cli-wrap.key",
            "--fido2-metadata-file",
            "/tmp/fido2.json",
            "--fido2-device",
            "auto",
            "--fido2-pin-file",
            "/tmp/fido2.pin",
            "--allow-tofu=false",
            "--log-level",
            "debug",
            "--log-json=false",
        ]);
        let config = ServerConfig::from_args(&args).expect("config");

        assert_eq!(config.bind, "127.0.0.2");
        assert_eq!(config.port, 9000);
        assert_eq!(config.directory, PathBuf::from("/tmp/cli-keys"));
        assert_eq!(config.key_backend, KeyBackendKind::EncryptedBundle);
        assert_eq!(
            config.wrapping_key_file,
            Some(PathBuf::from("/tmp/cli-wrap.key"))
        );
        assert_eq!(
            config.fido2_metadata_file,
            Some(PathBuf::from("/tmp/fido2.json"))
        );
        assert_eq!(config.fido2_device.as_deref(), Some("auto"));
        assert_eq!(config.fido2_pin_file, Some(PathBuf::from("/tmp/fido2.pin")));
        assert!(!config.allow_tofu);
        assert_eq!(config.log_level.as_deref(), Some("debug"));
        assert!(!config.log_json);
    }

    #[test]
    fn test_key_init_unlock_and_migrate_encrypted_bundle() {
        let plaintext_dir = tempfile::tempdir().expect("plaintext dir");
        let bundle_dir = tempfile::tempdir().expect("bundle dir");
        let migrated_dir = tempfile::tempdir().expect("migrated dir");
        let restored_dir = tempfile::tempdir().expect("restored dir");
        let key_file = tempfile::NamedTempFile::new().expect("key file");
        let backup_file = tempfile::NamedTempFile::new().expect("backup file");
        std::fs::write(key_file.path(), [42u8; 32]).expect("write key");

        let base = ServerConfig::default();
        let init = KeyCommandArgs {
            backend: Some("encrypted-bundle".to_string()),
            directory: Some(bundle_dir.path().to_path_buf()),
            wrapping_key_file: Some(key_file.path().to_path_buf()),
            fido2_metadata_file: None,
            fido2_device: None,
            fido2_pin_file: None,
        };
        run_key_command(&base, &KeyCommands::Init(init)).expect("init encrypted bundle");
        assert!(bundle_dir.path().join("keystore.bundle.json").exists());

        let unlock = KeyCommandArgs {
            backend: Some("encrypted-bundle".to_string()),
            directory: Some(bundle_dir.path().to_path_buf()),
            wrapping_key_file: Some(key_file.path().to_path_buf()),
            fido2_metadata_file: None,
            fido2_device: None,
            fido2_pin_file: None,
        };
        run_key_command(&base, &KeyCommands::UnlockTest(unlock)).expect("unlock encrypted bundle");

        let filesystem = FilesystemKeyBackend::new(plaintext_dir.path());
        filesystem.create_if_empty().expect("create plaintext keys");
        let migrate = KeyMigrateArgs {
            from: "filesystem".to_string(),
            to: "encrypted-bundle".to_string(),
            source_directory: plaintext_dir.path().to_path_buf(),
            directory: Some(migrated_dir.path().to_path_buf()),
            wrapping_key_file: Some(key_file.path().to_path_buf()),
            fido2_metadata_file: None,
            fido2_device: None,
            fido2_pin_file: None,
        };
        run_key_command(&base, &KeyCommands::Migrate(migrate)).expect("migrate keys");
        assert!(migrated_dir.path().join("keystore.bundle.json").exists());

        let migrated_backend = encrypted_bundle_backend(migrated_dir.path(), key_file.path());
        let migrated_store = migrated_backend.load().expect("load migrated store");
        let backup = migrated_backend
            .backup_store(&migrated_store)
            .expect("backup store");
        std::fs::write(backup_file.path(), backup).expect("write backup");
        let restore = KeyRestoreArgs {
            input: backup_file.path().to_path_buf(),
            directory: Some(restored_dir.path().to_path_buf()),
            wrapping_key_file: Some(key_file.path().to_path_buf()),
            fido2_metadata_file: None,
            fido2_device: None,
            fido2_pin_file: None,
        };
        run_key_command(&base, &KeyCommands::Restore(restore)).expect("restore backup");
        assert!(restored_dir.path().join("keystore.bundle.json").exists());
    }

    #[test]
    fn test_load_tang_server_from_encrypted_bundle() {
        let bundle_dir = tempfile::tempdir().expect("bundle dir");
        let key_file = tempfile::NamedTempFile::new().expect("key file");
        std::fs::write(key_file.path(), [43u8; 32]).expect("write key");

        let mut config = ServerConfig::default();
        config.directory = bundle_dir.path().to_path_buf();
        config.key_backend = KeyBackendKind::EncryptedBundle;
        config.wrapping_key_file = Some(key_file.path().to_path_buf());

        let init = KeyCommandArgs {
            backend: Some("encrypted-bundle".to_string()),
            directory: Some(bundle_dir.path().to_path_buf()),
            wrapping_key_file: Some(key_file.path().to_path_buf()),
            fido2_metadata_file: None,
            fido2_device: None,
            fido2_pin_file: None,
        };
        run_key_command(&ServerConfig::default(), &KeyCommands::Init(init))
            .expect("init encrypted bundle");

        let server = load_tang_server(&config).expect("load server");
        assert_eq!(server.key_store().key_count(), 2);
        assert_eq!(server.key_store().signing_key_count(), 1);
    }

    async fn start_test_server() -> TestServer {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = TangConfig::new(tempdir.path().to_string_lossy().into_owned());
        let tang_server = Arc::new(TangServer::new(config).expect("tang server"));
        let state = AppState {
            tang_server: tang_server.clone(),
        };

        let router = create_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, router).await {
                eprintln!("server error: {}", err);
            }
        });

        TestServer {
            addr,
            handle,
            _tempdir: tempdir,
            tang_server,
        }
    }

    #[tokio::test]
    async fn test_get_adv_returns_jws() {
        if !network_tests_enabled() {
            return;
        }
        let server = start_test_server().await;
        let client = Client::new();
        let url = format!("http://{}/adv", server.addr);
        let response = client.get(url).send().await.expect("request");
        assert!(response.status().is_success());

        let body = response.text().await.expect("body");
        let payload: Value = serde_json::from_str(&body).expect("json");
        assert!(payload.get("payload").and_then(Value::as_str).is_some());

        server.handle.abort();
    }

    #[tokio::test]
    async fn test_get_adv_with_key_returns_jws() {
        if !network_tests_enabled() {
            return;
        }
        let server = start_test_server().await;
        let signing_key = server
            .tang_server
            .key_store()
            .signing_keys
            .first()
            .expect("signing key");
        let thumbprint = signing_key.thumbprint("S256").expect("thumbprint");

        let client = Client::new();
        let url = format!("http://{}/adv/{}", server.addr, thumbprint);
        let response = client.get(url).send().await.expect("request");
        assert!(response.status().is_success());

        let body = response.text().await.expect("body");
        let payload: Value = serde_json::from_str(&body).expect("json");
        assert!(payload.get("payload").and_then(Value::as_str).is_some());

        server.handle.abort();
    }

    #[tokio::test]
    async fn test_post_recovery_returns_jwk() {
        if !network_tests_enabled() {
            return;
        }
        let server = start_test_server().await;
        let exchange_key = server
            .tang_server
            .key_store()
            .keys
            .iter()
            .find(|key| is_exchange_key(key))
            .expect("exchange key");
        let thumbprint = exchange_key.thumbprint("S256").expect("thumbprint");
        let request = RecoveryRequest {
            jwk: crypto::generate_key("ECMR").expect("client key"),
        };

        let client = Client::new();
        let url = format!("http://{}/rec/{}", server.addr, thumbprint);
        let response = client
            .post(url)
            .json(&request)
            .send()
            .await
            .expect("request");
        assert!(response.status().is_success());

        let payload: Value = response.json().await.expect("json");
        let kty = payload.get("kty").and_then(Value::as_str).unwrap_or("");
        assert!(!kty.is_empty());

        server.handle.abort();
    }

    #[tokio::test]
    async fn test_admin_socket_rejects_wrong_gid() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = TangConfig::new(tempdir.path().to_string_lossy().into_owned());
        let tang_server = Arc::new(TangServer::new(config).expect("tang server"));
        let state = AppState { tang_server };

        let (client, server) = UnixStream::pair().expect("pair");
        let allowed_gid = nix::unistd::getgid().as_raw().saturating_add(1);

        let server_task = tokio::spawn(async move {
            handle_admin_client(server, allowed_gid, state)
                .await
                .unwrap();
        });

        let (mut read_half, _write_half) = client.into_split();
        let mut resp_bytes = Vec::new();
        read_half.read_to_end(&mut resp_bytes).await.unwrap();
        let response: AdminResponse = serde_json::from_slice(&resp_bytes).unwrap();
        assert!(!response.ok);
        assert_eq!(response.code.as_deref(), Some("ADMIN_FORBIDDEN"));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_admin_socket_returns_keys() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = TangConfig::new(tempdir.path().to_string_lossy().into_owned());
        let tang_server = Arc::new(TangServer::new(config).expect("tang server"));
        let state = AppState { tang_server };

        let (client, server) = UnixStream::pair().expect("pair");
        let allowed_gid = nix::unistd::getgid().as_raw();

        let server_task = tokio::spawn(async move {
            handle_admin_client(server, allowed_gid, state)
                .await
                .unwrap();
        });

        let request = AdminRequest::ShowKeys {
            hash: "S256".to_string(),
        };
        let (mut read_half, mut write_half) = client.into_split();
        write_half
            .write_all(&serde_json::to_vec(&request).unwrap())
            .await
            .unwrap();
        drop(write_half);

        let mut resp_bytes = Vec::new();
        read_half.read_to_end(&mut resp_bytes).await.unwrap();
        let response: AdminResponse = serde_json::from_slice(&resp_bytes).unwrap();
        assert!(response.ok);
        assert!(response.thumbprints.unwrap_or_default().len() > 0);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_admin_socket_returns_encrypted_backup() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let key_file = tempfile::NamedTempFile::new().expect("key file");
        std::fs::write(key_file.path(), [44u8; 32]).expect("write key");
        let config = TangConfig::new(tempdir.path().to_string_lossy().into_owned());
        let tang_server = Arc::new(TangServer::new(config).expect("tang server"));
        let state = AppState {
            tang_server: tang_server.clone(),
        };

        let (client, server) = UnixStream::pair().expect("pair");
        let allowed_gid = nix::unistd::getgid().as_raw();

        let server_task = tokio::spawn(async move {
            handle_admin_client(server, allowed_gid, state)
                .await
                .unwrap();
        });

        let request = AdminRequest::BackupKeys {
            backend: "raw-file".to_string(),
            wrapping_key_file: key_file.path().to_string_lossy().into_owned(),
            fido2_metadata_file: None,
            fido2_device: None,
            fido2_pin_file: None,
        };
        let (mut read_half, mut write_half) = client.into_split();
        write_half
            .write_all(&serde_json::to_vec(&request).unwrap())
            .await
            .unwrap();
        drop(write_half);

        let mut resp_bytes = Vec::new();
        read_half.read_to_end(&mut resp_bytes).await.unwrap();
        let response: AdminResponse = serde_json::from_slice(&resp_bytes).unwrap();
        assert!(response.ok);
        let backup = response.backup.expect("backup artifact");
        let backend = encrypted_bundle_backend(tempdir.path(), key_file.path());
        let restored = backend.restore_backup(&backup).expect("restore backup");
        assert_eq!(restored.key_count(), tang_server.key_store().key_count());
        assert_eq!(
            restored.signing_key_count(),
            tang_server.key_store().signing_key_count()
        );

        server_task.await.unwrap();
    }
}
