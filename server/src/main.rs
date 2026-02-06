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

use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
};
use clap::Parser;
use kunci_core::{
    Result,
    admin::{AdminRequest, AdminResponse},
    tang::{RecoveryRequest, TangConfig, TangPolicy, TangServer},
};
use serde_json::json;
use tracing::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};

/// Command-line arguments for the Tang server.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to bind to (e.g., 127.0.0.1 or 0.0.0.0)
    #[arg(short = 'b', long, default_value = "127.0.0.1")]
    bind: String,

    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Directory containing JWK files
    #[arg(short, long, default_value = "/var/db/tang")]
    directory: PathBuf,

    /// Allow clients to request TOFU
    #[arg(long)]
    allow_tofu: bool,

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
    #[arg(long)]
    log_json: bool,
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
            kunci_core::Error::Config(_) => {
                HttpError::with_code(StatusCode::INTERNAL_SERVER_ERROR, "CONFIG_ERROR", err.to_string())
            }
            kunci_core::Error::Network(_) => {
                HttpError::with_code(StatusCode::BAD_GATEWAY, "NETWORK_ERROR", err.to_string())
            }
            kunci_core::Error::External(_) => {
                HttpError::with_code(StatusCode::INTERNAL_SERVER_ERROR, "EXTERNAL_ERROR", err.to_string())
            }
            kunci_core::Error::Crypto(_) => {
                HttpError::with_code(StatusCode::INTERNAL_SERVER_ERROR, "CRYPTO_ERROR", err.to_string())
            }
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
async fn get_policy(State(state): State<AppState>) -> std::result::Result<impl IntoResponse, HttpError> {
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

const ADMIN_MAX_REQUEST_BYTES: usize = 64 * 1024;

async fn run_admin_socket(path: PathBuf, allowed_gid: u32, state: AppState) -> Result<()> {
    if path.exists() {
        tokio::fs::remove_file(&path)
            .await
            .map_err(|e| kunci_core::Error::config(format!("Failed to remove admin socket: {}", e)))?;
    }
    let listener = UnixListener::bind(&path)
        .map_err(|e| kunci_core::Error::config(format!("Failed to bind admin socket: {}", e)))?;

    let mut perms = std::fs::metadata(&path)
        .map_err(|e| kunci_core::Error::config(format!("Failed to stat admin socket: {}", e)))?
        .permissions();
    perms.set_mode(0o660);
    std::fs::set_permissions(&path, perms)
        .map_err(|e| kunci_core::Error::config(format!("Failed to set admin socket perms: {}", e)))?;

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
        let bytes = serde_json::to_vec(&response)
            .map_err(|e| kunci_core::Error::config(format!("Admin response encode failed: {}", e)))?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|e| kunci_core::Error::config(format!("Admin response write failed: {}", e)))?;
        return Ok(());
    }

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| kunci_core::Error::config(format!("Admin read failed: {}", e)))?;
    if buf.len() > ADMIN_MAX_REQUEST_BYTES {
        let response = AdminResponse::error(
            "ADMIN_REQUEST_TOO_LARGE",
            "Admin request too large",
        );
        let bytes = serde_json::to_vec(&response)
            .map_err(|e| kunci_core::Error::config(format!("Admin response encode failed: {}", e)))?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|e| kunci_core::Error::config(format!("Admin response write failed: {}", e)))?;
        return Ok(());
    }

    let request: AdminRequest = match serde_json::from_slice(&buf) {
        Ok(req) => req,
        Err(_) => {
            let response = AdminResponse::error(
                "ADMIN_BAD_REQUEST",
                "Failed to parse admin request",
            );
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

    // Initialize logging
    let tracing_level = args
        .log_level
        .as_deref()
        .unwrap_or("info")
        .parse::<kunci_core::log::LogLevel>()
        .map_err(|e| kunci_core::Error::config(format!("Invalid --log-level: {}", e)))?;
    let use_json = args.log_json || std::env::var_os("KUNCI_LOG_JSON").is_some();
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

    init_core_logging(&args)?;

    info!("Starting Kunci Tang server");
    info!("Bind address: {}", args.bind);
    info!("Port: {}", args.port);
    info!("Key directory: {:?}", args.directory);
    info!("Allow TOFU: {}", args.allow_tofu);
    // Create Tang server instance
    let config = TangConfig::new(args.directory.to_string_lossy().into_owned())
        .with_allow_tofu(args.allow_tofu);
    let tang_server = TangServer::new(config)?;
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

    if let Some(admin_sock) = args.admin_sock.clone() {
        let admin_gid = args
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
    let bind_addr = format!("{}:{}", args.bind, args.port);
    let addr = bind_addr
        .to_socket_addrs()
        .map_err(|e| kunci_core::Error::config(format!("Failed to resolve {}: {}", bind_addr, e)))?
        .next()
        .ok_or_else(|| kunci_core::Error::config(format!("No socket addresses for {}", bind_addr)))?;

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

fn init_core_logging(args: &Args) -> Result<()> {
    use kunci_core::log::{LogConfig, LogLevel};
    use std::collections::HashSet;

    if args.log_level.is_none() && args.log_modules.is_none() {
        return Ok(());
    }

    let level = args
        .log_level
        .as_deref()
        .unwrap_or("info")
        .parse::<LogLevel>()
        .map_err(|e| kunci_core::Error::config(format!("Invalid --log-level: {}", e)))?;
    let modules = args.log_modules.as_ref().map(|value| {
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
        let response = client.post(url).json(&request).send().await.expect("request");
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
            handle_admin_client(server, allowed_gid, state).await.unwrap();
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
            handle_admin_client(server, allowed_gid, state).await.unwrap();
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
}
