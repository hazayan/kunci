//! Kunci Clevis client implementation in Rust.
//!
//! This is a reimplementation of the Clevis client in Rust.
//! It provides command-line tools for interacting with Tang servers
//! and performing pin-based encryption/decryption.
//!
//! # Commands
//!
//! - `fetch-adv` - Fetch and display a Tang server advertisement
//! - `recover` - Perform a recovery operation with a Tang server
//! - `encrypt` - Encrypt data using a configured pin
//!
//! - `decrypt` - Decrypt data using a configured pin

use std::error::Error;
use std::io::{Read, Write};

use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use kunci_core::tang::{RecoveryRequest, TangClient};

/// ZFS subcommands.
#[derive(Subcommand, Debug)]
enum ZfsCommands {
    /// Bind a Clevis pin to a ZFS dataset.
    Bind {
        /// ZFS dataset name (e.g., "pool/root")
        #[arg(short, long)]
        dataset: String,

        /// Pin name (e.g., "tang", "remote")
        #[arg(short, long)]
        pin: String,

        /// Pin configuration JSON string or file path
        #[arg(short, long)]
        config: String,

        /// Allow TOFU (trust on first use) for tang/remote pins
        #[arg(long)]
        trust: bool,
    },
    /// Unlock a ZFS dataset using a Clevis pin.
    Unlock {
        /// ZFS dataset name (e.g., "pool/root")
        #[arg(short, long)]
        dataset: String,

        /// Pin name (e.g., "tang", "remote") - optional, will be extracted from JWE if not provided
        #[arg(short, long)]
        pin: Option<String>,

        /// Pin configuration JSON string or file path - optional, required if pin is provided
        #[arg(short, long)]
        config: Option<String>,

        /// Allow TOFU (trust on first use) for tang/remote pins
        #[arg(long)]
        trust: bool,
    },
    /// Remove a Clevis binding from a ZFS dataset.
    Unbind {
        /// ZFS dataset name (e.g., "pool/root")
        #[arg(short, long)]
        dataset: String,
    },
    /// List ZFS datasets and their Clevis bindings.
    List,
}

/// Available commands.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Fetch and display the server advertisement.
    FetchAdv {
        /// Emit a Tang pin config JSON instead of raw advertisement
        #[arg(long)]
        as_config: bool,

        /// Allow TOFU (trust on first use) in emitted config
        #[arg(long)]
        trust: bool,
    },
    /// Perform a recovery operation.
    Recover {
        /// Thumbprint of the exchange key to use
        #[arg(short, long)]
        thumbprint: String,

        /// Path to the client JWK file (JSON format)
        #[arg(short, long)]
        client_jwk: String,

    },
    /// Encrypt data using a pin.
    Encrypt {
        /// Pin name (e.g., "tang", "sss", "null")
        #[arg(short, long)]
        pin: String,

        /// Pin configuration JSON string or file path
        #[arg(short, long)]
        config: String,

        /// Allow TOFU (trust on first use) for tang/remote pins
        #[arg(long)]
        trust: bool,

        /// Path to the input file (use '-' for stdin)
        #[arg(short, long, default_value = "-")]
        input: String,

        /// Path to the output file (use '-' for stdout)
        #[arg(short, long, default_value = "-")]
        output: String,
    },
    /// Decrypt data using a pin.
    Decrypt {
        /// Pin name (e.g., "tang", "sss", "null")
        #[arg(short, long)]
        pin: String,

        /// Pin configuration JSON string or file path (optional for some pins)
        #[arg(short, long)]
        config: Option<String>,

        /// Allow TOFU (trust on first use) for tang/remote pins
        #[arg(long)]
        trust: bool,

        /// Path to the input file (use '-' for stdin)
        #[arg(short, long, default_value = "-")]
        input: String,

        /// Path to the output file (use '-' for stdout)
        #[arg(short, long, default_value = "-")]
        output: String,
    },
    /// ZFS dataset encryption operations.
    Zfs {
        /// ZFS subcommand
        #[command(subcommand)]
        subcommand: ZfsCommands,
    },

    /// Show Tang signing key thumbprints via the local admin socket.
    ShowKeys {
        /// Path to the local admin Unix socket
        #[arg(long, default_value = "/var/run/kunci-admin.sock")]
        admin_sock: String,

        /// Hash algorithm to use for thumbprints (S1, S256, S384, S512)
        #[arg(long, default_value = "S256")]
        hash: String,
    },
}

/// Kunci Clevis client command-line interface.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Server URL (required for fetch-adv and recover)
    #[arg(short, long)]
    server: Option<String>,

    /// Core log level (trace|debug|info|warn|error)
    #[arg(long)]
    log_level: Option<String>,

    /// Comma-separated list of core modules to log (e.g., tang,zfs,remote)
    #[arg(long)]
    log_modules: Option<String>,

    /// Command to execute
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    use std::fs;
    use tracing::info;
    use std::io::Write;

    // Parse command-line arguments
    let cli = Cli::parse();
    let _ = writeln!(std::io::stderr(), "KUNCI_CLIENT_START");

    // Initialize logging
    let tracing_level = cli
        .log_level
        .as_deref()
        .unwrap_or("info")
        .parse::<kunci_core::log::LogLevel>()
        .map_err(|e| format!("Invalid --log-level: {}", e))?;
    tracing_subscriber::fmt()
        .with_max_level(map_tracing_level(tracing_level))
        .init();

    init_core_logging(&cli)?;

    match &cli.command {
        Commands::FetchAdv { as_config, trust } => {
            let server_url = cli
                .server
                .as_deref()
                .ok_or("Missing --server for fetch-adv")?
                .to_string();
            info!("Using server URL: {}", server_url);

            let client = TangClient::new(&server_url);

            info!("Fetching advertisement from server...");
            let advertisement = client.fetch_advertisement().await?;

            if *as_config {
                if *trust {
                    let config = serde_json::json!({
                        "tang": {
                            "adv": advertisement.jws,
                            "url": server_url,
                            "trust": true
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&config)?);
                    return Ok(());
                }
                let config = serde_json::json!({
                    "tang": {
                        "adv": advertisement.jws,
                        "url": server_url,
                    }
                });
                println!("{}", serde_json::to_string_pretty(&config)?);
                return Ok(());
            }
            if *trust {
                return Err("--trust requires --as-config".into());
            }

            println!("Advertisement JWS:");
            println!("{}", advertisement.jws);

            // Try to extract and display the payload
            match advertisement.extract_unverified() {
                Ok(jwk_set) => {
                    println!("\nUnverified payload (JWK Set):");
                    println!("{}", serde_json::to_string_pretty(&jwk_set)?);
                }
                Err(e) => {
                    eprintln!("Warning: Could not extract payload: {}", e);
                }
            }
        }
        Commands::Recover {
            thumbprint,
            client_jwk,
        } => {
            let server_url = cli
                .server
                .as_deref()
                .ok_or("Missing --server for recover")?
                .to_string();
            info!("Using server URL: {}", server_url);

            let client = TangClient::new(&server_url);

            // Read client JWK from file
            let jwk_content = fs::read_to_string(client_jwk)?;
            let client_jwk: kunci_core::jwk::Jwk = serde_json::from_str(&jwk_content)?;

            // Create recovery request
            let request = RecoveryRequest { jwk: client_jwk };

            info!("Performing recovery with thumbprint: {}", thumbprint);
            let response = client.recover(thumbprint, &request).await?;

            println!("Recovery response JWK:");
            println!("{}", serde_json::to_string_pretty(&response.jwk)?);
        }
        Commands::Encrypt {
            pin,
            config,
            trust,
            input,
            output,
        } => {
            // Load pin configuration (either a JSON string or a file path)
            let config_json = apply_trust_flag(load_config(config)?, pin, *trust)?;

            // Create pin registry and register available pins
            let mut registry = kunci_core::pin::PinRegistry::new();
            registry.register(Box::new(kunci_core::pin::NullPin::new()));
            registry.register(Box::new(kunci_core::pin::SssPin::new()));
            #[cfg(feature = "full")]
            registry.register(Box::new(kunci_core::pin::TangPin::new()));
            #[cfg(feature = "tpm2")]
            registry.register(Box::new(kunci_core::tpm2::Tpm2Pin::new()));
            registry.register(Box::new(kunci_core::remote::RemotePin::new()));

            // Get the pin
            let pin_instance = registry
                .get(pin)
                .ok_or_else(|| format!("Pin '{}' not found", pin))?;

            // Read input
            let plaintext = read_input(input)?;

            // Encrypt
            let ciphertext = pin_instance.encrypt(&config_json, &plaintext)?;

            // Write output
            write_output(output, &serde_json::to_vec(&ciphertext)?)?;
        }
        Commands::Decrypt {
            pin,
            config,
            trust,
            input,
            output,
        } => {
            // Load pin configuration if provided
            let config_json = if let Some(config_str) = config {
                apply_trust_flag(load_config(config_str)?, pin, *trust)?
            } else if *trust {
                return Err("--trust requires --config for decrypt".into());
            } else {
                serde_json::Value::Null
            };

            // Create pin registry and register available pins
            let mut registry = kunci_core::pin::PinRegistry::new();
            registry.register(Box::new(kunci_core::pin::NullPin::new()));
            registry.register(Box::new(kunci_core::pin::SssPin::new()));
            #[cfg(feature = "full")]
            registry.register(Box::new(kunci_core::pin::TangPin::new()));
            #[cfg(feature = "tpm2")]
            registry.register(Box::new(kunci_core::tpm2::Tpm2Pin::new()));
            registry.register(Box::new(kunci_core::remote::RemotePin::new()));

            // Get the pin
            let pin_instance = registry
                .get(pin)
                .ok_or_else(|| format!("Pin '{}' not found", pin))?;

            // Read input (should be JSON)
            let ciphertext_bytes = read_input(input)?;
            let ciphertext: serde_json::Value =
                serde_json::from_slice(&ciphertext_bytes).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid JSON: {}", e))
                })?;

            // Decrypt
            let plaintext = pin_instance.decrypt(&config_json, &ciphertext)?;

            // Write output
            write_output(output, &plaintext)?;
        }
        Commands::Zfs { subcommand } => {
            match subcommand {
                ZfsCommands::Bind { dataset, pin, config, trust } => {
                    let _ = writeln!(std::io::stderr(), "KUNCI_CLIENT_ZFS_BIND {}", dataset);
                    let config_json = apply_trust_flag(load_config(config)?, pin, *trust)?;
                    let wrapping_key = kunci_core::zfs::bind_zfs(dataset, pin, &config_json)?;
                    println!("Successfully bound pin '{}' to dataset '{}'", pin, dataset);
                    println!("Generated wrapping key (hex): {}", hex::encode(wrapping_key));
                }
                ZfsCommands::Unlock { dataset, pin, config, trust } => {
                    let _ = writeln!(std::io::stderr(), "KUNCI_CLIENT_ZFS_UNLOCK_START {}", dataset);
                    let config_json = if let Some(config_str) = config {
                        if *trust && pin.is_none() {
                            return Err("--trust requires --pin for zfs unlock".into());
                        }
                        let pin_name = pin.as_deref().unwrap_or("");
                        Some(apply_trust_flag(load_config(config_str)?, pin_name, *trust)?)
                    } else if *trust {
                        return Err("--trust requires --config for zfs unlock".into());
                    } else {
                        None
                    };
                    let pin_ref = pin.as_deref();
                    let _ = writeln!(std::io::stderr(), "KUNCI_CLIENT_ZFS_UNLOCK_CALL {}", dataset);
                    let wrapping_key = kunci_core::zfs::unlock_zfs(dataset, pin_ref, config_json.as_ref())?;
                    let _ = writeln!(std::io::stderr(), "KUNCI_CLIENT_ZFS_UNLOCK_OK {}", dataset);
                    println!("Successfully unlocked dataset '{}'", dataset);
                    println!("Loaded wrapping key (hex): {}", hex::encode(wrapping_key));
                }
                ZfsCommands::Unbind { dataset } => {
                    kunci_core::zfs::unbind_zfs(dataset)?;
                    println!("Successfully removed Clevis binding from dataset '{}'", dataset);
                }
                ZfsCommands::List => {
                    let datasets = kunci_core::zfs::list_zfs()?;
                    for dataset in datasets {
                        println!("Dataset: {}", dataset.name);
                        println!("  Encryption: {}", dataset.encryption.unwrap_or_else(|| "none".to_string()));
                        println!("  Key loaded: {}", dataset.loaded);
                        if let Some(jwe) = dataset.clevis_jwe {
                            println!("  Clevis bound: yes");
                            // Optionally display a snippet of the JWE
                            if jwe.len() > 50 {
                                println!("  JWE: {}...", &jwe[..50]);
                            } else {
                                println!("  JWE: {}", jwe);
                            }
                        } else {
                            println!("  Clevis bound: no");
                        }
                        println!();
                    }
                }
            }
        }
        Commands::ShowKeys { admin_sock, hash } => {
            let keys = admin_show_keys(admin_sock, hash).await?;
            for key in keys {
                println!("{}", key);
            }
        }
    }

    Ok(())
}

fn init_core_logging(cli: &Cli) -> Result<(), Box<dyn Error>> {
    use kunci_core::log::{LogConfig, LogLevel};
    use std::collections::HashSet;

    if cli.log_level.is_none() && cli.log_modules.is_none() {
        return Ok(());
    }

    let level = cli
        .log_level
        .as_deref()
        .unwrap_or("info")
        .parse::<LogLevel>()
        .map_err(|e| format!("Invalid --log-level: {}", e))?;
    let modules = cli.log_modules.as_ref().map(|value| {
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

/// Loads a configuration from a string that may be a JSON string or a file path.
fn load_config(config: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    // Try to parse as JSON first
    if let Ok(json) = serde_json::from_str(config) {
        return Ok(normalize_config(json));
    }
    // If that fails, try to read as a file
    let content = std::fs::read_to_string(config)?;
    let json = serde_json::from_str(&content)?;
    Ok(normalize_config(json))
}

fn normalize_config(json: serde_json::Value) -> serde_json::Value {
    let Some(obj) = json.as_object() else {
        return json;
    };
    if obj.contains_key("tang") {
        return json;
    }
    if obj.contains_key("payload") && obj.contains_key("signatures") {
        if let Ok(jws) = serde_json::to_string(&json) {
            return serde_json::json!({ "adv": jws });
        }
    }
    json
}

fn apply_trust_flag(
    config_json: serde_json::Value,
    pin: &str,
    trust: bool,
) -> Result<serde_json::Value, Box<dyn Error>> {
    if !trust {
        return Ok(config_json);
    }
    if pin != "tang" && pin != "remote" {
        return Err("--trust is only supported for tang or remote pins".into());
    }

    let pin_key = if pin == "tang" { "tang" } else { "remote" };
    let mut root = match config_json {
        serde_json::Value::Object(map) => map,
        _ => {
            return Err("--trust requires a JSON object config".into());
        }
    };

    if let Some(node) = root.get_mut(pin_key) {
        let map = node
            .as_object_mut()
            .ok_or_else(|| format!("'{}' config must be an object", pin_key))?;
        map.insert("trust".to_string(), serde_json::Value::Bool(true));
        return Ok(serde_json::Value::Object(root));
    }

    if let Some(clevis) = root.get_mut("clevis") {
        let clevis_map = clevis
            .as_object_mut()
            .ok_or_else(|| "clevis config must be an object".to_string())?;
        if let Some(node) = clevis_map.get_mut(pin_key) {
            let map = node
                .as_object_mut()
                .ok_or_else(|| format!("'{}' config must be an object", pin_key))?;
            map.insert("trust".to_string(), serde_json::Value::Bool(true));
            return Ok(serde_json::Value::Object(root));
        }
    }

    root.insert("trust".to_string(), serde_json::Value::Bool(true));
    Ok(serde_json::Value::Object(root))
}

async fn admin_show_keys(admin_sock: &str, hash: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut stream = tokio::net::UnixStream::connect(admin_sock).await?;
    let request = kunci_core::admin::AdminRequest::ShowKeys {
        hash: hash.to_string(),
    };
    let bytes = serde_json::to_vec(&request)?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await?;
    let response: kunci_core::admin::AdminResponse = serde_json::from_slice(&resp_bytes)?;
    if !response.ok {
        let msg = response.error.unwrap_or_else(|| "Admin request failed".to_string());
        return Err(msg.into());
    }
    Ok(response.thumbprints.unwrap_or_default())
}

/// Reads input from a file or stdin.
fn read_input(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if input == "-" {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        Ok(buffer)
    } else {
        std::fs::read(input).map_err(Into::into)
    }
}

/// Writes output to a file or stdout.
fn write_output(output: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
    if output == "-" {
        std::io::stdout().write_all(data)?;
        Ok(())
    } else {
        std::fs::write(output, data).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::{admin_show_keys, apply_trust_flag, normalize_config};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[test]
    fn test_normalize_config_preserves_tang_node() {
        let cfg = json!({
            "tang": { "adv": "adv", "url": "http://example" }
        });
        let normalized = normalize_config(cfg.clone());
        assert_eq!(normalized, cfg);
    }

    #[test]
    fn test_normalize_config_wraps_raw_adv_json() {
        let adv = json!({
            "payload": "abc",
            "signatures": []
        });
        let normalized = normalize_config(adv);
        assert!(normalized.get("adv").is_some());
    }

    #[test]
    fn test_apply_trust_flag_sets_tang_top_level() {
        let cfg = json!({
            "adv": "adv",
            "url": "http://example"
        });
        let updated = apply_trust_flag(cfg, "tang", true).unwrap();
        assert_eq!(updated.get("trust").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn test_apply_trust_flag_sets_remote_nested() {
        let cfg = json!({
            "clevis": {
                "remote": {
                    "adv": "adv",
                    "port": 7420
                }
            }
        });
        let updated = apply_trust_flag(cfg, "remote", true).unwrap();
        let trust = updated
            .get("clevis")
            .and_then(|v| v.get("remote"))
            .and_then(|v| v.get("trust"))
            .and_then(|v| v.as_bool());
        assert_eq!(trust, Some(true));
    }

    #[test]
    fn test_apply_trust_flag_rejects_non_tang_remote() {
        let cfg = json!({ "pin": "sss" });
        let err = apply_trust_flag(cfg, "sss", true).unwrap_err();
        assert!(err.to_string().contains("only supported"));
    }

    #[tokio::test]
    async fn test_admin_show_keys_happy_path() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let sock_path = tempdir.path().join("admin.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.expect("read");
            let request: kunci_core::admin::AdminRequest =
                serde_json::from_slice(&buf).expect("request");
            match request {
                kunci_core::admin::AdminRequest::ShowKeys { hash } => {
                    assert_eq!(hash, "S256");
                }
            }
            let response = kunci_core::admin::AdminResponse::ok_keys(vec!["abc".to_string()]);
            let bytes = serde_json::to_vec(&response).expect("resp");
            stream.write_all(&bytes).await.expect("write");
        });

        let keys = admin_show_keys(sock_path.to_str().unwrap(), "S256")
            .await
            .unwrap();
        assert_eq!(keys, vec!["abc"]);
        server_task.await.unwrap();
    }
}
