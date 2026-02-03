//! Lightweight debug logging for kunci core.
//!
//! Enabled by setting `KUNCI_LOG=1` in the environment.

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

/// Log level for structured logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Fine-grained tracing detail.
    Trace,
    /// Debug-level diagnostic output.
    Debug,
    /// Informational messages.
    Info,
    /// Warning-level diagnostics.
    Warn,
    /// Error-level diagnostics.
    Error,
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(format!("Unknown log level: {}", input)),
        }
    }
}

/// Logging configuration for core diagnostics.
#[derive(Debug, Clone)]
pub struct LogConfig {
    json: bool,
    level: LogLevel,
    modules: Option<HashSet<String>>,
}

impl LogConfig {
    /// Builds a new logging configuration.
    pub fn new(json: bool, level: LogLevel, modules: Option<HashSet<String>>) -> Self {
        Self { json, level, modules }
    }
}

static LOG_CONFIG: OnceLock<LogConfig> = OnceLock::new();

/// Initialize structured logging for the core crate.
pub fn init(config: LogConfig) {
    let _ = LOG_CONFIG.set(config);
}

fn env_config() -> Option<LogConfig> {
    let enabled = std::env::var_os("KUNCI_LOG").is_some()
        || std::env::var_os("KUNCI_LOG_JSON").is_some()
        || std::env::var_os("KUNCI_LOG_LEVEL").is_some()
        || std::env::var_os("KUNCI_LOG_MODULES").is_some();
    if !enabled {
        return None;
    }

    let level = std::env::var("KUNCI_LOG_LEVEL")
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or(LogLevel::Info);
    let modules = std::env::var("KUNCI_LOG_MODULES")
        .ok()
        .map(|val| {
            val.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<HashSet<_>>()
        })
        .filter(|set| !set.is_empty());

    Some(LogConfig::new(true, level, modules))
}

/// Returns true when logging is enabled.
pub fn enabled() -> bool {
    LOG_CONFIG.get().is_some() || env_config().is_some()
}

/// Emit a structured log entry for the given module.
pub fn log(module: &str, level: LogLevel, message: &str, fields: &[(&str, String)]) {
    let config = LOG_CONFIG.get().cloned().or_else(env_config);
    let Some(config) = config else {
        return;
    };

    if level < config.level {
        return;
    }

    if let Some(modules) = &config.modules {
        if !modules.contains(module) {
            return;
        }
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    if config.json {
        let mut field_map = Map::new();
        for (key, value) in fields {
            field_map.insert((*key).to_string(), Value::String(value.clone()));
        }
        let payload = json!({
            "ts": ts,
            "level": level.as_str(),
            "module": module,
            "msg": message,
            "fields": field_map,
        });
        eprintln!("{}", payload);
    } else {
        eprintln!("[{}] {} {} {}", ts, level.as_str(), module, message);
    }
}

/// Structured logging macro.
#[macro_export]
macro_rules! klog {
    (module: $module:expr, level: $level:expr, $fmt:literal $(, $args:expr)* $(; $($key:ident = $value:expr),* $(,)?)?) => {{
        let message = format!($fmt $(, $args)*);
        #[allow(unused_mut)]
        let mut fields: Vec<(&str, String)> = Vec::new();
        $(
            $(
                fields.push((stringify!($key), format!("{:?}", $value)));
            )*
        )?
        $crate::log::log($module, $level, &message, &fields);
    }};
}
