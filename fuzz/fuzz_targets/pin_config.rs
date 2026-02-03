#![no_main]
use libfuzzer_sys::fuzz_target;

use kunci_core::remote::{RemoteDecryptConfig, RemoteEncryptConfig};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(value) = serde_json::from_str::<Value>(input) {
        let _ = serde_json::from_value::<RemoteEncryptConfig>(value.clone());
        let _ = serde_json::from_value::<RemoteDecryptConfig>(value);
    }
});
