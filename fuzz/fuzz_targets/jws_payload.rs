#![no_main]
use libfuzzer_sys::fuzz_target;

use kunci_core::jose;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let _ = jose::extract_jws_payload(input);
    let _ = serde_json::from_str::<Value>(input);
});
