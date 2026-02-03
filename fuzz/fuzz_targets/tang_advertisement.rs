#![no_main]
use libfuzzer_sys::fuzz_target;

use kunci_core::jwk::Jwk;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(payload) = kunci_core::jose::extract_jws_payload(input) {
        if let Ok(jwk_set) = serde_json::from_value::<kunci_core::jwk::JwkSet>(payload) {
            let _ = kunci_core::tang::util::validate_advertisement(&jwk_set);
        }
    }

    let _ = serde_json::from_str::<Value>(input);
    let _ = serde_json::from_str::<Jwk>(input);
});
