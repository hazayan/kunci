#![no_main]
use libfuzzer_sys::fuzz_target;

use kunci_core::jwk::Jwk;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Try to parse as a JWK
        let jwk_result = serde_json::from_str::<Jwk>(json_str);
        // If it parses, validate it
        if let Ok(jwk) = jwk_result {
            let _ = jwk.validate();
        }
        // Also try to parse as arbitrary JSON to see if it's valid JSON
        let _json_value: Result<Value, _> = serde_json::from_str(json_str);
    }
});
