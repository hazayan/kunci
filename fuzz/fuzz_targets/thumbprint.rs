#![no_main]
use libfuzzer_sys::fuzz_target;

use kunci_core::jwk::Jwk;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(jwk) = serde_json::from_str::<Jwk>(input) {
        let _ = jwk.thumbprint("S256");
        let _ = jwk.thumbprint("S1");
    }

    let _ = serde_json::from_str::<Value>(input);
});
