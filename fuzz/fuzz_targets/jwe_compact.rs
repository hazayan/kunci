#![no_main]
use libfuzzer_sys::fuzz_target;

use kunci_core::zfs;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(json) = zfs::convert_jwe_compact_to_json(input) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) {
            let _ = zfs::convert_jwe_json_to_compact(&value);
        }
    }
});
