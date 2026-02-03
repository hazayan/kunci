//! Cryptsetup plugin for Kunci.
//!
//! This crate provides a cryptsetup token plugin for LUKS2 volumes encrypted with Clevis.
//! It implements the cryptsetup token interface to allow unlocking LUKS2 volumes using
//! Clevis/Tang decryption.
//!
//! The plugin is built as a cdylib and should be installed to the appropriate directory
//! (usually /usr/lib64/cryptsetup/libkunci.so) and registered with cryptsetup.

// This plugin is only available on Linux.
#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// Manual FFI bindings for libcryptsetup
#[allow(non_camel_case_types)]
type crypt_device = c_void;

const CRYPT_LOG_ERROR: c_int = 1;
const CRYPT_LOG_NORMAL: c_int = 2;
const CRYPT_LOG_DEBUG: c_int = 3;

unsafe extern "C" {
    pub fn crypt_log(cd: *mut crypt_device, level: c_int, msg: *const c_char);
    pub fn crypt_token_json_get(
        cd: *mut crypt_device,
        token: c_int,
        json: *mut *const c_char,
    ) -> c_int;
}

/// Version string for the token plugin.
static VERSION: &[u8] = b"0.1\0";

/// Get the version of the token plugin.
///
/// This function is called by cryptsetup to identify the plugin version.
/// # Safety
/// The function returns a pointer to a static null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cryptsetup_token_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

/// Open a token (decrypt the JWE and return the password).
///
/// This is the main function that decrypts the Clevis JWE and returns the passphrase.
/// # Safety
/// The function uses raw pointers and must handle null pointers and invalid data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cryptsetup_token_open(
    cd: *mut crypt_device,
    token_id: c_int,
    password: *mut *mut c_char,
    password_len: *mut usize,
    _usrptr: *mut c_void,
) -> c_int {
    unsafe { cryptsetup_token_open_pin(cd, token_id, ptr::null(), 0, password, password_len, _usrptr) }
}

/// Open a token with an optional PIN.
///
/// This function handles the actual decryption. The PIN is not used by Clevis tokens.
/// # Safety
/// The function uses raw pointers and must handle null pointers and invalid data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cryptsetup_token_open_pin(
    cd: *mut crypt_device,
    token_id: c_int,
    _pin: *const c_char,
    _pin_size: usize,
    password: *mut *mut c_char,
    password_len: *mut usize,
    _usrptr: *mut c_void,
) -> c_int {
    if cd.is_null() || password.is_null() || password_len.is_null() {
        return -libc::EINVAL;
    }

    // Get the token JSON from cryptsetup
    let mut cjson_ptr: *const c_char = ptr::null();
    let cerr = unsafe { crypt_token_json_get(cd, token_id, &mut cjson_ptr) };
    if cerr < 0 {
        let msg = CString::new("Failed to get token JSON").unwrap();
        unsafe { crypt_log(cd, CRYPT_LOG_ERROR, msg.as_ptr()) };
        return cerr;
    }

    // Convert to Rust string
    let json_str = unsafe { CStr::from_ptr(cjson_ptr).to_string_lossy() };

    // Parse the JSON and decrypt using kunci-core
    let json_value: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            let msg = CString::new(format!("Failed to parse token JSON: {}", e)).unwrap();
            unsafe { crypt_log(cd, CRYPT_LOG_ERROR, msg.as_ptr()) };
            return -libc::EINVAL;
        }
    };

    // Extract the JWE from the token (field "jwe" as in Go implementation)
    let jwe_value = match json_value.get("jwe") {
        Some(v) => v,
        None => {
            let msg = CString::new("Token JSON missing 'jwe' field").unwrap();
            unsafe { crypt_log(cd, CRYPT_LOG_ERROR, msg.as_ptr()) };
            return -libc::EINVAL;
        }
    };

    // Decrypt using kunci-core
    let plaintext = match kunci_core::decrypt(jwe_value) {
        Ok(p) => p,
        Err(e) => {
            let msg = CString::new(format!("Clevis decryption failed: {}", e)).unwrap();
            unsafe { crypt_log(cd, CRYPT_LOG_ERROR, msg.as_ptr()) };
            return -libc::EINVAL;
        }
    };

    // Store the length before moving plaintext
    let plaintext_len = plaintext.len();

    // Allocate memory for the password and copy the plaintext
    // The caller (cryptsetup) will free the password.
    let c_password = match CString::new(plaintext) {
        Ok(c) => c,
        Err(_) => return -libc::EINVAL,
    };
    let c_password_ptr = c_password.into_raw(); // This transfers ownership to C.
    unsafe {
        *password = c_password_ptr;
        *password_len = plaintext_len;
    }

    0
}

/// Dump token information (for debugging).
///
/// This function is called by `cryptsetup token dump`.
/// # Safety
/// The function uses raw pointers and must handle null pointers and invalid data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cryptsetup_token_dump(cd: *mut crypt_device, cjson: *const c_char) {
    if cd.is_null() || cjson.is_null() {
        return;
    }

    let json_str = unsafe { CStr::from_ptr(cjson).to_string_lossy() };
    let msg = CString::new(format!("Clevis Token (Kunci implementation): {}", json_str)).unwrap();
    unsafe { crypt_log(cd, CRYPT_LOG_NORMAL, msg.as_ptr()) };
}

/// Validate token configuration.
///
/// This function is called by cryptsetup when adding a token to validate the configuration.
/// # Safety
/// The function uses raw pointers and must handle null pointers and invalid data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cryptsetup_token_validate(
    cd: *mut crypt_device,
    cjson: *const c_char,
) -> c_int {
    if cd.is_null() || cjson.is_null() {
        return -libc::EINVAL;
    }

    let json_str = unsafe { CStr::from_ptr(cjson).to_string_lossy() };
    // For now, we just check if it's valid JSON. In the future, we can do more validation.
    if serde_json::from_str::<serde_json::Value>(&json_str).is_ok() {
        let msg = CString::new("Validated Clevis Token Config.").unwrap();
        unsafe { crypt_log(cd, CRYPT_LOG_DEBUG, msg.as_ptr()) };
        0
    } else {
        let msg = CString::new("Invalid JSON config.").unwrap();
        unsafe { crypt_log(cd, CRYPT_LOG_NORMAL, msg.as_ptr()) };
        -libc::EINVAL
    }
}
