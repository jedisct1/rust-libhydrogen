//! Key derivation
//!
//! Multiple secret subkeys can be derived from a single, high-entropy master key.
//!
//! With the master key and a key identifier, a subkey can be deterministically computed.
//! However, given a subkey, an attacker cannot compute the master key nor any other subkeys.
//!
//! The derive_from_key API can derive up to 2^64 keys from a single master key and context,
//! and individual subkeys can have an arbitrary length between 128 (16 bytes) and 524,280 bits (65535 bytes).
//!
//! # Examples
//! ```
//! // these must come from a high entropy source such as a hardware RNG.
//! // A password is not ok.
//! let master_key_data=[64,33,195,234,107,63,107,237,113,199,
//!     183,130,203,194,247,31,76,51,203,163,
//!     126,238,206,125,225,74,103,105,133,181,
//!     61,189];
//!
//! let master  = libhydrogen::kdf::Key::from(master_key_data);
//! let context = libhydrogen::kdf::Context::default();
//!
//! let subkey1 = libhydrogen::kdf::derive_from_key(32, 1, &context, &master).unwrap();
//! let subkey2 = libhydrogen::kdf::derive_from_key(32, 2, &context, &master).unwrap();
//! ```

use super::ensure_initialized;
use crate::errors::*;
use crate::ffi;
use crate::utils;
use std::mem::MaybeUninit;

pub const CONTEXTBYTES: usize = ffi::hydro_kdf_CONTEXTBYTES as usize;
pub const KEYBYTES: usize = ffi::hydro_kdf_KEYBYTES as usize;
pub const BYTES_MAX: usize = ffi::hydro_kdf_BYTES_MAX as usize;
pub const BYTES_MIN: usize = ffi::hydro_kdf_BYTES_MIN as usize;

#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct Context([u8; CONTEXTBYTES]);

#[derive(Debug, Clone)]
pub struct Key([u8; KEYBYTES]);

/// Derives a subkey_id-th subkey of length subkey_len bytes using the master key and the context.
pub fn derive_from_key(
    subkey_len: usize,
    subkey_id: u64,
    context: &Context,
    key: &Key,
) -> Result<Vec<u8>, HydroError> {
    let mut subkey = vec![0u8; subkey_len];
    if unsafe {
        ffi::hydro_kdf_derive_from_key(
            subkey.as_mut_ptr(),
            subkey_len,
            subkey_id,
            context.0.as_ptr() as *const _,
            key.0.as_ptr(),
        )
    } != 0
    {
        return Err(HydroError::UnsupportedOutputLength);
    }
    Ok(subkey)
}

impl Drop for Key {
    fn drop(&mut self) {
        utils::memzero(self)
    }
}

impl From<[u8; KEYBYTES]> for Key {
    #[inline]
    fn from(key: [u8; KEYBYTES]) -> Key {
        Key(key)
    }
}

impl Into<[u8; KEYBYTES]> for Key {
    #[inline]
    fn into(self) -> [u8; KEYBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        utils::equal(self, other)
    }
}

impl Eq for Key {}

impl Key {
    pub fn gen() -> Key {
        ensure_initialized();
        unsafe {
            let mut key = MaybeUninit::<Key>::uninit();
            ffi::hydro_kdf_keygen((*key.as_mut_ptr()).0.as_mut_ptr());
            key.assume_init()
        }
    }
}

impl From<&'static str> for Context {
    fn from(context_str: &'static str) -> Context {
        let context_str_u8 = context_str.as_bytes();
        let context_str_u8_len = context_str_u8.len();
        if context_str_u8_len > CONTEXTBYTES {
            panic!("Context too long");
        }
        let mut context = Context::default();
        context.0[..context_str_u8_len].copy_from_slice(context_str_u8);
        context
    }
}

impl From<[u8; CONTEXTBYTES]> for Context {
    #[inline]
    fn from(context: [u8; CONTEXTBYTES]) -> Context {
        Context(context)
    }
}

impl Into<[u8; CONTEXTBYTES]> for Context {
    #[inline]
    fn into(self) -> [u8; CONTEXTBYTES] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_kdf() {
        init().unwrap();

        let context = "tests".into();
        let key = kdf::Key::gen();
        let subkey = kdf::derive_from_key(50, 1, &context, &key).unwrap();
        assert_eq!(subkey.len(), 50);

        let contextx: [u8; kdf::CONTEXTBYTES] = context.into();
        let contexty: kdf::Context = contextx.into();
        assert_eq!(context, contexty);
    }
}
