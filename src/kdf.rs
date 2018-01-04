use super::ensure_initialized;
use errors::*;
use ffi;
use std::mem;
use utils;

pub const CONTEXTBYTES: usize = ffi::hydro_kdf_CONTEXTBYTES as usize;
pub const KEYBYTES: usize = ffi::hydro_kdf_KEYBYTES as usize;
pub const BYTES_MAX: usize = ffi::hydro_kdf_BYTES_MAX as usize;
pub const BYTES_MIN: usize = ffi::hydro_kdf_BYTES_MIN as usize;

#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct Context([u8; CONTEXTBYTES]);

#[derive(Debug, Clone)]
pub struct Key([u8; KEYBYTES]);

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
            let mut key: Key = mem::uninitialized();
            ffi::hydro_kdf_keygen(key.0.as_mut_ptr());
            key
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
    use ::*;

    #[test]
    fn test_kdf() {
        init().unwrap();

        let context = "tests".into();
        let key = kdf::Key::gen();
        let subkey = kdf::derive_from_key(50, 1, &context, &key).unwrap();
        assert_eq!(subkey.len(), 50);
    }
}
