use core::{mem::MaybeUninit, ptr};

use super::ensure_initialized;
use crate::errors::*;
use crate::ffi;
use crate::utils;

pub const CONTEXTBYTES: usize = ffi::hydro_hash_CONTEXTBYTES as usize;
pub const KEYBYTES: usize = ffi::hydro_hash_KEYBYTES as usize;
pub const BYTES: usize = ffi::hydro_hash_BYTES as usize;
pub const BYTES_MAX: usize = ffi::hydro_hash_BYTES_MAX as usize;
pub const BYTES_MIN: usize = ffi::hydro_hash_BYTES_MIN as usize;

#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct Context([u8; CONTEXTBYTES]);

#[derive(Debug, Clone)]
pub struct Key([u8; KEYBYTES]);

#[derive(Debug, Clone)]
pub struct State(ffi::hydro_hash_state);

pub struct DefaultHasher {
    state: State,
}

impl DefaultHasher {
    #[inline]
    fn new(key: Option<&Key>, context: &Context) -> DefaultHasher {
        unsafe {
            let mut state = MaybeUninit::<State>::uninit();
            let key = match key {
                None => ptr::null(),
                Some(key) => key.0.as_ptr(),
            };
            ffi::hydro_hash_init(
                &mut (*state.as_mut_ptr()).0,
                context.0.as_ptr() as *const _,
                key,
            );
            DefaultHasher {
                state: state.assume_init(),
            }
        }
    }

    #[inline]
    pub fn update(&mut self, input: &[u8]) {
        unsafe {
            ffi::hydro_hash_update(&mut self.state.0, input.as_ptr() as *const _, input.len());
        }
    }

    pub fn finish_into(mut self, out: &mut [u8]) -> Result<(), HydroError> {
        unsafe {
            if ffi::hydro_hash_final(&mut self.state.0, out.as_mut_ptr(), out.len()) == 0 {
                Ok(())
            } else {
                Err(HydroError::UnsupportedOutputLength)
            }
        }
    }

    pub fn finish(self, out_len: usize) -> Result<Vec<u8>, HydroError> {
        let mut out = vec![0u8; out_len];
        self.finish_into(&mut out)?;
        Ok(out)
    }
}

#[inline]
pub fn init(context: &Context, key: Option<&Key>) -> DefaultHasher {
    DefaultHasher::new(key, context)
}

pub fn hash_into(
    mut out: &mut [u8],
    input: &[u8],
    context: &Context,
    key: Option<&Key>,
) -> Result<(), HydroError> {
    let mut hasher = init(context, key);
    hasher.update(input);
    hasher.finish_into(&mut out)?;
    Ok(())
}

pub fn hash(
    out_len: usize,
    input: &[u8],
    context: &Context,
    key: Option<&Key>,
) -> Result<Vec<u8>, HydroError> {
    let mut out = vec![0u8; out_len];
    hash_into(&mut out, input, context, key)?;
    Ok(out)
}

impl Drop for State {
    fn drop(&mut self) {
        utils::memzero(self)
    }
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
            ffi::hydro_hash_keygen((*key.as_mut_ptr()).0.as_mut_ptr());
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
    fn test_hash() {
        init().unwrap();

        let context = "tests".into();
        let key = hash::Key::gen();
        assert_ne!(key, hash::Key::gen());

        let mut h = hash::init(&context, Some(&key));
        h.update(b"test message");
        h.finish(hash::BYTES).unwrap();

        hash::hash(hash::BYTES_MIN, b"test message", &context, Some(&key)).unwrap();

        let keyx: [u8; hash::KEYBYTES] = key.clone().into();
        let keyy: hash::Key = keyx.into();
        assert_eq!(key, keyy);

        let contextx: [u8; hash::CONTEXTBYTES] = context.into();
        let contexty: hash::Context = contextx.into();
        assert_eq!(context, contexty);
    }
}
