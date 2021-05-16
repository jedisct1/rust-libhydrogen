//! Secret-key authenticated encryption
//!
//! A single key is used both to encrypt/sign and verify/decrypt messages. For this reason, it is critical to keep the key confidential.
//!
//! # Examples
//! ```
//! let key_data =[64,33,195,234,107,63,107,237,113,199,
//!     183,130,203,194,247,31,76,51,203,163,
//!     126,238,206,125,225,74,103,105,133,181,
//!     61,189];
//!
//! let key         = libhydrogen::secretbox::Key::from(key_data);
//! let context     = libhydrogen::secretbox::Context::default();
//! let ciphertext  = libhydrogen::secretbox::encrypt(b"hello world", 1, &context, &key);
//!
//! let decrypted   = libhydrogen::secretbox::decrypt(&ciphertext, 1, &context, &key).unwrap();
//!
//! println!("{}", String::from_utf8(decrypted).unwrap());
//! ```

use super::ensure_initialized;
use crate::errors::*;
use crate::ffi;
use crate::utils;
use core::mem::MaybeUninit;

pub const CONTEXTBYTES: usize = ffi::hydro_secretbox_CONTEXTBYTES as usize;
pub const HEADERBYTES: usize = ffi::hydro_secretbox_HEADERBYTES as usize;
pub const KEYBYTES: usize = ffi::hydro_secretbox_KEYBYTES as usize;
pub const PROBEBYTES: usize = ffi::hydro_secretbox_PROBEBYTES as usize;

#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct Context([u8; CONTEXTBYTES]);

#[derive(Debug, Clone)]
pub struct Key([u8; KEYBYTES]);

#[derive(Debug, Clone)]
pub struct Probe([u8; PROBEBYTES]);

pub fn encrypt(input: &[u8], msg_id: u64, context: &Context, key: &Key) -> Vec<u8> {
    let out_len = HEADERBYTES + input.len();
    let mut out = Vec::with_capacity(out_len);
    unsafe {
        out.set_len(out_len);
        ffi::hydro_secretbox_encrypt(
            out.as_mut_ptr(),
            input.as_ptr() as *const _,
            input.len(),
            msg_id,
            context.0.as_ptr() as *const _,
            key.0.as_ptr(),
        );
    }
    out
}

pub fn decrypt(
    input: &[u8],
    msg_id: u64,
    context: &Context,
    key: &Key,
) -> Result<Vec<u8>, HydroError> {
    if input.len() < HEADERBYTES {
        return Err(HydroError::DecryptionError);
    }
    let out_len = input.len() - HEADERBYTES;
    let mut out: Vec<u8> = Vec::with_capacity(out_len);
    unsafe {
        out.set_len(out_len);
        if ffi::hydro_secretbox_decrypt(
            out.as_mut_ptr() as *mut _,
            input.as_ptr(),
            input.len(),
            msg_id,
            context.0.as_ptr() as *const _,
            key.0.as_ptr(),
        ) != 0
        {
            return Err(HydroError::DecryptionError);
        }
    }
    Ok(out)
}

impl Probe {
    pub fn create(input: &[u8], context: &Context, key: &Key) -> Probe {
        if input.len() < HEADERBYTES {
            panic!("A probe cannot be created for an impossible ciphertext")
        }
        unsafe {
            let mut probe = MaybeUninit::<Probe>::uninit();
            ffi::hydro_secretbox_probe_create(
                (*probe.as_mut_ptr()).0.as_mut_ptr(),
                input.as_ptr(),
                input.len(),
                context.0.as_ptr() as *const _,
                key.0.as_ptr(),
            );
            probe.assume_init()
        }
    }

    pub fn verify(&self, input: &[u8], context: &Context, key: &Key) -> Result<(), HydroError> {
        if unsafe {
            ffi::hydro_secretbox_probe_verify(
                self.0.as_ptr(),
                input.as_ptr(),
                input.len(),
                context.0.as_ptr() as *const _,
                key.0.as_ptr(),
            )
        } != 0
        {
            return Err(HydroError::InvalidProbe);
        }
        Ok(())
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
            ffi::hydro_kdf_keygen((*key.as_mut_ptr()).0.as_mut_ptr());
            key.assume_init()
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        utils::memzero(self)
    }
}

impl From<[u8; PROBEBYTES]> for Probe {
    #[inline]
    fn from(probe: [u8; PROBEBYTES]) -> Probe {
        Probe(probe)
    }
}

impl Into<[u8; PROBEBYTES]> for Probe {
    #[inline]
    fn into(self) -> [u8; PROBEBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for Probe {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl PartialEq for Probe {
    fn eq(&self, other: &Self) -> bool {
        utils::equal(self, other)
    }
}

impl Eq for Probe {}

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
    fn test_secretbox() {
        init().unwrap();

        let context = "tests".into();
        let key = secretbox::Key::gen();

        let ciphertext = secretbox::encrypt(b"test message", 1, &context, &key);
        let decrypted = secretbox::decrypt(&ciphertext, 1, &context, &key).unwrap();
        assert_eq!(decrypted, b"test message");

        let probe = secretbox::Probe::create(&ciphertext, &context, &key);
        probe.verify(&ciphertext, &context, &key).unwrap();

        let contextx: [u8; secretbox::CONTEXTBYTES] = context.into();
        let contexty: secretbox::Context = contextx.into();
        assert_eq!(context, contexty);
    }
}
