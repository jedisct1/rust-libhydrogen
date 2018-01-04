use super::ensure_initialized;
use errors::*;
use ffi;
use std::mem;
use utils;

pub const BYTES: usize = ffi::hydro_sign_BYTES as usize;
pub const CONTEXTBYTES: usize = ffi::hydro_sign_CONTEXTBYTES as usize;
pub const PUBLICKEYBYTES: usize = ffi::hydro_sign_PUBLICKEYBYTES as usize;
pub const SECRETKEYBYTES: usize = ffi::hydro_sign_SECRETKEYBYTES as usize;
pub const SEEDBYTES: usize = ffi::hydro_sign_SEEDBYTES as usize;

#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct Context([u8; CONTEXTBYTES]);

#[derive(Debug, Copy, PartialEq, Eq, Clone)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

#[derive(Clone)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

#[derive(Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

#[derive(Debug, Clone)]
pub struct State(ffi::hydro_sign_state);

#[derive(Copy, Clone)]
pub struct Signature([u8; BYTES]);

pub struct Sign {
    state: State,
}

impl Sign {
    fn new(context: &Context) -> Sign {
        unsafe {
            let mut state: State = mem::uninitialized();
            ffi::hydro_sign_init(&mut state.0, context.0.as_ptr() as *const _);
            Sign { state }
        }
    }

    #[inline]
    pub fn update(&mut self, input: &[u8]) {
        unsafe {
            ffi::hydro_sign_update(&mut self.state.0, input.as_ptr() as *const _, input.len());
        }
    }

    pub fn finish_create(mut self, secret_key: &SecretKey) -> Result<Signature, HydroError> {
        unsafe {
            let mut signature: Signature = mem::uninitialized();
            if ffi::hydro_sign_final_create(
                &mut self.state.0,
                signature.0.as_mut_ptr(),
                secret_key.0.as_ptr(),
            ) != 0
            {
                return Err(HydroError::InvalidKey);
            }
            Ok(signature)
        }
    }

    pub fn finish_verify(
        mut self,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), HydroError> {
        if unsafe {
            ffi::hydro_sign_final_verify(
                &mut self.state.0,
                signature.0.as_ptr(),
                public_key.0.as_ptr(),
            )
        } != 0
        {
            return Err(HydroError::InvalidSignature);
        }
        Ok(())
    }
}

#[inline]
pub fn init(context: &Context) -> Sign {
    Sign::new(context)
}

pub fn create(
    input: &[u8],
    context: &Context,
    secret_key: &SecretKey,
) -> Result<Signature, HydroError> {
    let mut sign = init(context);
    sign.update(input);
    sign.finish_create(secret_key)
}

pub fn verify(
    signature: &Signature,
    input: &[u8],
    context: &Context,
    public_key: &PublicKey,
) -> Result<(), HydroError> {
    let mut sign = init(context);
    sign.update(input);
    sign.finish_verify(signature, public_key)
}

impl Drop for State {
    fn drop(&mut self) {
        utils::memzero(self)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        utils::memzero(self)
    }
}

impl From<[u8; SECRETKEYBYTES]> for SecretKey {
    #[inline]
    fn from(key: [u8; SECRETKEYBYTES]) -> SecretKey {
        SecretKey(key)
    }
}

impl Into<[u8; SECRETKEYBYTES]> for SecretKey {
    #[inline]
    fn into(self) -> [u8; SECRETKEYBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        utils::equal(self, other)
    }
}

impl Eq for SecretKey {}

impl From<[u8; BYTES]> for Signature {
    #[inline]
    fn from(key: [u8; BYTES]) -> Signature {
        Signature(key)
    }
}

impl Into<[u8; BYTES]> for Signature {
    #[inline]
    fn into(self) -> [u8; BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        utils::equal(self, other)
    }
}

impl Eq for Signature {}

impl From<[u8; PUBLICKEYBYTES]> for PublicKey {
    #[inline]
    fn from(key: [u8; PUBLICKEYBYTES]) -> PublicKey {
        PublicKey(key)
    }
}

impl Into<[u8; PUBLICKEYBYTES]> for PublicKey {
    #[inline]
    fn into(self) -> [u8; PUBLICKEYBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl KeyPair {
    pub fn gen() -> KeyPair {
        ensure_initialized();
        unsafe {
            let mut keypair_c: ffi::hydro_sign_keypair = mem::uninitialized();
            ffi::hydro_sign_keygen(&mut keypair_c);
            let mut keypair: KeyPair = mem::uninitialized();
            keypair.public_key.0.copy_from_slice(&keypair_c.pk);
            keypair.secret_key.0.copy_from_slice(&keypair_c.sk);
            ffi::hydro_memzero(
                &mut keypair_c as *mut _ as *mut _,
                mem::size_of_val(&keypair_c),
            );
            keypair
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
    fn test_signature() {
        init().unwrap();

        let context = "tests".into();
        let keypair = sign::KeyPair::gen();

        let mut s = sign::init(&context);
        s.update(b"test message");
        let signature = s.finish_create(&keypair.secret_key).unwrap();

        let mut s = sign::init(&context);
        s.update(b"test message");
        s.finish_verify(&signature, &keypair.public_key).unwrap();

        let signature = sign::create(b"test message", &context, &keypair.secret_key).unwrap();
        sign::verify(&signature, b"test message", &context, &keypair.public_key).unwrap();

        let contextx: [u8; sign::CONTEXTBYTES] = context.into();
        let contexty: sign::Context = contextx.into();
        assert_eq!(context, contexty);
    }
}
