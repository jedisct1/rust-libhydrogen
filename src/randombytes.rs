use super::ensure_initialized;
use ffi;

pub struct Seed([u8; ffi::randombytes_SEEDBYTES as usize]);

pub fn u32() -> u32 {
    ensure_initialized();
    unsafe { ffi::randombytes_random() }
}

pub fn uniform(upper_bound: u32) -> u32 {
    ensure_initialized();
    unsafe { ffi::randombytes_uniform(upper_bound) }
}

pub fn buf_into(out: &mut [u8]) {
    ensure_initialized();
    unsafe {
        ffi::randombytes_buf(out.as_mut_ptr() as *mut _, out.len());
    }
}

pub fn buf(out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    buf_into(&mut out);
    out
}

pub fn buf_deterministic_into(out: &mut [u8], seed: &Seed) {
    ensure_initialized();
    unsafe {
        ffi::randombytes_buf_deterministic(out.as_mut_ptr() as *mut _, out.len(), seed.0.as_ptr())
    }
}

pub fn buf_deterministic(out_len: usize, seed: &Seed) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    buf_deterministic_into(&mut out, seed);
    out
}

pub fn ratchet() {
    ensure_initialized();
    unsafe {
        ffi::randombytes_ratchet();
    }
}

pub fn reseed() {
    ensure_initialized();
    unsafe {
        ffi::randombytes_reseed();
    }
}

impl From<[u8; ffi::randombytes_SEEDBYTES as usize]> for Seed {
    fn from(seed: [u8; 32]) -> Seed {
        Seed(seed)
    }
}

impl Into<[u8; ffi::randombytes_SEEDBYTES as usize]> for Seed {
    fn into(self) -> [u8; 32] {
        self.0
    }
}

impl Seed {
    pub fn random() -> Seed {
        let mut seed_inner = [0u8; ffi::randombytes_SEEDBYTES as usize];
        buf_into(&mut seed_inner);
        Seed(seed_inner)
    }
}
