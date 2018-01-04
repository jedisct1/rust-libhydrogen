use super::ensure_initialized;
use ffi;
use utils;

pub const SEEDBYTES: usize = ffi::hydro_random_SEEDBYTES as usize;

#[derive(Debug, Clone)]
pub struct Seed([u8; SEEDBYTES]);

#[inline]
pub fn u32() -> u32 {
    ensure_initialized();
    unsafe { ffi::hydro_random_u32() }
}

#[inline]
pub fn uniform(upper_bound: u32) -> u32 {
    ensure_initialized();
    unsafe { ffi::hydro_random_uniform(upper_bound) }
}

#[inline]
pub fn buf_into(out: &mut [u8]) {
    ensure_initialized();
    unsafe {
        ffi::hydro_random_buf(out.as_mut_ptr() as *mut _, out.len());
    }
}

pub fn buf(out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    buf_into(&mut out);
    out
}

#[inline]
pub fn buf_deterministic_into(out: &mut [u8], seed: &Seed) {
    ensure_initialized();
    unsafe {
        ffi::hydro_random_buf_deterministic(out.as_mut_ptr() as *mut _, out.len(), seed.0.as_ptr())
    }
}

#[inline]
pub fn buf_deterministic(out_len: usize, seed: &Seed) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    buf_deterministic_into(&mut out, seed);
    out
}

#[inline]
pub fn ratchet() {
    ensure_initialized();
    unsafe {
        ffi::hydro_random_ratchet();
    }
}

#[inline]
pub fn reseed() {
    ensure_initialized();
    unsafe {
        ffi::hydro_random_reseed();
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        utils::memzero(self)
    }
}

impl From<[u8; SEEDBYTES]> for Seed {
    #[inline]
    fn from(seed: [u8; SEEDBYTES]) -> Seed {
        Seed(seed)
    }
}

impl Into<[u8; SEEDBYTES]> for Seed {
    #[inline]
    fn into(self) -> [u8; SEEDBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl PartialEq for Seed {
    fn eq(&self, other: &Self) -> bool {
        utils::equal(self, other)
    }
}

impl Eq for Seed {}

impl Seed {
    pub fn gen() -> Seed {
        let mut seed_inner = [0u8; SEEDBYTES];
        buf_into(&mut seed_inner);
        Seed(seed_inner)
    }
}

#[cfg(test)]
mod tests {
    use ::*;

    #[test]
    fn test_randombytes() {
        init().unwrap();
        assert_ne!(random::u32() | random::u32() | random::u32(), 0);

        for _ in 0..100 {
            let max = random::u32();
            assert!(random::uniform(max) < max)
        }

        let len = random::uniform(100) as usize + 1;
        let mut buf = random::buf(len);
        random::buf_into(&mut buf);

        let seed = random::Seed::gen();
        let buf = random::buf_deterministic(len, &seed);
        let mut buf2 = vec![0u8; len];
        random::buf_deterministic_into(&mut buf2, &seed);
        assert_eq!(buf, buf2);

        let seedx: [u8; random::SEEDBYTES] = seed.clone().into();
        let seedy: random::Seed = seedx.into();
        assert_eq!(seed, seedy);

        random::ratchet();

        random::reseed();
    }
}
