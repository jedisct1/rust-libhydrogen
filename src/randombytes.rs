use super::ensure_initialized;
use ffi;
use utils;

pub const SEEDBYTES: usize = ffi::randombytes_SEEDBYTES as usize;

#[derive(Debug, Copy, Clone)]
pub struct Seed([u8; SEEDBYTES]);

#[inline]
pub fn u32() -> u32 {
    ensure_initialized();
    unsafe { ffi::randombytes_random() }
}

#[inline]
pub fn uniform(upper_bound: u32) -> u32 {
    ensure_initialized();
    unsafe { ffi::randombytes_uniform(upper_bound) }
}

#[inline]
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

#[inline]
pub fn buf_deterministic_into(out: &mut [u8], seed: &Seed) {
    ensure_initialized();
    unsafe {
        ffi::randombytes_buf_deterministic(out.as_mut_ptr() as *mut _, out.len(), seed.0.as_ptr())
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
        ffi::randombytes_ratchet();
    }
}

#[inline]
pub fn reseed() {
    ensure_initialized();
    unsafe {
        ffi::randombytes_reseed();
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
        assert_ne!(
            randombytes::u32() | randombytes::u32() | randombytes::u32(),
            0
        );

        for _ in 0..100 {
            let max = randombytes::u32();
            assert!(randombytes::uniform(max) < max)
        }

        let len = randombytes::uniform(100) as usize + 1;
        let mut buf = randombytes::buf(len);
        randombytes::buf_into(&mut buf);

        let seed = randombytes::Seed::gen();
        let buf = randombytes::buf_deterministic(len, &seed);
        let mut buf2 = vec![0u8; len];
        randombytes::buf_deterministic_into(&mut buf2, &seed);
        assert_eq!(buf, buf2);

        let seedx: [u8; randombytes::SEEDBYTES] = seed.into();
        let seedy: randombytes::Seed = seedx.into();
        assert_eq!(seed, seedy);

        randombytes::ratchet();

        randombytes::reseed();
    }
}
