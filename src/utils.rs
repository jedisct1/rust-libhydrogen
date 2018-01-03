use errors::*;
use ffi;
use std::{mem, ptr};
use std::cmp::Ordering;
use std::ffi::CString;

#[inline]
pub fn memzero<T>(mut obj: T)
where
    T: Sized,
{
    unsafe { ffi::hydro_memzero(&mut obj as *mut _ as *mut _, mem::size_of::<T>()) }
}

#[inline]
pub fn increment(n: &mut [u8]) {
    unsafe {
        ffi::hydro_increment(n.as_mut_ptr(), n.len());
    }
}

pub fn equal<T, U>(b1: T, b2: U) -> bool
where
    T: AsRef<[u8]>,
    U: AsRef<[u8]>,
{
    let b1 = b1.as_ref();
    let b2 = b2.as_ref();
    let len = b1.len();
    if b2.len() != len {
        return false;
    }
    unsafe { ffi::hydro_equal(b1.as_ptr() as *const _, b2.as_ptr() as *const _, len) as bool }
}

pub fn compare(b1: &[u8], b2: &[u8]) -> Ordering {
    let len = b1.len();
    if b2.len() != len {
        panic!("Comparison of vectors with different lengths")
    }
    unsafe {
        match ffi::hydro_compare(b1.as_ptr(), b2.as_ptr(), len) {
            -1 => Ordering::Less,
            0 => Ordering::Equal,
            1 => Ordering::Greater,
            _ => unreachable!(),
        }
    }
}

pub fn bin2hex<T>(bin: T) -> String
where
    T: AsRef<[u8]>,
{
    let bin = bin.as_ref();
    let len = bin.len();
    let hex_len = len * 2 + 1;
    let mut hex = vec![0u8; hex_len];
    unsafe {
        ffi::hydro_bin2hex(hex.as_mut_ptr() as *mut _, hex_len, bin.as_ptr(), len);
        hex.truncate(hex_len - 1);
        String::from_utf8_unchecked(hex)
    }
}

pub fn hex2bin(hex: &str, ignore: Option<&[u8]>) -> Result<Vec<u8>, HydroError> {
    let hex = hex.as_bytes();
    let hex_len = hex.len();
    let max_bin_len = hex_len / 2;
    let mut bin = vec![0u8; max_bin_len];
    let ignore_p = match ignore {
        Some(ignore) => CString::new(ignore)
            .map_err(|_| HydroError::InvalidInput)?
            .into_raw(),
        None => ptr::null(),
    };
    let mut bin_len = 0usize;
    if unsafe {
        ffi::hydro_hex2bin(
            bin.as_mut_ptr(),
            max_bin_len,
            hex.as_ptr() as *const _,
            hex_len,
            ignore_p,
            &mut bin_len,
            ptr::null_mut(),
        )
    } == 0
    {
        bin.truncate(bin_len);
        return Ok(bin.into());
    }
    Err(HydroError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use ::*;

    #[test]
    fn test_utils() {
        let bin = [69u8, 42];
        let hex = utils::bin2hex(bin);
        assert_eq!(hex, "452a");
        let bin2: Vec<u8> = utils::hex2bin(&hex, None).unwrap();
        assert_eq!(bin, &bin2[..]);
        let bin2: Vec<u8> = utils::hex2bin("#452a#", Some(b"#")).unwrap();
        assert_eq!(bin, &bin2[..]);
    }
}
