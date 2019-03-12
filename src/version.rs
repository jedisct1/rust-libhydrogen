use crate::ffi;

#[inline]
pub fn major() -> u32 {
    ffi::HYDRO_VERSION_MAJOR
}

#[inline]
pub fn minor() -> u32 {
    ffi::HYDRO_VERSION_MINOR
}

pub fn string() -> String {
    format!("{}.{}", major(), minor())
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_version() {
        assert!(version::major() + version::minor() > 0);
        assert_eq!(version::string().is_empty(), false);
    }
}
