#[allow(clippy::trivially_copy_pass_by_ref)]
use libhydrogen_sys as ffi;

pub mod errors;
pub mod hash;
pub mod kdf;
pub mod random;
pub mod secretbox;
pub mod sign;
pub mod utils;
pub mod version;

use crate::errors::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Once,
};

static INIT: Once = Once::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() -> Result<(), HydroError> {
    INIT.call_once(|| {
        if unsafe { ffi::hydro_init() } >= 0 {
            INITIALIZED.store(true, Ordering::Release);
        }
    });
    if INITIALIZED.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(HydroError::InitError)
    }
}

pub fn ensure_initialized() {
    assert!(
        INITIALIZED.load(Ordering::Acquire),
        "Hydrogen library not initialized"
    )
}
