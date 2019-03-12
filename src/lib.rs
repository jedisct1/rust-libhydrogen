use failure;
#[macro_use]
extern crate failure_derive;
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
use std::sync::{Once, ONCE_INIT};

static INIT: Once = ONCE_INIT;
static mut INITIALIZED: bool = false;

pub fn init() -> Result<(), HydroError> {
    unsafe {
        INIT.call_once(|| {
            if ffi::hydro_init() >= 0 {
                INITIALIZED = true;
            }
        });
        if INITIALIZED {
            Ok(())
        } else {
            Err(HydroError::InitError)
        }
    }
}

pub fn ensure_initialized() {
    if unsafe { !INITIALIZED } {
        panic!("Hydrogen library not initialized");
    }
}
