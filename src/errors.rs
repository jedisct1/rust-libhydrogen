pub use anyhow::{anyhow, bail, ensure, Error};

#[derive(Debug, thiserror::Error)]
pub enum HydroError {
    #[error("Invalid input")]
    InvalidInput,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid padding")]
    InvalidPadding,
    #[error("Invalid probe")]
    InvalidProbe,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Unable to decrypt the ciphertext")]
    DecryptionError,
    #[error("Unable to initialized the hydrogen library")]
    InitError,
    #[error("Unsupported output length")]
    UnsupportedOutputLength,
}
