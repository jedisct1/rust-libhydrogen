#[derive(Debug, Fail)]
pub enum HydroError {
    #[fail(display = "Invalid input")] InvalidInput,
    #[fail(display = "Invalid key")] InvalidKey,
    #[fail(display = "Invalid padding")] InvalidPadding,
    #[fail(display = "Invalid probe")] InvalidProbe,
    #[fail(display = "Invalid signature")] InvalidSignature,
    #[fail(display = "Unable to decrypt the ciphertext")] DecryptionError,
    #[fail(display = "Unable to initialized the hydrogen library")] InitError,
    #[fail(display = "Unsupported output length")] UnsupportedOutputLength,
}
