#[derive(Debug, Fail)]
pub enum HydroError {
    #[fail(display = "Unable to initialized the hydrogen library")] InitError,
    #[fail(display = "Unsupported output length")] UnsupportedOutputLength,
    #[fail(display = "Invalid input")] InvalidInput,
}
