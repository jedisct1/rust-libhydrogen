#[derive(Debug, Fail)]
pub enum HydroError {
    #[fail(display = "Unable to initialized the hydrogen library")] InitError,
}
