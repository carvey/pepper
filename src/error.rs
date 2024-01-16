use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParsingError {
    #[error("failed to parse: {reason:?}")]
    Malformed { reason: String },

    #[error("Invalid magic byte in the {header:?} at offset {offset:?}")]
    InvalidMagic { header: String, offset: usize },

    #[error("Unable to access byte at: {byte:}")]
    PointerAccessError { byte: usize },
}
