use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to create NetBird client: {0}")]
    Create(String),

    #[error("failed to start NetBird client")]
    Start,

    #[error("failed to stop NetBird client")]
    Stop,

    #[error("buffer too small for response")]
    BufferTooSmall,

    #[error("FFI returned error: {0}")]
    Ffi(String),

    #[error("failed to deserialize response: {0}")]
    Deserialize(#[from] serde_json::Error),

    #[error("dial failed")]
    Dial,

    #[error("listen failed")]
    Listen,

    #[error("string contains interior NUL byte")]
    InteriorNul,
}
