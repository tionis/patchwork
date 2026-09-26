#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("numeric range exhausted")]
    Exhausted,
    #[error("stream not found")]
    NotFound,
    #[error("stream name already exists")]
    Conflict,
    #[error("revision does not match")]
    RevisionMismatch,
    #[error("operation is unavailable for this stream mode")]
    StreamMode,
    #[error("position ahead of tail")]
    PositionAhead,
    #[error("requested history is unavailable")]
    HistoryLost,
    #[error("record exceeds size limit")]
    TooLarge,
    #[error("database format is foreign or newer than this binary")]
    DatabaseFormat,
    #[error("storage operation failed: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("health request failed")]
    HealthRequest(#[source] reqwest::Error),
    #[error("server health endpoint returned {0}")]
    Unhealthy(reqwest::StatusCode),
    #[error("invalid tracing filter")]
    TracingFilter,
}

pub type Result<T> = std::result::Result<T, Error>;
