use thiserror::Error;


#[derive(Error, Debug)]
pub enum Error {
    #[error("Load error")]
    LoadError,
    #[error("Memory error")]
    MemoryError,
    #[error("Execution error")]
    ExecutionError,
    #[error("Goblin error: {0}")]
    Goblin(goblin::error::Error),
    #[error("Unsupported architecture")]
    UnsupportedArchitecture,
    #[error("Unsupported format")]
    UnsupportedFormat,
    #[error("IO error: {0}")]
    Io(std::io::Error),
}