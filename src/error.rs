use std::fmt;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Cli,
    Preflight,
    Stage,
    Policy,
    Spawn,
    Record,
}

#[derive(Debug)]
pub struct AutoCageError {
    pub kind: ErrorKind,
    pub message: String,
}

impl AutoCageError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn io(kind: ErrorKind, context: impl AsRef<str>, error: io::Error) -> Self {
        Self::new(kind, format!("{}: {error}", context.as_ref()))
    }

    pub fn exit_code(&self) -> u8 {
        2
    }
}

impl fmt::Display for AutoCageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for AutoCageError {}

pub type Result<T> = std::result::Result<T, AutoCageError>;
