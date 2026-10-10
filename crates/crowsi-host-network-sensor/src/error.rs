use std::error::Error;
use std::fmt;

/// Safe failure categories that never include source data or operating-system text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorError {
    InvalidContract,
    InputTooLarge,
    InputReadFailed,
    InvalidArguments,
}

impl fmt::Display for SensorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContract => "input does not satisfy the closed contract",
            Self::InputTooLarge => "input exceeds the bounded size",
            Self::InputReadFailed => "input could not be read",
            Self::InvalidArguments => "invalid command arguments",
        })
    }
}

impl Error for SensorError {}
