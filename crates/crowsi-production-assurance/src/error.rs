use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AssuranceError {
    #[error("durable trusted-time state is unavailable")]
    StateUnavailable,
}
