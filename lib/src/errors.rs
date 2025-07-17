//! Error handling.

/// Crate result specialization.
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

/// Errors used in this crate.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The state has been explicitly disabled.
    #[error("the {state} has been explicitly disabled")]
    #[non_exhaustive]
    StateDisabled {
        state: &'static str,
    },
}

impl Error {
    /// Signals that the state has been explicitly disabled.
    pub(crate) fn state_disabled(state: &'static str) -> Self {
        Error::StateDisabled { state }
    }
}
