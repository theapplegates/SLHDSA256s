//! Types used in the interface.

use std::{
    path::PathBuf,
};

use crate::errors::Result;

mod cert_designator;
pub use cert_designator::FileStdinOrKeyHandle;
pub use cert_designator::FileOrStdin;
mod convert;
pub use convert::Convert;
mod preferred_userid;
pub use preferred_userid::PreferredUserID;
mod query;
pub use query::Query;
pub use query::QueryKind;
mod safe;
pub use safe::Safe;
mod trust_amount;
pub use trust_amount::TrustAmount;

/// Either an absolute path, or a default path.
///
/// Even though this type is homomorphic to [`Option<PathBuf>`], we
/// need a new type for this, because clap handles [`Option`]s
/// differently, and we cannot return [`Option<PathBuf>`] from
/// `TypedValueParser::parse_ref`.
#[derive(Clone, Debug)]
pub enum StateDirectory {
    /// An absolute path.
    Absolute(PathBuf),

    /// The default path.
    Default,

    /// Explicitly disable this state.
    None,
}

impl StateDirectory {
    /// Returns whether this state has been disabled.
    pub fn is_none(&self) -> bool {
        matches!(self, StateDirectory::None)
    }

    /// Returns the absolute path, or `None` if the default path is to
    /// be used.
    pub fn path(&self) -> Result<Option<PathBuf>> {
        match self {
            StateDirectory::Absolute(p) => Ok(Some(p.clone())),
            StateDirectory::Default => Ok(None),
            StateDirectory::None =>
                Err(crate::Error::state_disabled("state").into()),
        }
    }
}
