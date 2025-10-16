use std::borrow::Cow;

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;

use sequoia_wot as wot;

use crate::types::Safe;

/// Something like a User ID.
///
/// This is used to avoid unnecessary allocations.
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
enum UserIDLike {
    UserID(UserID),
    String(String),
    Unknown,
}

/// The preferred user ID for a certificate.
///
/// This can be smartly truncated using the precision formatting
/// parameter, e.g.:
///
/// ```text
/// format!("{:.70}", userid);
/// ```
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct PreferredUserID {
    userid: UserIDLike,
    trust_amount: usize,
}

struct PreferredUserIDDisplay<'p>(&'p PreferredUserID);

impl<'p> std::fmt::Display for PreferredUserIDDisplay<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
        -> Result<(), std::fmt::Error>
    {
        let userid_;
        let userid = match self.0.userid {
            UserIDLike::Unknown => {
                return write!(f, "<unknown>");
            }
            UserIDLike::UserID(ref userid) => {
                userid_ = String::from_utf8_lossy(userid.value());
                &userid_[..]
            }
            UserIDLike::String(ref userid) => {
                &userid[..]
            }
        };

        let userid = Safe(userid).to_string();

        let suffix_;
        let suffix = if self.0.trust_amount == 0 {
            "(UNAUTHENTICATED)"
        } else if self.0.trust_amount < wot::FULLY_TRUSTED {
            suffix_ = format!("(partially authenticated, {}/{})",
                              self.0.trust_amount, wot::FULLY_TRUSTED);
            &suffix_[..]
        } else {
            "(authenticated)"
        };

        // We always keep the suffix and at least 16 characters of the user ID.
        const MIN_USERID: usize = 16;

        if let Some(width) = f.precision() {
            let space_for_userid = width.saturating_sub(1 + suffix.len()).max(MIN_USERID);
            if userid.chars().count() > space_for_userid {
                return write!(f, "{}… {}",
                              userid.chars().take(MIN_USERID).collect::<String>(),
                              suffix);
            }
        }

        write!(f, "{} {}", userid, suffix)
    }
}

impl PreferredUserID {
    /// Returns a new `PreferredUserID`.
    pub fn from_userid<U>(userid: U, trust_amount: usize) -> Self
    where U: Into<UserID>
    {
        Self {
            userid: UserIDLike::UserID(userid.into()),
            trust_amount,
        }
    }

    /// Returns a new `PreferredUserID`.
    pub fn from_string<S>(userid: S, trust_amount: usize) -> Self
    where S: Into<String>
    {
        Self {
            userid: UserIDLike::String(userid.into()),
            trust_amount,
        }
    }

    /// Returns a new "unknown" `PreferredUserID`.
    pub fn unknown() -> Self {
        Self {
            userid: UserIDLike::Unknown,
            trust_amount: 0,
        }
    }

    /// Returns the user ID with authentication information, suitable
    /// for displaying to the user.
    ///
    /// Do not use for arguments in hints.
    pub fn display<'p>(&'p self) -> impl std::fmt::Display + 'p {
        PreferredUserIDDisplay(self)
    }

    /// Returns the user ID without authentication information,
    /// suitable for use in text for displaying to the user, where a
    /// best effort string conversion is better than failing, and
    /// byte-accuracy is not required.
    ///
    /// Do not use for general displaying, use
    /// [`PreferredUserID::display`] for that which includes
    /// authentication information.
    ///
    /// Do not use for arguments in hints.
    pub fn userid_lossy(&self) -> Cow<'_, str> {
        match &self.userid {
            UserIDLike::UserID(u) => String::from_utf8_lossy(u.value()),
            UserIDLike::String(u) => Cow::Borrowed(&u),
            UserIDLike::Unknown => Cow::Borrowed("<unknown userid>"),
        }
    }

    /// Returns the user ID without authentication information,
    /// suitable for use as argument in hints.
    ///
    /// Do not use for general displaying, use
    /// [`PreferredUserID::display`] for that which includes
    /// authentication information.
    pub fn userid(&self) -> Result<&str> {
        match &self.userid {
            UserIDLike::UserID(u) => Ok(std::str::from_utf8(u.value())?),
            UserIDLike::String(u) => Ok(&u),
            UserIDLike::Unknown =>
                Err(anyhow::anyhow!("User ID is unknown")),
        }
    }

    /// Returns the trust amount.
    pub fn trust_amount(&self) -> usize {
        self.trust_amount
    }
}

