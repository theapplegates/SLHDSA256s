use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use chrono::DateTime;
use chrono::Utc;

use crate::Time;
use crate::Result;

/// Expiration information
///
/// This enum tracks expiry information either in the form of a timestamp or
/// a duration.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Expiration {
    /// An expiry timestamp
    Timestamp(Time),
    /// There is no expiry
    Never,
}

impl Expiration {
    /// Create a new Expiration in a Result
    ///
    /// If `expiry` ends with `"y"`, `"m"`, `"w"`, `"w"`, `"d"` or `"s"` it
    /// is treated as a duration, which is parsed using `parse_duration()` and
    /// returned in an `Expiration::Duration`.
    /// If the special keyword `"never"` is provided as `expiry`,
    /// `Expiration::Never` is returned.
    /// If `expiry` is an ISO 8601 compatible string it is returned as
    /// `cli::types::Time` in an `Expiration::Timestamp`.
    pub fn new(expiry: &str) -> Result<Self> {
        match expiry {
            "never" => Ok(Expiration::Never),
            _ => Ok(Expiration::Timestamp(Time::from_str(expiry)?)),
        }
    }

    /// Create a new Expiration from a `Duration`.
    pub fn from_duration(duration: Duration) -> Self {
        Expiration::Timestamp(Time::from_duration(duration))
    }

    /// Return the expiry as an optional Duration in a Result
    ///
    /// This method returns an Error if the reference time is later than the
    /// time provided in an `Expiration::Timestamp(Time)`.
    ///
    /// If self is `Expiration::Timestamp(Time)`, `reference` is used as the start
    /// of a period, `Some(Time - reference)` is returned.
    /// If self is `Expiration::Duration(duration)`, `Some(duration)` is returned.
    /// If self is `Expiration::Never`, `None` is returned.
    pub fn as_duration(
        &self,
        reference: DateTime<Utc>,
    ) -> Result<Option<Duration>> {
        match self {
            Expiration::Timestamp(time) => {
                Ok(Some(time.duration_since(reference.into())?))
            }
            Expiration::Never => Ok(None),
        }
    }

    /// Return the expiry as absolute time.
    pub fn to_system_time(&self, now: SystemTime) -> Result<Option<SystemTime>> {
        match self {
            Expiration::Timestamp(t) => Ok(Some(t.to_system_time(now)?)),
            Expiration::Never => Ok(None),
        }
    }
}

impl FromStr for Expiration {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Expiration> {
        Expiration::new(s)
    }
}

impl Display for Expiration {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Expiration::Timestamp(time) => write!(f, "{}", time),
            Expiration::Never => write!(f, "never"),
        }
    }
}

#[cfg(feature = "clap")]
impl clap::builder::IntoResettable<clap::builder::OsStr> for Expiration {
    fn into_resettable(self)
        -> clap::builder::Resettable<clap::builder::OsStr>
    {
        clap::builder::Resettable::Value(format!("{}", self).into()).into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::consts::SECONDS_IN_YEAR;

    #[test]
    fn test_expiry() {
        assert_eq!(
            Expiration::new("1y").unwrap(),
            Expiration::from_duration(Duration::new(SECONDS_IN_YEAR, 0)),
        );
        assert_eq!(
            Expiration::new("2023-05-15T20:00:00Z").unwrap(),
            Expiration::Timestamp(Time::from_str("2023-05-15T20:00:00Z").unwrap()),
        );
        assert_eq!(
            Expiration::new("never").unwrap(),
            Expiration::Never,
        );
    }

    #[test]
    fn test_expiry_as_duration() {
        let reference = DateTime::from_timestamp(1, 0).unwrap();

        let expiry = Expiration::Timestamp(
            Time::try_from(DateTime::from_timestamp(2, 0).unwrap())
                .expect("valid"));
        assert_eq!(
            expiry.as_duration(reference).unwrap(),
            Some(Duration::new(1, 0)),
        );

        let expiry = Expiration::from_duration(Duration::new(2, 0));
        assert_eq!(
            expiry.as_duration(reference).unwrap(),
            Some(Duration::new(2, 0)),
        );

        let expiry = Expiration::Never;
        assert_eq!(expiry.as_duration(reference).unwrap(), None);
    }

    #[test]
    fn test_expiry_as_duration_errors() {
        let reference = DateTime::from_timestamp(2, 0).unwrap();
        let expiry = Expiration::Timestamp(
            Time::try_from(DateTime::from_timestamp(1, 0).unwrap())
                .expect("valid"));
        assert!(expiry.as_duration(reference).is_err());
    }
}
