use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

use crate::Result;

/// Describes the purpose of the encryption.
#[derive(Copy, Clone, Debug)]
pub enum TrustAmount<T> {
    /// No trust.
    None,

    /// Partial trust.
    Partial,

    /// Full trust.
    Full,

    /// Double trust.
    Double,

    /// Other trust amount.
    Other(T),
}

impl<T: Copy + From<u8>> TrustAmount<T> {
    /// Returns the trust amount as numeric value.
    pub fn amount(&self) -> T {
        match self {
            TrustAmount::None => 0.into(),
            // See section 5.2.3.13. Trust Signature of RFC4880 for
            // the values of partial and full trust.
            TrustAmount::Partial => 60.into(),
            TrustAmount::Full => 120.into(),
            TrustAmount::Double => 240.into(),
            TrustAmount::Other(a) => *a,
        }
    }
}

impl<T: Display + FromStr> FromStr for TrustAmount<T>
where
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<TrustAmount<T>> {
        if s.eq_ignore_ascii_case("none") {
            Ok(TrustAmount::None)
        } else if s.eq_ignore_ascii_case("partial") {
            Ok(TrustAmount::Partial)
        } else if s.eq_ignore_ascii_case("full") {
            Ok(TrustAmount::Full)
        } else if s.eq_ignore_ascii_case("double") {
            Ok(TrustAmount::Double)
        } else {
            Ok(TrustAmount::Other(s.parse()?))
        }
    }
}

impl<T: Display + FromStr> Display for TrustAmount<T> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            TrustAmount::None => f.write_str("none"),
            TrustAmount::Partial => f.write_str("partial"),
            TrustAmount::Full => f.write_str("full"),
            TrustAmount::Double => f.write_str("double"),
            TrustAmount::Other(a) => write!(f, "{}", a),
        }
    }
}
