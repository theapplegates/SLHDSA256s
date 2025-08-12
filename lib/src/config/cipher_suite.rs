use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

use sequoia_openpgp as openpgp;
use openpgp::cert::CipherSuite as SqCipherSuite;

/// A wrapper type for Sequoia's CipherSuite.
///
/// This is a wrapper type for [`sequoia_openpgp::cert::CipherSuite`],
/// which implements [`std::str::FromStr`], [`std::fmt::Display`], and
/// [`std::string::ToString`].  Note: `Display` displays the string as
/// lower-case, and `FromStr` only matches on lower-case strings.
///
/// Note: this is an opinionated interface, and only passes the subset
/// of the values through that a user should choose from.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[non_exhaustive]
pub enum CipherSuite {
    Rsa2k,
    Rsa3k,
    Rsa4k,
    #[default]
    Cv25519

    // If you add a variant here, be sure to update
    // CipherSuite::variants below.
}

impl CipherSuite {
    /// Returns an iterator over CipherSuite’s variants.
    pub fn variants() -> impl Iterator<Item = Self> {
        use CipherSuite::*;

        [ Rsa2k, Rsa3k, Rsa4k, Cv25519 ].into_iter()
    }
}

impl From<&CipherSuite> for SqCipherSuite {
    fn from(value: &CipherSuite) -> Self {
        match value {
            CipherSuite::Rsa2k => SqCipherSuite::RSA2k,
            CipherSuite::Rsa3k => SqCipherSuite::RSA3k,
            CipherSuite::Rsa4k => SqCipherSuite::RSA4k,
            CipherSuite::Cv25519 => SqCipherSuite::Cv25519,
        }
    }
}

impl From<CipherSuite> for SqCipherSuite {
    fn from(value: CipherSuite) -> Self {
        SqCipherSuite::from(&value)
    }
}

const CIPHER_SUITE_MAP: &[(&str, CipherSuite)] = &[
    // This must be sorted so that it can be used with
    // [`slice::binary_search`].
    ("cv25519", CipherSuite::Cv25519),
    ("rsa2k", CipherSuite::Rsa2k),
    ("rsa3k", CipherSuite::Rsa3k),
    ("rsa4k", CipherSuite::Rsa4k),
];

impl Display for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (as_str, variant) in CIPHER_SUITE_MAP.iter() {
            if variant == self {
                return write!(f, "{}", as_str);
            }
        }
        unreachable!("CIPHER_SUITE_MAP is inconsistent");
    }
}

impl Debug for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

impl FromStr for CipherSuite {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Make sure it is sorted.
        debug_assert!(
            CIPHER_SUITE_MAP.windows(2).all(|window| {
                window[0].0 < window[1].0
            }),
            "CIPHER_SUITE not sorted");

        match CIPHER_SUITE_MAP.binary_search_by(|&(probe, _)| {
            probe.cmp(s)
        }) {
            Ok(i) => Ok(CIPHER_SUITE_MAP[i].1.clone()),
            Err(_) => {
                Err(anyhow::anyhow!("{:?} is not a valid cipher suite", s))
            }
        }
    }
}

impl CipherSuite {
    /// Unwrap the wrapped value.
    ///
    /// Returns the underlying [`sequoia_openpgp::cert::CipherSuite`].
    pub fn as_ciphersuite(&self) -> sequoia_openpgp::cert::CipherSuite {
        SqCipherSuite::from(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphersuite_from_str() {
        assert_eq!(CipherSuite::from_str("rsa3k").expect("can parse"),
                   CipherSuite::Rsa3k);
        assert!(CipherSuite::from_str("RSA3k").is_err());

        for v in CipherSuite::variants() {
            // Roundtrip: display -> from_str
            assert_eq!(
                CipherSuite::from_str(&format!("{}", v)).expect("can parse"),
                v);
        }
    }

    #[test]
    fn ciphersuite_display() {
        // Make sure everything is lower case.
        assert_eq!(&CipherSuite::Rsa3k.to_string(), "rsa3k");

        for v in CipherSuite::variants() {
            let s = format!("{}", v);
            assert!(s.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit()
            }));
        }
    }
}
