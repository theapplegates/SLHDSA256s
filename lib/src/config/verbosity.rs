//! OpenPGP profiles.

use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

/// How verbose the UI should be.
///
/// This type does not implement `clap::ValueEnum`.  That would add an
/// argument that takes the verbosity level as a value, which is
/// unusual.  The typical pattern is to have `-v` and `-q` flags,
/// which set the verbosity accordingly.
#[derive(Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Verbosity {
    /// Be more verbose.
    Verbose,

    /// The standard amount of output.
    #[default]
    Default,

    /// Be more quiet.
    Quiet,

    // If you add a variant here, be sure to update
    // Verbosity::variants below.
}

impl Verbosity {
    /// Returns an iterator over Verbosity’s variants.
    pub fn variants() -> impl Iterator<Item = Self> {
        use Verbosity::*;

        [ Verbose, Default, Quiet ].into_iter()
    }
}

const VERBOSITY_MAP: &[(&str, Verbosity)] = &[
    // This must be sorted so that it can be used with
    // [`slice::binary_search`].
    ("default", Verbosity::Default),
    ("quiet", Verbosity::Quiet),
    ("verbose", Verbosity::Verbose),
];

impl Display for Verbosity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (as_str, variant) in VERBOSITY_MAP.iter() {
            if variant == self {
                return write!(f, "{}", as_str);
            }
        }
        unreachable!("VERBOSITY_MAP is inconsistent");
    }
}

impl Debug for Verbosity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

impl FromStr for Verbosity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Make sure it is sorted.
        debug_assert!(
            VERBOSITY_MAP.windows(2).all(|window| {
                window[0].0 < window[1].0
            }),
            "VERBOSITY_MAP not sorted");

        match VERBOSITY_MAP.binary_search_by(|&(probe, _)| {
            probe.cmp(s)
        }) {
            Ok(i) => Ok(VERBOSITY_MAP[i].1.clone()),
            Err(_) => {
                Err(anyhow::anyhow!("{:?} is not a valid profile", s))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_from_str() {
        assert_eq!(Verbosity::from_str("verbose").expect("can parse"),
                   Verbosity::Verbose);
        assert!(Verbosity::from_str("VERBOSE").is_err());
        assert!(Verbosity::from_str("Verbose").is_err());

        for v in Verbosity::variants() {
            // Roundtrip: display -> from_str
            assert_eq!(
                Verbosity::from_str(&format!("{}", v)).expect("can parse"),
                v);
        }
    }

    #[test]
    fn profile_display() {
        // Make sure everything is lower case.
        assert_eq!(&Verbosity::Verbose.to_string(), "verbose");

        for v in Verbosity::variants() {
            let s = format!("{}", v);
            // Only lower-case ascii or digits.
            assert!(s.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit()
            }));
        }
    }
}
