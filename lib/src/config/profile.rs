//! OpenPGP profiles.

use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

use sequoia_openpgp as openpgp;
use openpgp::Profile as SqProfile;

/// A wrapper type for Sequoia's Profile type.
///
/// Profiles select versions of the OpenPGP standard.
///
/// This is a wrapper type for [`sequoia_openpgp::Profile`], which
/// implements [`std::str::FromStr`], [`std::fmt::Display`],
/// [`std::fmt::Debug`], [`std::string::ToString`], and
/// [`std::default::Default`].
///
/// `Display` and `Debug` display the string as lower-case, and
/// `FromStr` only matches on lower-case strings, which are the
/// acceptable values for the configuration file.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[non_exhaustive]
pub enum Profile {
    /// RFC9580, published in 2024, defines "v6" OpenPGP.
    RFC9580,

    /// RFC4880, published in 2007, defines "v4" OpenPGP.
    #[default]
    RFC4880,

    // If you add a variant here, be sure to update
    // Profile::variants below.
}

impl Profile {
    /// Returns an iterator over Profile’s variants.
    pub fn variants() -> impl Iterator<Item = Self> {
        use Profile::*;

        [ RFC9580, RFC4880 ].into_iter()
    }
}

impl From<&Profile> for SqProfile {
    fn from(value: &Profile) -> Self {
        match value {
            Profile::RFC9580 => SqProfile::RFC9580,
            Profile::RFC4880 => SqProfile::RFC4880,
        }
    }
}

impl From<Profile> for SqProfile {
    fn from(value: Profile) -> Self {
        SqProfile::from(&value)
    }
}

const PROFILE_MAP: &[(&str, Profile)] = &[
    // This must be sorted so that it can be used with
    // [`slice::binary_search`].
    ("rfc4880", Profile::RFC4880),
    ("rfc9580", Profile::RFC9580),
];

impl Display for Profile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (as_str, variant) in PROFILE_MAP.iter() {
            if variant == self {
                return write!(f, "{}", as_str);
            }
        }
        unreachable!("PROFILE_MAP is inconsistent");
    }
}

impl Debug for Profile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

impl FromStr for Profile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Make sure it is sorted.
        debug_assert!(
            PROFILE_MAP.windows(2).all(|window| {
                window[0].0 < window[1].0
            }),
            "PROFILE_MAP not sorted");

        match PROFILE_MAP.binary_search_by(|&(probe, _)| {
            probe.cmp(s)
        }) {
            Ok(i) => Ok(PROFILE_MAP[i].1.clone()),
            Err(_) => {
                Err(anyhow::anyhow!("{:?} is not a valid profile", s))
            }
        }
    }
}

impl Profile {
    /// Unwraps the wrapped value.
    ///
    /// Returns the underlying [`sequoia_openpgp::Profile`].
    pub fn as_profile(&self) -> sequoia_openpgp::Profile {
        SqProfile::from(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_from_str() {
        assert_eq!(Profile::from_str("rfc4880").expect("can parse"),
                   Profile::RFC4880);
        assert!(Profile::from_str("RFC4880").is_err());

        for v in Profile::variants() {
            // Roundtrip: display -> from_str
            assert_eq!(
                Profile::from_str(&format!("{}", v)).expect("can parse"),
                v);
        }
    }

    #[test]
    fn profile_display() {
        // Make sure everything is lower case.
        assert_eq!(&Profile::RFC4880.to_string(), "rfc4880");

        for v in Profile::variants() {
            let s = format!("{}", v);
            // Only lower-case ascii or digits.
            assert!(s.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit()
            }));
        }
    }
}
