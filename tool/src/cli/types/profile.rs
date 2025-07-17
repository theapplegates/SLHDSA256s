//! OpenPGP profiles.

/// Profiles select versions of the OpenPGP standard.
#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum Profile {
    /// RFC9580, published in 2024, defines "v6" OpenPGP.
    RFC9580,

    /// RFC4880, published in 2007, defines "v4" OpenPGP.
    RFC4880,
}

impl Default for Profile {
    fn default() -> Profile {
        match sequoia::openpgp::Profile::default() {
            sequoia::openpgp::Profile::RFC9580 => Profile::RFC9580,
            sequoia::openpgp::Profile::RFC4880 => Profile::RFC4880,
            _ => Profile::RFC9580,
        }
    }
}

impl From<Profile> for sequoia::openpgp::Profile {
    fn from(p: Profile) -> Self {
        match p {
            Profile::RFC9580 => sequoia::openpgp::Profile::RFC9580,
            Profile::RFC4880 => sequoia::openpgp::Profile::RFC4880,
        }
    }
}
