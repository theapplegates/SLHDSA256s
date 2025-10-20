use sequoia_openpgp as openpgp;
use openpgp::types::SignatureType;

/// Signature mode, either binary or text.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum HashMode {
    /// Create binary signatures.
    #[default]
    Binary,

    /// Create text signatures.
    Text,
}

impl From<HashMode> for SignatureType {
    fn from(m: HashMode) -> Self {
        SignatureType::from(&m)
    }
}

impl From<&HashMode> for SignatureType {
    fn from(m: &HashMode) -> Self {
        match m {
            HashMode::Binary => SignatureType::Binary,
            HashMode::Text => SignatureType::Text,
        }
    }
}
