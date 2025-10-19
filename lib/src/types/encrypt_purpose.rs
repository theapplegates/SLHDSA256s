use sequoia_openpgp as openpgp;
use openpgp::types::KeyFlags;

/// Describes the purpose of the encryption.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum EncryptPurpose {
    /// Selects subkeys marked as suitable for transport encryption.
    Transport,

    /// Selects those for encrypting data at rest.
    Storage,

    /// Selects all encryption-capable subkeys.
    Universal,
}

impl From<&EncryptPurpose> for KeyFlags {
    fn from(p: &EncryptPurpose) -> Self {
        match p {
            EncryptPurpose::Storage => {
                KeyFlags::empty().set_storage_encryption()
            }
            EncryptPurpose::Transport => {
                KeyFlags::empty().set_transport_encryption()
            }
            EncryptPurpose::Universal => KeyFlags::empty()
                .set_storage_encryption()
                .set_transport_encryption(),
        }
    }
}

impl From<EncryptPurpose> for KeyFlags {
    fn from(p: EncryptPurpose) -> Self {
        KeyFlags::from(&p)
    }
}
