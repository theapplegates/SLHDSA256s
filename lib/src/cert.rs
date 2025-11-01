//! Additional functionality related to certificates.

use std::borrow::Cow;
use std::time::SystemTime;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::packet::Signature;
use openpgp::types::KeyFlags;
use openpgp::types::PublicKeyAlgorithm;

use crate::types::Convert;

pub mod import;

pub mod problem {
    use super::*;

    /// The certificate is revoked.
    ///
    /// The signatures are validated revocations.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{} is revoked", .cert)]
    pub struct CertRevoked {
        pub cert: Fingerprint,
        pub revocations: Vec<Signature>,
    }

    /// The certificate is invalid according to the policy.
    ///
    /// The error is the error returned by
    /// [`Cert::with_policy`](sequoia_openpgp::Cert::with_policy).
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("{} is invalid", .cert)]
    pub struct CertInvalid {
        pub cert: Fingerprint,
        #[source]
        pub error: anyhow::Error,
    }

    /// The certificate does not contain any usable keys with the
    /// required capabilities.
    ///
    /// The required capabilities depend on the context.  For
    /// instance, if looking for signing-capable keys, then only
    /// signing-capable keys are considered.
    ///
    /// A key is not usable if it is revoked, expired, etc.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{} has no usable {}",
            .cert,
            if .capabilities == &KeyFlags::certification() {
                "certification-capable keys"
            } else if .capabilities == &KeyFlags::signing() {
                "signing-capable keys"
            } else if .capabilities == &KeyFlags::storage_encryption() {
                "keys for storage encryption"
            } else if .capabilities == &KeyFlags::transport_encryption() {
                "keys for transport encryption"
            } else if .capabilities == &(&KeyFlags::transport_encryption()
                                         | &KeyFlags::storage_encryption()) {
                "encryption-capable keys"
            } else if .capabilities == &KeyFlags::authentication() {
                "authentication-capable keys"
            } else {
                "keys in this context"
            })]
    pub struct NoUsableKeys {
        pub cert: Fingerprint,

        /// The type of key that is being search for.
        ///
        /// The key must match all of the flags.
        pub capabilities: KeyFlags,

        /// The number of keys that have the capabilities, but are
        /// unusable, because they are, e.g., revoked.
        pub unusable: usize,
    }

    /// The key is invalid according to the policy.
    ///
    /// The error is the error returned by
    /// [`KeyAmalgamation::with_policy`](openpgp::cert::amalgamation::ValidateAmalgamation::with_policy).
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("{} is not valid",
            if .cert == .key {
                format!("{}", .cert)
            } else {
                format!("{}/{}", .cert, .key)
            })]
    pub struct KeyInvalid {
        pub cert: Fingerprint,
        pub key: Fingerprint,
        #[source]
        pub error: anyhow::Error,
    }

    /// The key is not usable, because the public key algorithm is
    /// not supported by the cryptographic backend.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{} uses {}, but that algorithm not supported",
            if .cert == .key {
                format!("{}", .cert)
            } else {
                format!("{}/{}", .cert, .key)
            },
            .algo)]
    pub struct UnsupportedAlgorithm {
        pub cert: Fingerprint,
        pub key: Fingerprint,
        pub algo: PublicKeyAlgorithm,
    }

    /// The key is not usable, because it is revoked.
    ///
    /// The signatures are validated revocations.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{} is revoked",
            if .cert == .key {
                format!("{}", .cert)
            } else {
                format!("{}/{}", .cert, .key)
            })]
    pub struct KeyRevoked {
        pub cert: Fingerprint,
        pub key: Fingerprint,
        pub revocations: Vec<Signature>,
    }

    /// The key is not usable, because it is not live.
    ///
    /// A key that is not live has either expired (its expiration
    /// time is now or earlier) or its creation time is the
    /// future.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("{} {}",
            if .cert == .key {
                format!("{}", .cert)
            } else {
                format!("{}/{}", .cert, .key)
            },
            if let Some(expiration) = .expiration_time {
                if expiration <= .reference_time {
                    format!("expired on {}",
                            expiration.convert().to_string())
                } else {
                    format!("not yet live (creation time: {})",
                            .creation_time.convert().to_string())
                }
            } else {
                format!("not yet live (creation time: {})",
                        .creation_time.convert().to_string())
            })]
    pub struct NotLive {
        pub cert: Fingerprint,
        pub key: Fingerprint,
        pub creation_time: SystemTime,
        pub expiration_time: Option<SystemTime>,
        pub reference_time: SystemTime,
        #[source]
        pub error: anyhow::Error,
    }

    impl NotLive {
        /// Returns whether the reason the certificate is not live
        /// is because it is expired.
        pub fn expired(&self) -> bool {
            if let Some(expiration_time) = self.expiration_time {
                if expiration_time <= self.reference_time {
                    return true;
                }
            }
            false
        }
    }

    /// The key is not usable, because secret key material is
    /// required, but none is present.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("No secret key material for {}",
            if .cert == .key {
                format!("{}", .cert)
            } else {
                format!("{}/{}", .cert, .key)
            })]
    pub struct MissingSecretKeyMaterial {
        pub cert: Fingerprint,
        pub key: Fingerprint,
    }
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum CertProblem {
    /// The certificate is revoked.
    ///
    /// The signatures are validated revocations.
    #[error(transparent)]
    CertRevoked(#[from] problem::CertRevoked),

    /// The certificate is invalid according to the policy.
    ///
    /// The error is the error returned by
    /// [`KeyAmalgamation::with_policy`](openpgp::cert::amalgamation::ValidateAmalgamation::with_policy).
    #[error(transparent)]
    CertInvalid(#[from] problem::CertInvalid),

    /// The certificate does not contain any usable keys with the
    /// required capabilities.
    ///
    /// The required capabilities depend on the context.  For
    /// instance, if looking for signing-capable keys, then only
    /// signing-capable keys are considered.
    ///
    /// A key is not usable if it is revoked, expired, etc.
    #[error(transparent)]
    NoUsableKeys(#[from] problem::NoUsableKeys),

    /// The key is invalid according to the policy.
    ///
    /// The error is the error returned by
    /// [`KeyAmalgamation::with_policy`](openpgp::cert::amalgamation::ValidateAmalgamation::with_policy).
    #[error(transparent)]
    KeyInvalid(#[from] problem::KeyInvalid),

    /// The key is not usable, because the public key algorithm is
    /// not supported by the cryptographic backend.
    #[error(transparent)]
    UnsupportedAlgorithm(#[from] problem::UnsupportedAlgorithm),

    /// The key is not usable, because it is revoked.
    ///
    /// The signatures are validated revocations.
    #[error(transparent)]
    KeyRevoked(#[from] problem::KeyRevoked),

    /// The key is not usable, because it is not live.
    ///
    /// A key that is not live has either expired (its expiration
    /// time is now or earlier) or its creation time is the
    /// future.
    #[error(transparent)]
    NotLive(#[from] problem::NotLive),

    /// The key is not usable, because secret key material is
    /// required, but none is present.
    #[error(transparent)]
    MissingSecretKeyMaterial(#[from] problem::MissingSecretKeyMaterial),
}

/// The certificate is not usable.
///
/// `problems` are some reasons why the certificate is not usable.  It
/// is not necessarily exhaustive, but it will normally include at
/// least one reason.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
#[error("The certificate {} is unusable{}",
        .cert.fingerprint(),
        if .problems.is_empty() {
            Cow::Borrowed("")
        } else {
            Cow::Owned(format!(": {}",
                               .problems
                               .iter()
                               .map(|p| p.to_string())
                               .collect::<Vec<String>>()
                               .join("; ")))
        })]
pub struct CertError {
    /// The certificate.
    pub cert: Cert,

    /// A not necessarily exhaustive list of the problems that the
    /// certificate has.
    pub problems: Vec<CertProblem>,
}

impl CertError {
    /// Returns the [`CertRevoked`](problem::CertRevoked) record, if
    /// any.
    pub fn cert_revoked(&self) -> Option<&problem::CertRevoked> {
        self.problems.iter().find_map(|p| {
            match p {
                CertProblem::CertRevoked(p) => Some(p),
                _ => None,
            }
        })
    }

    /// Returns the [`CertInvalid`](problem::CertInvalid) record, if
    /// any.
    pub fn cert_invalid(&self) -> Option<&problem::CertInvalid> {
        self.problems.iter().find_map(|p| {
            match p {
                CertProblem::CertInvalid(p) => Some(p),
                _ => None,
            }
        })
    }

    /// Returns the [`NoUsableKeys`](problem::NoUsableKeys) record, if
    /// any.
    pub fn no_usable_keys(&self)
        -> Option<&problem::NoUsableKeys>
    {
        self.problems.iter().find_map(|p| {
            match p {
                CertProblem::NoUsableKeys(p) => Some(p),
                _ => None,
            }
        })
    }
}
