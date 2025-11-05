//! Signature verification.
//!
//! # Examples
//!
//! Verify a message and just get the verified message or a succinct
//! error message; the structured output that includes information
//! about the signatures is discarded:
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::verify;
//!
//! # fn main() -> anyhow::Result<()> {
//! let message = b"-----BEGIN PGP MESSAGE-----
//!
//! xA0DAAoW0fHeyI2faiIAxA0DAAoWXBlCBA8F6L4BywpiAAAAAABmb28Kwr0EABYK
//! # AG8FgmjVMzYJEFwZQgQPBei+RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVv
//! # aWEtcGdwLm9yZ+1bBHsT0PK4Q2lkuDHQ5CTbOWeHYnKAw9RbOdsin32FFiEE6eay
//! # LiUrXUk+zRphXBlCBA8F6L4AAG4nAQDNliWncs/fB8lVnkjxFDmFCs9FZGgNwbyQ
//! # RtE0xafNdQD/a7Yy7OIV23HNmVAuNJfnKIqxkeASat/r9gdc5byB1wnCvQQAFgoA
//! # bwWCaNUzNgkQ0fHeyI2faiJHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9p
//! # YS1wZ3Aub3JnbYs5xov77H9AAHQzFUoyI5qWFWUM0LHPXKQElGAUD1IWIQQiEsNi
//! # c1VLB0KxSYrR8d7IjZ9qIgAAJisBAPttuQBJJOVcqd0zV1bDX8I9LNgXt4mIXRM7
//! # ewZfwAjvAQC/LZc4j2tBqAxV5ORGXtArETa3r+ekLOD+hGLpo8j+Ag==
//! # =yiKW
//! # -----END PGP MESSAGE-----";
//! // ...";
//!
//! // Initialize Sequoia.
//! let sequoia = Sequoia::builder().stateless().build()?;
//!
//! // Verify the message and store the verified data in output.
//! let mut output = Vec::new();
//! if let Err(err) = sequoia
//!     .verify()
//!     .inline_signature(
//!         std::io::Cursor::new(message),
//!         &mut output,
//!         // Discards the structured output.
//!         ())
//! {
//!     eprintln!("Failed to verify message: {}.", err);
//! } else {
//!     // The signed data is in `output`.
//!     eprintln!("Verified message.");
//! }
//! # Ok(()) }
//! ```
//!
//! Verify a message and examine the structured output.  This example
//! shows how to implement [`Stream`], and how to pick apart the
//! [`Output`] and [`output::MessageStructure`] structs to determine
//! the status of any [`output::Signature`]s.
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::verify;
//!
//! # fn main() -> anyhow::Result<()> {
//! struct VerifyOutputHandler<'a> {
//!     sequoia: &'a sequoia::Sequoia,
//! }
//!
//! impl verify::Stream for &mut VerifyOutputHandler<'_> {
//!     fn output(&mut self, _params: &verify::Params, output: verify::Output)
//!         -> sequoia::Result<()>
//!     {
//!         match output {
//!             verify::Output::MessageStructure(structure) => {
//!                 // Iterate over the message's layers.
//!                 for layer in structure.layers {
//!                     match layer {
//!                         // Examine the signatures.
//!                         verify::output::MessageLayer::Signature(
//!                             verify::output::message_layer::SignatureLayer {
//!                                 sigs,
//!                                 ..
//!                              }) =>
//!                         {
//!                             for sig in sigs {
//!                                 match sig.status {
//!                                     verify::output::SignatureStatus::Verified(
//!                                         verify::output::signature_status::Verified {
//!                                             cert,
//!                                             ..
//!                                         }) =>
//!                                      {
//!                                          eprintln!("Verified signature from {}, {}.",
//!                                                    cert.fingerprint(),
//!                                                    self.sequoia.best_userid(
//!                                                        &cert, true).display());
//!                                      }
//!                                      // Handle other signature statuses if you want.
//!                                      _ => (),
//!                                 }
//!                             }
//!                         }
//!                         // Ignore the non-signature layers.
//!                         _ => (),
//!                     }
//!                 }
//!            }
//!            verify::Output::Report(report) => {
//!                if report.authenticated {
//!                    eprintln!("Verified message");
//!                }
//!            }
//!            // Ignore other output.
//!            _ => (),
//!         }
//!
//!         // If we return an error, processing is aborted and the
//!         // error is immediately returned to the caller.
//!         Ok(())
//!     }
//! }
//!
//! let message = b"-----BEGIN PGP MESSAGE-----
//!
//! xA0DAAoW0fHeyI2faiIAxA0DAAoWXBlCBA8F6L4BywpiAAAAAABmb28Kwr0EABYK
//! # AG8FgmjVMzYJEFwZQgQPBei+RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVv
//! # aWEtcGdwLm9yZ+1bBHsT0PK4Q2lkuDHQ5CTbOWeHYnKAw9RbOdsin32FFiEE6eay
//! # LiUrXUk+zRphXBlCBA8F6L4AAG4nAQDNliWncs/fB8lVnkjxFDmFCs9FZGgNwbyQ
//! # RtE0xafNdQD/a7Yy7OIV23HNmVAuNJfnKIqxkeASat/r9gdc5byB1wnCvQQAFgoA
//! # bwWCaNUzNgkQ0fHeyI2faiJHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9p
//! # YS1wZ3Aub3JnbYs5xov77H9AAHQzFUoyI5qWFWUM0LHPXKQElGAUD1IWIQQiEsNi
//! # c1VLB0KxSYrR8d7IjZ9qIgAAJisBAPttuQBJJOVcqd0zV1bDX8I9LNgXt4mIXRM7
//! # ewZfwAjvAQC/LZc4j2tBqAxV5ORGXtArETa3r+ekLOD+hGLpo8j+Ag==
//! # =yiKW
//! # -----END PGP MESSAGE-----";
//! // ...";
//!
//! // Initialize Sequoia.
//! let sequoia = Sequoia::builder().stateless().build()?;
//!
//! // Verify the message and store the verified data in output.
//! let mut output = Vec::new();
//! let mut output_handler = VerifyOutputHandler {
//!     sequoia: &sequoia,
//! };
//! if let Err(err) = sequoia.verify()
//!     .inline_signature(
//!         std::io::Cursor::new(message),
//!         &mut output,
//!         &mut output_handler)
//! {
//!     eprintln!("Failed to verify message: {}.", err);
//! } else {
//!     // The signed data is in `output`.
//!     eprintln!("Verified message.");
//! }
//! # Ok(()) }
//! ```

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashSet, btree_map::{BTreeMap, Entry}};
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use sequoia_openpgp::parse::buffered_reader;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyID;
use openpgp::packet::UserID;
use openpgp::packet;
use openpgp::parse::Parse;
use openpgp::parse::stream::DetachedVerifierBuilder;
use openpgp::parse::stream::VerificationError;
use openpgp::parse::stream::VerificationResult;
use openpgp::parse::stream::VerifierBuilder;
use openpgp::parse::stream;
use openpgp::types::AEADAlgorithm;
use openpgp::types::CompressionAlgorithm;
use openpgp::types::SymmetricAlgorithm;

use sequoia_cert_store::Store;
use sequoia_wot::store::Store as _;

use crate::Result;
use crate::Sequoia;
use crate::decrypt;
use crate::inspect::Kind;

const TRACE: bool = false;

/// The trait for collecting output.
pub trait Stream {
    /// Output from [`inline_signature`](Builder::inline_signature)
    /// and [`detached_signature`](Builder::detached_signature).
    fn output(&mut self, params: &Params, output: Output) -> Result<()>;
}

impl<T> Stream for Box<T>
where
    T: Stream + ?Sized
{
    fn output(&mut self, params: &Params, output: Output) -> Result<()> {
        self.as_mut().output(params, output)
    }
}

/// Collects the output in the specified vector.
impl Stream for &mut Vec<Output> {
    fn output(&mut self, _params: &Params, output: Output) -> Result<()> {
        self.push(output);
        Ok(())
    }
}

/// Discards the output.
impl Stream for () {
    fn output(&mut self, _params: &Params, _output: Output) -> Result<()> {
        Ok(())
    }
}

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// Web of Trust-specific authentication information.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct WebOfTrust {
        /// The maximum authentication level of any user ID.
        ///
        /// 120 means fully authenticated.
        pub authentication_level: usize,

        /// The authentication paths in the web of trust for each user
        /// ID.
        ///
        /// Self-signed user IDs that could not be authenticated
        /// (i.e., those for which there is no path from a trust root)
        /// are still included.
        pub authentication_paths: Vec<(UserID, sequoia_wot::Paths)>,
    }

    /// Direct authentication-specific authentication information.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Direct {
    }

    /// Data structures related to [`SignatureStatus`].
    pub mod signature_status {
        use super::*;

        /// A verified signature.
        ///
        /// A signature is considered verified if the signature is
        /// mathematically correct, and either at least one user ID
        /// (not necessarily a self-signed user ID) could be
        /// authenticated for the signer's certificate using the web
        /// of trust, or the certificate is considered authenticated
        /// (see [`Builder::designated_signers`]).
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct Verified {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The key that made the signature.
            pub key: Fingerprint,

            /// Web of trust authentication information.
            pub wot: Option<WebOfTrust>,

            /// Direct authentication information.
            ///
            /// See [`Builder::designated_signers`].
            pub direct: Option<Direct>,
        }

        /// A signature that could be mathemtically verified, but the
        /// signer's certificate could not be authenticated.
        ///
        /// This is called `GoodChecksum`, because a signature whose
        /// signer cannot be authenticated is no better than a
        /// checksum.
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct GoodChecksum {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The key that made the signature.
            pub key: Fingerprint,

            /// Web of trust authentication information.
            pub wot: Option<WebOfTrust>,

            /// Direct authentication information.
            ///
            /// See [`Builder::designated_signers`].
            pub direct: Option<Direct>,
        }

        /// Missing key.
        ///
        /// A certificate that includes the alleged issuer's key is
        /// not available.
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct MissingKey {
            /// The signature.
            pub sig: packet::Signature,
        }

        /// Unbound key.
        ///
        /// There is no valid binding signature at the time the
        /// signature was created under the given policy.
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct UnboundKey {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The reason why the key is not bound.
            pub error: anyhow::Error,
        }

        /// Bad key.
        ///
        /// We have a key, but it is not alive, etc.
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct BadKey {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The key that made the signature.
            pub key: Fingerprint,

            /// The reason why the key is bad.
            pub error: anyhow::Error,
        }

        /// Bad signature.
        ///
        /// We have a valid key, but the signature isn't valid.
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct BadSignature {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The key that made the signature.
            pub key: Fingerprint,

            /// The reason why the signature isn't valid.
            pub error: anyhow::Error,
        }

        /// Malformed signature.
        ///
        /// The signature is malformed.  This could be because it does
        /// not include a signature creation subpacket.
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct MalformedSignature {
            /// The signature.
            pub sig: packet::Signature,

            /// The reason why the signature is malformed.
            pub error: anyhow::Error,
        }

        /// A signature that we failed to parse.
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct UnknownSignature {
            /// The signature parsed into an [`Unknown`] packet.
            ///
            /// You can get the parse error using [`Unknown::error`].
            ///
            /// [`Unknown`]: sequoia_openpgp::packet::Unknown
            /// [`Unknown::error`]: sequoia_openpgp::packet::Unknown::error
            pub sig: packet::Unknown,
        }

        /// An unknown error occurred.
        ///
        /// This may happen if your application is using a newer
        /// version of `sequoia_openpgp` than your code is prepared
        /// for.
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct Unknown {
            /// The unknown `VerificationResult` as an error.
            pub error: anyhow::Error,
        }
    }

    /// A signature's verification status.
    #[non_exhaustive]
    #[derive(Debug)]
    pub enum SignatureStatus {
        Verified(signature_status::Verified),
        GoodChecksum(signature_status::GoodChecksum),
        MissingKey(signature_status::MissingKey),
        UnboundKey(signature_status::UnboundKey),
        BadKey(signature_status::BadKey),
        BadSignature(signature_status::BadSignature),
        MalformedSignature(signature_status::MalformedSignature),
        UnknownSignature(signature_status::UnknownSignature),
        Unknown(signature_status::Unknown),
    }

    impl SignatureStatus {
        /// Returns whether the signature could be verified.
        ///
        /// A signature is considered verified if the signature is
        /// mathematically correct, and either at least one user ID
        /// (not necessarily a self-signed user ID) could be
        /// authenticated for the signer's certificate using the web
        /// of trust, or the certificate is considered authenticated
        /// (see [`Builder::designated_signers`]).
        pub fn verified(&self) -> bool {
            matches!(self, SignatureStatus::Verified(_))
        }

        /// Returns the signature.
        ///
        /// Returns `None` for
        /// [`UnknownSignature`](SignatureStatus::UnknownSignature).
        /// It is still possible to get the raw signature data from an
        /// `UnknownSignature` by matching on the field.
        pub fn signature(&self) -> Option<&packet::Signature> {
            use signature_status::*;

            match self {
                SignatureStatus::Verified(Verified { sig, .. }) => Some(sig),
                SignatureStatus::GoodChecksum(GoodChecksum { sig, .. }) => Some(sig),
                SignatureStatus::MissingKey(MissingKey { sig, .. }) => Some(sig),
                SignatureStatus::UnboundKey(UnboundKey { sig, .. }) => Some(sig),
                SignatureStatus::BadKey(BadKey { sig, .. }) => Some(sig),
                SignatureStatus::BadSignature(BadSignature { sig, .. }) => Some(sig),
                SignatureStatus::MalformedSignature(MalformedSignature { sig, .. }) => Some(sig),
                SignatureStatus::UnknownSignature(UnknownSignature { .. }) => None,
                SignatureStatus::Unknown(Unknown { .. }) => None,
            }
        }

        /// Returns a certificate with the signing key that made the
        /// signature.
        ///
        /// Returns `None` if the certificate is not available.
        pub fn cert(&self) -> Option<&Cert> {
            use signature_status::*;

            match self {
                SignatureStatus::Verified(Verified { cert, .. }) => Some(cert),
                SignatureStatus::GoodChecksum(GoodChecksum { cert, .. }) => Some(cert),
                SignatureStatus::MissingKey(MissingKey { .. }) => None,
                SignatureStatus::UnboundKey(UnboundKey { cert, .. }) => Some(cert),
                SignatureStatus::BadKey(BadKey { cert, .. }) => Some(cert),
                SignatureStatus::BadSignature(BadSignature { cert, .. }) => Some(cert),
                SignatureStatus::MalformedSignature(MalformedSignature { .. }) => None,
                SignatureStatus::UnknownSignature(UnknownSignature { .. }) => None,
                SignatureStatus::Unknown(Unknown { .. }) => None,
            }
        }

        /// Returns the key that made the signature.
        ///
        /// Returns `None` if the key is not known.
        pub fn key(&self) -> Option<&Fingerprint> {
            use signature_status::*;

            match self {
                SignatureStatus::Verified(Verified { key, .. }) => Some(key),
                SignatureStatus::GoodChecksum(GoodChecksum { key, .. }) => Some(key),
                SignatureStatus::MissingKey(MissingKey { .. }) => None,
                SignatureStatus::UnboundKey(UnboundKey { .. }) => None,
                SignatureStatus::BadKey(BadKey { key, .. }) => Some(key),
                SignatureStatus::BadSignature(BadSignature { key, .. }) => Some(key),
                SignatureStatus::MalformedSignature(MalformedSignature { .. }) => None,
                SignatureStatus::UnknownSignature(UnknownSignature { .. }) => None,
                SignatureStatus::Unknown(Unknown { .. }) => None,
            }
        }

        /// Returns the related error.
        ///
        /// Returns `None` if no related error is available.  Note:
        /// even if there is no related error, that does not mean that
        /// the signature was verified.
        pub fn error(&self) -> Option<&anyhow::Error> {
            use signature_status::*;

            match self {
                SignatureStatus::Verified(Verified { .. }) => None,
                SignatureStatus::GoodChecksum(GoodChecksum { .. }) => None,
                SignatureStatus::MissingKey(MissingKey { .. }) => None,
                SignatureStatus::UnboundKey(UnboundKey { error, .. }) => Some(error),
                SignatureStatus::BadKey(BadKey { error, .. }) => Some(error),
                SignatureStatus::BadSignature(BadSignature { error, .. }) => Some(error),
                SignatureStatus::MalformedSignature(MalformedSignature { error, .. }) => Some(error),
                SignatureStatus::UnknownSignature(UnknownSignature { .. }) => None,
                SignatureStatus::Unknown(Unknown { error, .. }) => Some(error),
            }
        }
    }

    /// Miscellaneous information about a signature.
    ///
    /// The variants contain miscellaneous information about a
    /// signature.  This could be displayed under more information or
    /// as warnings.
    #[non_exhaustive]
    #[derive(Debug)]
    pub enum SignatureInfo {
        /// The signer's certificate can't be authenticated, because
        /// it has no user IDs.
        NoUserIDs,
    }

    /// A signature.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Signature {
        /// The signature's status.
        pub status: SignatureStatus,

        /// Miscellaneous information about the signature.
        pub info: Vec<SignatureInfo>,
    }

    impl Signature {
        /// Returns whether the signature could be verified.
        ///
        /// A signature is considered verified if the signature is
        /// mathematically correct, and either at least one user ID
        /// (not necessarily a self-signed user ID) could be
        /// authenticated for the signer's certificate using the web
        /// of trust, or the certificate is considered authenticated
        /// (see [`Builder::designated_signers`]).
        pub fn verified(&self) -> bool {
            self.status.verified()
        }

        /// Returns the signature.
        ///
        /// Returns `None` for
        /// [`UnknownSignature`](SignatureStatus::UnknownSignature).
        /// It is still possible to get the raw signature data from an
        /// `UnknownSignature` by matching on the field.
        pub fn signature(&self) -> Option<&packet::Signature> {
            self.status.signature()
        }

        /// Returns a certificate with the signing key that made the
        /// signature.
        ///
        /// Returns `None` if the certificate is not available.
        pub fn cert(&self) -> Option<&Cert> {
            self.status.cert()
        }

        /// Returns the key that made the signature.
        ///
        /// Returns `None` if the key is not known.
        pub fn key(&self) -> Option<&Fingerprint> {
            self.status.key()
        }

        /// Returns the related error.
        ///
        /// Returns `None` if no related error is available.  Note:
        /// even if there is no related error, that does not mean that
        /// the signature was verified.
        pub fn error(&self) -> Option<&anyhow::Error> {
            self.status.error()
        }
    }

    /// Data structures related to [`MessageLayer`].
    pub mod message_layer {
        use super::*;

        /// Information about a message's signature layer.
        ///
        /// See [`MessageLayer`].
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct SignatureLayer {
            pub sigs: Vec<Signature>,
        }

        /// Information about a message's compression layer.
        ///
        /// See [`MessageLayer`].
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct CompressionLayer {
            pub algo: CompressionAlgorithm,
        }

        /// Information about a message's encryption layer.
        ///
        /// See [`MessageLayer`].
        #[non_exhaustive]
        #[derive(Debug)]
        pub struct EncryptionLayer {
            pub sym_algo: SymmetricAlgorithm,
            pub aead_algo: Option<AEADAlgorithm>,
        }
    }

    /// The layers of an OpenPGP message.
    ///
    /// A valid OpenPGP message contains one literal data packet with
    /// optional encryption, signing, and compression layers freely
    /// combined on top.
    #[non_exhaustive]
    #[derive(Debug)]
    pub enum MessageLayer {
        Signature(message_layer::SignatureLayer),
        Compression(message_layer::CompressionLayer),
        Encryption(message_layer::EncryptionLayer),
    }

    /// Information about an OpenPGP message's structure.
    ///
    /// This data structure contains information about an OpenPGP
    /// message's structure; it does not include the message's
    /// content.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct MessageStructure {
        pub layers: Vec<MessageLayer>,
    }

    /// Information about the operation.
    ///
    /// This includes summary statistics.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Report {
        /// Whether enough signatures could be verified.
        ///
        /// A signature is considered verified if the signature is
        /// mathematically correct, and either at least one user ID
        /// (not necessarily a self-signed user ID) could be
        /// authenticated for the signer's certificate using the web
        /// of trust, or the certificate is considered authenticated
        /// (see [`Builder::designated_signers`]).
        pub authenticated: bool,

        /// The number of authenticated signatures.
        ///
        /// See [`SignatureStatus::Verified`].
        pub authenticated_signatures: usize,

        /// The number of mathematically correct signatures whose
        /// signer could not be authenticated.
        ///
        /// See [`SignatureStatus::GoodChecksum`].
        pub unauthenticated_signatures: usize,

        /// Signatures that could not be checked, because the key is
        /// missing.
        ///
        /// See [`SignatureStatus::MissingKey`].
        pub uncheckable_signatures: usize,

        /// The number of signatures that could not be checked,
        /// because the signature was bad.
        ///
        /// See [`SignatureStatus::UnknownSignature`] and
        /// [`SignatureStatus::BadSignature`].
        pub bad_signatures: usize,

        /// The number of signatures that could not be checked,
        /// because the key or certificate was bad.
        ///
        /// See [`SignatureStatus::UnboundKey`] and
        /// [`SignatureStatus::BadKey`].
        pub broken_keys: usize,

        /// The number of signatures that are broken.
        ///
        /// See [`SignatureStatus::MalformedSignature`].
        pub broken_signatures: usize,
    }
}

/// The variants of this enum are the different types of output that
/// [`inline_signature`](Builder::inline_signature) and
/// [`detached_signature`](Builder::detached_signature) emit.
#[non_exhaustive]
#[derive(Debug)]
pub enum Output {
    MessageStructure(output::MessageStructure),
    Report(output::Report),
}

impl Sequoia {
    /// Returns a builder for verifying messages.
    ///
    /// See [`Builder`] for details.
    pub fn verify(&self) -> Builder<'_>
    {
        Builder {
            params: Params {
                sequoia: self,
                detached_sig_arg: None,
                detached_sig_value: None,
                signatures: 1,
                designated_signers: None,
            }
        }
    }
}

/// Parameters to the verify function.
///
/// The parameters passed to
/// [`inline_signature`](Builder::inline_signature) and
/// [`detached_signature`](Builder::detached_signature).
#[derive(Clone)]
pub struct Params<'sequoia> {
    pub(crate) sequoia: &'sequoia Sequoia,
    // XXX transitional: Remove once we fix Kind::identify.
    pub(crate) detached_sig_arg: Option<String>,
    pub(crate) detached_sig_value: Option<PathBuf>,
    pub(crate) signatures: usize,
    pub(crate) designated_signers: Option<Vec<Cert>>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        self.sequoia
    }

    /// Returns the number of signatures that have to be authenticated
    /// for the verification to succeed.
    pub fn signatures(&self) -> usize {
        self.signatures
    }

    /// Returns the set of designated signers.
    pub fn designated_signers(&self) -> Option<&[Cert]> {
        self.designated_signers.as_deref()
    }

    // If you add any methods here, add forwarders in decrypt::Params.
}

/// Verify signatures.
///
/// This command builder is used to verify signatures.
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia> {
    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Sets the number of required authenticated signatures.
    ///
    /// By default there must be one authenticated signature.  Note: a
    /// mathematically correct signature is not considered
    /// authenticated; at least one of the user IDs on the signer's
    /// certificate must also be fully authenticated.
    pub fn signatures(&mut self, signatures: usize) -> &mut Self {
        self.params.signatures = signatures;

        self
    }

    /// Sets the designated signers.
    ///
    /// The specified certificates (and no other certificates) are
    /// considered authenticated.
    ///
    /// By default, signer certificates are authenticated using the
    /// web of trust using certificates from the certificate store
    /// (unless disabled with [`SequoiaBuilder::stateless`]) and any
    /// configured keyrings (see [`SequoiaBuiler::add_keyring`]).
    /// This disables the use of the web of trust and only considers
    /// signatures by the specified certificates.
    ///
    ///   [`SequoiaBuilder::stateless`]: crate::SequoiaBuilder::stateless
    ///   [`SequoiaBuiler::add_keyring`]: crate::SequoiaBuilder::add_keyring
    pub fn designated_signers(&mut self, certs: Vec<Cert>) -> &mut Self {
        self.params.designated_signers = Some(certs);

        self
    }

    /// XXX transitional: remove once presentation is moved back to
    /// sq.
    pub fn detached_args(&mut self, detached_sig_arg: Option<&str>,
                         detached_sig_value: &Path)
        -> &mut Self
    {
        self.params.detached_sig_arg
            = detached_sig_arg.map(|a| a.to_string());
        self.params.detached_sig_value = Some(detached_sig_value.to_path_buf());

        self
    }

    /// Verifies an inline signing message.
    ///
    /// An inline-signed message is an OpenPGP message that includes
    /// one or more signatures and the signed data.  If the signatures
    /// and the data are stored separately, you have a detached
    /// signature.
    ///
    /// Returns `Ok` if the message could be verified according to the
    /// policy.  (You can configure the signing policy using
    /// [`Builder::signatures`] and [`Builder::designated_signers`].)
    ///
    /// The verified data is written to `output`.  If you don't plan
    /// to consume the verified data, you can pass pass an instance of
    /// `std::io::Empty`, which is normally created by calling
    /// `std::io::empty`.  If you do plan to consume the verified
    /// data, you should not use the input, but save the output and
    /// use that.  This avoids TOUTOC errors, and, accidentally using
    /// the wrong data.
    ///
    /// `stream` allows you to stream the status information.  If you
    /// don't want to stream the status information, you can pass a
    /// mutable reference to a `Vec<Output>`.  If you don't care about
    /// the status information, you can pass `()`.
    pub fn inline_signature<I, O, S>(&self, input: I, output: O, stream: S)
        -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream,

    {
        self.execute_stream(input, None::<std::io::Empty>, output, stream)
    }

    /// Verifies an inline signing message.
    ///
    /// An inline-signed message is an OpenPGP message that includes
    /// one or more signatures and the signed data.  If the signatures
    /// and the data are stored separately, you have a detached
    /// signature.
    ///
    /// Returns `Ok` if the message could be verified according to the
    /// policy.  (You can configure the signing policy using
    /// [`Builder::signatures`] and [`Builder::designated_signers`].)
    ///
    /// The verified data is written to `output`.  If you don't plan
    /// to consume the verified data, you can pass pass an instance of
    /// `std::io::Empty`, which is normally created by calling
    /// `std::io::empty`.  If you do plan to consume the verified
    /// data, you should not use the input, but save the output and
    /// use that.  This avoids TOUTOC errors, and, accidentally using
    /// the wrong data.
    ///
    /// `stream` allows you to stream the status information.  If you
    /// don't want to stream the status information, you can pass a
    /// mutable reference to a `Vec<Output>`.  If you don't care about
    /// the status information, you can pass `()`.
    pub fn detached_signature<I, D, O, S>(&self, input: I, detached: D,
                                          output: O, stream: S)
        -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        D: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream,

    {
        self.execute_stream(input, Some(detached), output, stream)
    }

    /// Execute the verifier with the configured parameters.
    ///
    /// Returns `Ok` if the message could be verified.
    fn execute_stream<I, D, O, S>(&self, input: I, detached: Option<D>,
                                  mut output: O, stream: S)
        -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        D: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream,
    {
        let &Builder {
            params: Params {
                sequoia,
                ref detached_sig_arg,
                ref detached_sig_value,
                signatures,
                ref designated_signers,
            }
        } = self;

        let mut detached = if let Some(detached) = detached {
            Some(buffered_reader::Generic::with_cookie(
                detached, None, Default::default()))
        } else {
            None
        };

        let mut detached = if let Some(ref mut sig) = detached {
            let (kind, sig) = Kind::identify(sequoia, sig)?;
            kind.expect_or_else(sequoia, "verify", Kind::DetachedSig,
                                detached_sig_arg
                                .as_deref()
                                .unwrap_or("the detached signature"),
                                detached_sig_value.as_deref())?;

            Some(sig)
        } else {
            None
        };

        let proxy: Rc<RefCell<Box<dyn VerifyDecryptStream>>>
            = Rc::new(RefCell::new(Box::new(StreamProxy {
                stream: Box::new(stream),
            })));

        let mut helper = VerificationHelper::new(
            sequoia, signatures, designated_signers.clone());
        helper.stream = Some((proxy, Cow::Borrowed(&self.params)));
        let helper = if let Some(ref mut dsig) = detached {
            let mut v = DetachedVerifierBuilder::from_reader(dsig)?
                .with_policy(sequoia.policy(), Some(sequoia.time()), helper)?;
            v.verify_reader(input)?;
            v.into_helper()
        } else {
            let mut v = VerifierBuilder::from_reader(input)?
                .with_policy(sequoia.policy(), Some(sequoia.time()), helper)?;
            io::copy(&mut v, &mut output)?;
            v.into_helper()
        };

        if helper.authenticated_signatures >= signatures {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Verification failed: could not \
                                 authenticate any signatures"))
        }
    }
}

struct StreamProxy<'a> {
    stream: Box<dyn Stream + 'a>,
}

impl Stream for StreamProxy<'_>
{
    fn output(&mut self, params: &Params, output: Output)
        -> Result<()>
    {
        self.stream.output(params, output)
    }
}

impl decrypt::Stream for StreamProxy<'_>
{
    fn output(&mut self, _params: &decrypt::Params, _output: decrypt::Output)
        -> Result<()>
    {
        Ok(())
    }
}

/// A wrapper trait so that we can have a `Box<dyn verify::Stream +
/// decrypt::Stream>`.
pub(crate) trait VerifyDecryptStream: Stream + decrypt::Stream {
}

/// Implement the wrapper for everything that implements
/// verify::Stream and `Stream`.
impl<T: ?Sized> VerifyDecryptStream for T where T: Stream + decrypt::Stream {
}

pub(crate) struct VerificationHelper<'c>
{
    sequoia: &'c Sequoia,
    signatures: usize,

    pub(crate) stream: Option<(Rc<RefCell<Box<dyn VerifyDecryptStream + 'c>>>,
                               Cow<'c, Params<'c>>)>,

    /// Require signatures to be made by this set of certs.
    designated_signers: Option<Vec<Cert>>,

    trusted: HashSet<KeyID>,

    /// Tracks the inner-most encryption container encountered.
    pub sym_algo: Option<SymmetricAlgorithm>,

    // Tracks the signatures encountered.
    authenticated_signatures: usize,
    unauthenticated_signatures: usize,
    uncheckable_signatures: usize,
    bad_signatures: usize,
    broken_keys: usize,
    broken_signatures: usize,
}

impl<'c> VerificationHelper<'c> {
    pub fn new(sequoia: &'c Sequoia, signatures: usize,
               designated_signers: Option<Vec<Cert>>)
               -> Self
    {
        VerificationHelper {
            sequoia,
            signatures,
            designated_signers,
            trusted: HashSet::new(),
            sym_algo: None,
            stream: None,
            authenticated_signatures: 0,
            unauthenticated_signatures: 0,
            uncheckable_signatures: 0,
            broken_keys: 0,
            bad_signatures: 0,
            broken_signatures: 0,
        }
    }

    /// Returns the Sequoia instance.
    pub fn sequoia(&self) -> &Sequoia {
        self.sequoia
    }
}

impl<'c> stream::VerificationHelper for VerificationHelper<'c> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        let mut certs = BTreeMap::new();

        let have_designated_signers = if let Some(designated_signers)
            = self.designated_signers.as_ref()
        {
            for c in designated_signers.iter().cloned() {
                match certs.entry(c.fingerprint()) {
                    Entry::Vacant(e) => {
                        e.insert(c);
                    },
                    Entry::Occupied(mut e) => {
                        let merged = e.get().clone().merge_public(c)?;
                        e.insert(merged);
                    },
                }
            }

            // Get all keys.
            let seen: HashSet<_> = certs.values()
                .flat_map(|cert| {
                    cert.keys().map(|ka| ka.key().fingerprint().into())
                }).collect();

            // Explicitly provided keys are trusted.
            self.trusted = seen;

            true
        } else {
            false
        };

        // If we have any designated signers, we do not consider
        // certificates in the cert store: we require all signatures
        // to be made by the set of designated signers.
        if have_designated_signers {
            return Ok(certs.into_values().collect());
        }

        // Otherwise, look up the issuer IDs in the certificate store.

        // Avoid initializing the certificate store if we don't actually
        // need to.
        if ! ids.is_empty() {
            if let Some(cert_store) = self.sequoia.cert_store()? {
                for id in ids.iter() {
                    for c in cert_store.lookup_by_cert_or_subkey(id)
                        .unwrap_or_default()
                    {
                        let c = c.to_cert()?.clone();
                        match certs.entry(c.fingerprint()) {
                            Entry::Vacant(e) => {
                                e.insert(c);
                            },
                            Entry::Occupied(mut e) => {
                                let merged = e.get().clone().merge_public(c)?;
                                e.insert(merged);
                            },
                        }
                    }
                }
            }
        }

        Ok(certs.into_values().collect())
    }

    fn check(&mut self, structure: stream::MessageStructure)
             -> Result<()>
    {
        use output::message_layer::*;

        tracer!(TRACE, "VerificationHelper::check");

        let mut layers = Vec::new();

        for layer in structure {
            match layer {
                stream::MessageLayer::Compression { algo } => {
                    t!("Compression layer: {}", algo);
                    layers.push(output::MessageLayer::Compression(
                        CompressionLayer { algo }));
                },
                stream::MessageLayer::Encryption { sym_algo, aead_algo } => {
                    t!("Encryption layer: sym: {}, aead: {:?}",
                       sym_algo, aead_algo);
                    self.sym_algo = Some(sym_algo);
                    layers.push(output::MessageLayer::Encryption(
                        EncryptionLayer { sym_algo, aead_algo }));
                }
                stream::MessageLayer::SignatureGroup { results } => {
                    t!("Signature layer: {} signatures", results.len());

                    let mut sigs = Vec::new();
                    for result in results.into_iter() {
                        sigs.push(self.check_sig(result));
                    }
                    layers.push(output::MessageLayer::Signature(
                        SignatureLayer { sigs }));
                },
            }
        }

        let message_structure = output::MessageStructure { layers };

        let authenticated
            = self.authenticated_signatures >= self.signatures;

        if let Some((stream, params)) = self.stream.as_ref() {
            use std::ops::DerefMut;

            let mut stream = stream.borrow_mut();
            let stream = stream.deref_mut();

            stream.output(params,
                          Output::MessageStructure(message_structure))?;

            stream.output(
                params,
                Output::Report(output::Report {
                    authenticated,
                    authenticated_signatures: self.authenticated_signatures,
                    unauthenticated_signatures: self.unauthenticated_signatures,
                    uncheckable_signatures: self.uncheckable_signatures,
                    bad_signatures: self.bad_signatures,
                    broken_keys: self.broken_keys,
                    broken_signatures: self.broken_signatures,
                }))?;
        }

        if self.authenticated_signatures >= self.signatures {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Verification failed: could not \
                                 authenticate enough signatures"))
        }
    }
}

impl<'c> VerificationHelper<'c> {
    /// Converts a `VerificationResult` into a `Signature`.
    fn check_sig(&mut self, result: VerificationResult) -> output::Signature {
        use output::signature_status::*;

        tracer!(TRACE, "VerificationHelper::check_sig");

        let (sig, ka) = match result {
            Ok(stream::GoodChecksum { sig, ka, .. }) => (sig, ka),
            Err(VerificationError::MissingKey { sig, .. }) => {
                t!("missing key");

                self.uncheckable_signatures += 1;
                return output::Signature {
                    status: output::SignatureStatus::MissingKey(MissingKey {
                        sig: sig.clone(),
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::UnboundKey { sig, cert, error, .. }) => {
                t!("unbound key: {}", error);

                self.broken_keys += 1;
                return output::Signature {
                    status: output::SignatureStatus::UnboundKey(UnboundKey {
                        sig: sig.clone(),
                        cert: cert.clone(),
                        error,
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::BadKey { sig, ka, error, .. }) => {
                t!("bad key: {}", error);

                self.broken_keys += 1;
                return output::Signature {
                    status: output::SignatureStatus::BadKey(BadKey {
                        sig: sig.clone(),
                        cert: ka.cert().clone(),
                        key: ka.key().fingerprint(),
                        error,
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::BadSignature { sig, ka, error, .. }) => {
                t!("bad signature: {}", error);

                self.bad_signatures += 1;
                return output::Signature {
                    status: output::SignatureStatus::BadSignature(BadSignature {
                        sig: sig.clone(),
                        cert: ka.cert().clone(),
                        key: ka.key().fingerprint(),
                        error,
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::MalformedSignature { sig, error, .. }) => {
                t!("malformed signature: {}", error);

                self.broken_signatures += 1;
                return output::Signature {
                    status: output::SignatureStatus::MalformedSignature(MalformedSignature {
                        sig: sig.clone(),
                        error
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::UnknownSignature { sig, .. }) => {
                t!("unknown signature: {}", sig.error());

                self.bad_signatures += 1;
                return output::Signature {
                    status: output::SignatureStatus::UnknownSignature(UnknownSignature {
                        sig: sig.clone(),
                    }),
                    info: Vec::new(),
                };
            }
            Err(ve) => {
                t!("unhandled signature");

                return output::Signature {
                    status: output::SignatureStatus::Unknown(Unknown {
                        error: openpgp::Error::from(ve).into(),
                    }),
                    info: Vec::new(),
                };
            }
        };

        t!("good signature (not yet authenticated)");

        // The signature is mathematically correct, but we still need
        // to authenticate it.
        let cert = ka.cert();
        let cert_fpr = cert.fingerprint();
        let issuer = ka.key().keyid();

        let mut direct = None;
        let mut wot = None;
        let mut authenticated = false;
        let mut info = Vec::new();

        if self.designated_signers.is_some() {
            // Direct trust.
            direct = Some(output::Direct {});
            authenticated = self.trusted.contains(&issuer);
        } else if ! self.sequoia.trust_roots().is_empty() {
            // Web of trust.

            let trust_roots = self.sequoia.trust_roots();
            if let Ok(Some(cert_store)) = self.sequoia.cert_store() {
                let mut authentication_paths = vec![];
                let mut authentication_level = 0;

                // Build the network.
                let cert_store = sequoia_wot::store::CertStore::from_store(
                    cert_store, self.sequoia.policy(), self.sequoia.time());

                let userids =
                    cert_store.certified_userids_of(&cert_fpr);

                if userids.is_empty() {
                    info.push(output::SignatureInfo::NoUserIDs);
                } else {
                    let n = sequoia_wot::NetworkBuilder::rooted(
                        &cert_store, &*trust_roots).build();

                    let authenticated_userids
                        = userids.into_iter().filter(|userid| {
                            let paths = n.authenticate(
                                userid, cert.fingerprint(),
                                // XXX: Make this user configurable.
                                sequoia_wot::FULLY_TRUSTED);

                            let amount = paths.amount();

                            // Return if the user ID could be at least
                            // partially authenticated.
                            authentication_paths.push(
                                (userid.clone(), paths));

                            authentication_level
                                = authentication_level.max(amount);

                            amount >= sequoia_wot::FULLY_TRUSTED
                        })
                        .collect::<Vec<UserID>>();

                    if ! authenticated_userids.is_empty() {
                        authenticated = true;
                    }

                    wot = Some(output::WebOfTrust {
                        authentication_level,
                        authentication_paths,
                    });
                }
            }
        }

        let status = if authenticated {
            self.authenticated_signatures += 1;
            output::SignatureStatus::Verified(Verified {
                sig: sig.clone(),
                cert: ka.cert().clone(),
                key: ka.key().fingerprint(),
                direct,
                wot,
            })
        } else {
            self.unauthenticated_signatures += 1;
            output::SignatureStatus::GoodChecksum(GoodChecksum {
                sig: sig.clone(),
                cert: ka.cert().clone(),
                key: ka.key().fingerprint(),
                direct,
                wot,
            })
        };

        output::Signature {
            status,
            info,
        }
    }
}
