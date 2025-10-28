//! Functionality for creating digital signature over data.
//!
//! This module contains functionality related to creating digital
//! signatures.
//!
//! # Examples
//!
//! Create an inline-signed message:
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::sign;
//! # use sequoia::openpgp::cert::CertBuilder;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let (cert, _) =
//! #     CertBuilder::general_purpose(Some("alice@example.org"))
//! #         .generate()?;
//! #
//! // A stateless Sequoia instance.
//! let sequoia = Sequoia::builder().stateless().build()?;
//!
//! // The message to sign.
//! let message = b"Super s3cr3t";
//!
//! let mut signed_message = Vec::new();
//! sequoia.sign()
//!     // Create an inline-signed message where the signature and the
//!     // data are combined in the output.
//!     .inline()
//!     .add_signer(cert.clone())
//!     .sign(
//!         std::io::Cursor::new(message),
//!         &mut signed_message,
//!         // Fail if the signing key is password protected.
//!         sequoia::prompt::Cancel::new(),
//!         // Ignore status reports; we only care about the result.
//!         ())?;
//! #
//! # sequoia.verify()
//! #     .designated_signers(vec![ cert ])
//! #     .inline_signature(
//! #         std::io::Cursor::new(signed_message),
//! #         std::io::empty(),
//! #         ())
//! #     .expect("Valid signature");
//! # Ok(()) }
//! ```
use anyhow::Context as _;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::Packet;
use openpgp::armor;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::parse::PacketParserResult;
use openpgp::parse::Parse;
use openpgp::parse::buffered_reader::BufferedReader;
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::Armorer;
use openpgp::serialize::stream::LiteralWriter;
use openpgp::serialize::stream::Message;
use openpgp::serialize::stream::Signer;
use openpgp::types::SignatureType;

use crate::Result;
use crate::Sequoia;
use crate::cert::CertError;
use crate::prompt;
use crate::types::HashMode;

/// The trait for collecting output.
pub trait Stream {
    /// Output from [`sign`](Builder::sign) and  [`append`](Builder::append).
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

    /// Emitted when signing fails.
    ///
    /// Provides some information about why signing was not possible.
    #[derive(Debug)]
    pub struct SigningFailed {
        /// The certificates that could not be used to generate a
        /// signature.
        ///
        /// This list is not necessarily exhaustive.  That is, if you
        /// want to sign with two certificates and both of them are
        /// problematic, the following is not guaranteed to mention
        /// both certificates.
        pub unusable_certs: Vec<CertError>,
    }

    /// Information about how we are going to sign the message before
    /// we create the actual signatures.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Signing {
        /// The signers.
        pub signers: Vec<(Cert, Fingerprint)>,
    }

    /// Information about how we signed the message after we create
    /// the actual signatures.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Signed {
    }
}

/// The variants of this enum are the different types of output that
/// [`sign`](Builder::sign) and [`append`](Builder::append) emit.
#[non_exhaustive]
#[derive(Debug)]
pub enum Output {
    /// Emitted when signing fails.
    ///
    /// Provides some information about why signing was not possible.
    SigningFailed(output::SigningFailed),

    /// Information about how we are going to sign the message before
    /// we create the actual signatures.
    Signing(output::Signing),

    /// Information about how we signed the message after we create
    /// the actual signatures.
    Signed(output::Signed),
}

impl Sequoia {
    /// Returns a builder providing control over how to generate a
    /// signature.
    ///
    /// See [`Builder`] for details.
    pub fn sign(&self) -> Builder<'_, builder::UnspecifiedSignatureType>
    {
        Builder {
            params: Params {
                sequoia: self,
                signers: Vec::new(),
                hash_mode: HashMode::Binary,
                notarize: false,
                notations: Vec::new(),

                armor_headers: Some(Vec::new()),
            },
            t: std::marker::PhantomData,
        }
    }
}

/// The signing parameters.
///
/// These parameters are used by [`sign`](Builder::sign) and
/// [`append`](Builder::append).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,

    signers: Vec<Cert>,
    hash_mode: HashMode,
    /// Creating notarizations is currently unsupported.
    ///
    /// See
    /// <https://gitlab.com/sequoia-pgp/sequoia-sq/-/commit/993a719a7429f0afa87afd6cdc47e7d60645a1b4>
    /// and <https://gitlab.com/sequoia-pgp/sequoia/-/issues/1041>.
    notarize: bool,
    notations: Vec<(bool, NotationData)>,

    /// If Some, ASCII-armor.  Otherwise, binary.
    armor_headers: Option<Vec<(String, String)>>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns the configured signers.
    pub fn signers(&self) -> impl Iterator<Item=&Cert> {
        self.signers.iter()
    }

    /// Returns the hashing mode.
    pub fn hash_mode(&self) -> HashMode {
        self.hash_mode.clone()
    }

    /// Returns the configured notations.
    pub fn notations(&self) -> impl Iterator<Item=&(bool, NotationData)> {
        self.notations.iter()
    }

    /// Returns whether ASCII-armor is enabled.
    pub fn ascii_armor(&self) -> bool {
        self.armor_headers.is_some()
    }

    /// Returns the configured ASCII-armor headers.
    pub fn ascii_armor_headers(&self) -> impl Iterator<Item=&(String, String)> {
        static EMPTY: Vec<(String, String)> = Vec::new();

        if let Some(h) = self.armor_headers.as_ref() {
            h.iter()
        } else {
            EMPTY.iter()
        }
    }
}

/// Sign messages.
///
/// A builder providing control over how to sign a message.
pub struct Builder<'sequoia, T> {
    params: Params<'sequoia>,
    t: std::marker::PhantomData<T>,
}

/// Types related to [`Builder`].
pub mod builder {
    #[cfg(doc)]
    use super::Builder;

    mod private {
        pub trait Sealed {}
    }

    /// The signature type.
    pub trait SignatureType: private::Sealed {}

    /// Indicates that an extended set of parameters are applicable to
    /// the signature type.
    ///
    /// Detached and inline signatures are rich signature types.
    /// Cleartext signatures are more constrained.
    pub trait RichSignature: private::Sealed + SignatureType {}

    /// The base signature type.
    ///
    /// Before you create a signature, you must call
    /// [`Builder::detached`], [`Builder::inline`], or [`Builder::clear`],
    /// to specify the signature type.
    #[derive(Debug)]
    pub struct UnspecifiedSignatureType;
    impl private::Sealed for UnspecifiedSignatureType {}
    impl SignatureType for UnspecifiedSignatureType {}

    /// Designates a detached signature.
    ///
    /// A detached signature is stored separately from the signed data.
    #[derive(Debug)]
    pub struct DetachedSignature;
    impl private::Sealed for DetachedSignature {}
    impl SignatureType for DetachedSignature {}
    impl RichSignature for DetachedSignature {}

    /// Designates an inline-signed message.
    ///
    /// In an inline-signed message, the signature is stored with the
    /// signed data.
    #[derive(Debug)]
    pub struct InlineSignature;
    impl private::Sealed for InlineSignature {}
    impl SignatureType for InlineSignature {}
    impl RichSignature for InlineSignature {}

    /// Designates a cleartext signed message.
    ///
    /// A [cleartext-signed message] is an inline signed text message
    /// that has not been ASCII-armored.  The result is that the
    /// message remains readable.
    ///
    /// The cleartext signature framework normalizes line endings,
    /// trims trailing whitespace, and dash escapes lines starting
    /// with a dash.
    ///
    ///   [cleartext-signed message]: https://www.rfc-editor.org/rfc/rfc9580.html#name-cleartext-signature-framewo
    #[derive(Debug)]
    pub struct CleartextSignature;
    impl private::Sealed for CleartextSignature {}
    impl SignatureType for CleartextSignature {}
}

impl<'sequoia> Builder<'sequoia, builder::UnspecifiedSignatureType>
{
    /// Sets that a detached signature should be created.
    ///
    /// When generating an inline-signed message, the data being
    /// signed is included with the signature.  When generated a
    /// [detached signature], only a signature is created.  This means
    /// that an inline-signed message is mostly self contained whereas
    /// someone who wants to use a detached signature needs a copy of
    /// the signed data.
    ///
    ///   [detached signature]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.4
    pub fn detached(self) -> Builder<'sequoia, builder::DetachedSignature>
    {
        Builder {
            params: self.params,
            t: std::marker::PhantomData,
        }
    }

    /// Sets that an inline-signed message should be created.
    ///
    /// When generating an inline-signed message, the data being
    /// signed is included with the signature.  When generated a
    /// [detached signature], only a signature is created.  This means
    /// that an inline-signed message is mostly self contained whereas
    /// someone who wants to use a detached signature needs a copy of
    /// the signed data.
    ///
    ///   [detached signature]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.4
    pub fn inline(self) -> Builder<'sequoia, builder::InlineSignature>
    {
        Builder {
            params: self.params,
            t: std::marker::PhantomData,
        }
    }

    /// Sets that a cleartext signed message should be created.
    ///
    /// A [cleartext-signed message] is an inline signed text message
    /// that has not been ASCII-armored.  The result is that the
    /// message remains readable.
    ///
    /// The cleartext signature framework normalizes line endings,
    /// trims trailing whitespace, and dash escapes lines starting
    /// with a dash.
    ///
    ///   [cleartext-signed message]: https://www.rfc-editor.org/rfc/rfc9580.html#name-cleartext-signature-framewo
    pub fn clear(self) -> Builder<'sequoia, builder::CleartextSignature>
    {
        Builder {
            params: self.params,
            t: std::marker::PhantomData,
        }
    }

}

impl<'sequoia, T> Builder<'sequoia, T>
where
    T: builder::SignatureType
{
    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Signs the message with the specified certificate.
    ///
    /// This adds the certificate to the list of certificates that the
    /// message will be signed with.  It is possible to add multiple
    /// signatures to a message.
    ///
    /// The message will be signed with one valid (live, non-revoked)
    /// signing-capable key associated with the certificate for which
    /// the secret key material is available.  If the certificate has
    /// no valid signing-capable keys with secret key material, then
    /// the signing operation will return an error.
    pub fn add_signer(mut self, signer: Cert) -> Self {
        self.params.signers.push(signer);
        self
    }

    /// Signs the message with the specified certificates.
    ///
    /// See [`Builder::add_signer`] for details.
    pub fn add_signers(mut self, signers: impl Iterator<Item=Cert>)
                       -> Self
    {
        self.params.signers.extend(signers);
        self
    }

    /// Adds a notation to each of the new signatures.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notation(mut self, critical: bool, notation: NotationData)
                        -> Self
    {
        self.params.notations.push((critical, notation));
        self
    }

    /// Adds notations to each of the new signatures.
    ///
    /// The first value of the tuple is the notation's criticality.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notations(mut self,
                         notations: impl Iterator<Item=(bool, NotationData)>)
                         -> Self
    {
        self.params.notations.extend(notations);
        self
    }
}

impl<'sequoia, T> Builder<'sequoia, T>
where
    T: builder::RichSignature
{
    /// Sets the hashing mode.
    ///
    /// The hashing mode determines how the data is hash.  By default
    /// the signature is generated in binary mode.  In binary mode,
    /// the signed content is hashed as-is.  In [text mode], line
    /// endings are normalized to `\n\r`.  If in doubt, you probably
    /// want binary mode.
    ///
    ///   [text mode]: https://www.rfc-editor.org/rfc/rfc9580.html#sigtype-text
    pub fn hash_mode(mut self, hash_mode: HashMode) -> Self {
        self.params.hash_mode = hash_mode;
        self
    }

    /// Sets whether ASCII armor is used.
    ///
    /// If disabled, then the message is binary encoded.
    ///
    /// The default is to using ASCII armor and not add any headers.
    pub fn ascii_armor(mut self, use_ascii_armor: bool) -> Self
    {
        self.params.armor_headers = if use_ascii_armor {
            Some(Vec::new())
        } else {
            None
        };
        self
    }

    /// Enables ASCII armor and sets the ASCII-armor headers.
    ///
    /// This implicitly enables ASCII armor, and uses the specified
    /// headers.
    ///
    /// Note: the headers are informative and are neither encrypted
    /// nor protected by any signature.
    pub fn ascii_armor_headers<K, V>(mut self,
                                     headers: impl Iterator<Item=(K, V)>)
                                     -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.params.armor_headers = Some(
            headers
                .map(|(k, v)| {
                    (k.into(), v.into())
                })
                .collect());
        self
    }
}

impl<'sequoia, T> Builder<'sequoia, T>
where
    T: builder::SignatureType
{
    fn sign_<'a, I, O, S, P>(&self, mut input: I, output: O,
                             prompt: P, mut stream: S,
                             detached_signature: bool,
                             preexisting_signatures: Vec<Signature>)
                             -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream + 'a,
        P: prompt::Prompt,
    {
        let &Builder {
            params: Params {
                sequoia,
                ref signers,
                ref hash_mode,
                notarize: _,
                ref notations,

                ref armor_headers,
            },
            t: _,
        } = self;

        if signers.is_empty() {
            return Err(anyhow::anyhow!("No signing keys specified"));
        }

        let mut signers = match sequoia.get_signing_keys(
            &signers, None, &prompt)
        {
            Ok(signers) => {
                stream.output(
                    &self.params,
                    Output::Signing(output::Signing {
                        signers: signers.iter()
                            .map(|(cert, signer)| {
                                (cert.clone(), signer.public().fingerprint())
                            })
                            .collect(),
                    }))?;

                signers
            }
            Err(err) => {
                // XXX: We want to clone err, but it doesn't implement
                // clone so we do a shallow copy.
                let err2 = anyhow::anyhow!("{}", err);

                stream.output(
                    self.params(),
                    Output::SigningFailed(
                        output::SigningFailed {
                            unusable_certs: vec![ err ],
                        }))?;

                return Err(err2);
            }
        };

        let mut message = Message::new(output);
        if let Some(armor_headers) = armor_headers {
            let mut armorer = Armorer::new(message).kind(
                if detached_signature {
                    armor::Kind::Signature
                } else {
                    armor::Kind::Message
                });
            for (k, v) in armor_headers {
                armorer = armorer.add_header(k, v);
            }
            message = armorer.build()?;
        }

        // Prepend any existing signatures.
        if detached_signature {
            for sig in preexisting_signatures.into_iter() {
                Packet::Signature(sig).serialize(&mut message)?;
            }
        } else if ! preexisting_signatures.is_empty() {
            panic!(
                "Internal error: Appending signatures to an inline-signed \
                 message is not supported by this function");
        }

        let mut builder = SignatureBuilder::new(hash_mode.into());
        for (critical, n) in notations.iter() {
            builder = builder.add_notation(
                n.name(),
                n.value(),
                Some(n.flags().clone()),
                *critical)?;
        }

        let mut signer = Signer::with_template(
            message,
            signers.pop().unwrap().1,
            builder)?;
        signer = signer.creation_time(sequoia.time());
        for s in signers {
            signer = signer.add_signer(s.1)?;
        }
        if detached_signature {
            signer = signer.detached();
        }
        let signer = signer.build().context("Failed to create signer")?;

        let mut writer = if detached_signature {
            // Detached signatures do not need a literal data packet, just
            // hash the data as is.
            signer
        } else {
            // We want to wrap the data in a literal data packet.
            LiteralWriter::new(signer).build()
                .context("Failed to create literal writer")?
        };

        // Finally, copy stdin to our writer stack to sign the data.
        std::io::copy(&mut input, &mut writer)
            .context("Failed to sign")?;

        writer.finalize()
            .context("Failed to sign")?;

        stream.output(
            &self.params,
            Output::Signed(output::Signed {
            }))?;

        Ok(())
    }
}

impl<'sequoia> Builder<'sequoia, builder::DetachedSignature> {
    /// Signs a message and generates a detached signature.
    ///
    /// The detached signature is written to `output`.  By default,
    /// the message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    ///
    /// If you don't want to implement [`Stream`], you can pass `&mut
    /// Vec<Output>` to collect the status messages, or `()` to ignore
    /// them.
    pub fn sign<'a, I, O, S, P>(&self, input: I, output: O,
                                prompt: P, stream: S)
                                -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream + 'a,
        P: prompt::Prompt,
    {
        self.sign_(input, output, prompt, stream, true, Vec::new())
    }

    /// Adds signatures to a detached signature file.
    ///
    /// This function interprets `detached_signatures` as a detached
    /// signature file, and adds the new signatures to the existing
    /// signatures.  The pre-existing signatures are not checked for
    /// validity.
    ///
    /// The detached signatures are written to `output`.  By default,
    /// the message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    ///
    /// If you don't want to implement [`Stream`], you can pass `&mut
    /// Vec<Output>` to collect the status messages, or `()` to ignore
    /// them.
    pub fn append<'a, I, D, O, S, P>(
        &self, input: I,
        detached_signatures: D,
        output: O,
        prompt: P, stream: S)
        -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        D: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream + 'a,
        P: prompt::Prompt,
    {
        let &Builder {
            params: Params {
                sequoia: _,
                signers: _,
                hash_mode: _,
                notarize: _,
                notations: _,

                armor_headers: _,
            },
            t: _,
        } = self;

        // First, read the existing signatures.
        let mut sigs = Vec::new();
        let mut ppr =
            openpgp::parse::PacketParser::from_reader(detached_signatures)?;

        while let PacketParserResult::Some(pp) = ppr {
            let (packet, ppr_tmp) = pp.recurse()?;
            ppr = ppr_tmp;

            match packet {
                Packet::Signature(sig) => sigs.push(sig),
                p => return Err(
                    anyhow::anyhow!(
                        "{} in detached signature", p.tag())
                        .context("Invalid detached signature")),
            }
        }

        // Force detached_signatures to be dropped before output.
        // This way if output is a `PartFileWriter` referring to the
        // same file, the file will not exist when `PartFileWriter`
        // persists it.  This is only relevant on Windows where it is
        // not possible to replace a file that is open.
        drop(ppr);

        self.sign_(input, output, prompt, stream, true, sigs)
    }
}

impl<'sequoia> Builder<'sequoia, builder::InlineSignature> {
    /// Signs a message and generates an inline-signed message.
    ///
    /// The inlined-signed message is written to `output`.  By
    /// default, the message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    ///
    /// If you don't want to implement [`Stream`], you can pass `&mut
    /// Vec<Output>` to collect the status messages, or `()` to ignore
    /// them.
    pub fn sign<'a, I, O, S, P>(&self, input: I, output: O,
                                prompt: P, stream: S)
                                -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream + 'a,
        P: prompt::Prompt,
    {
        self.sign_(input, output, prompt, stream, false, Vec::new())
    }

    /// Adds signatures to an inline signed message.
    ///
    /// Unlike [`Builder::sign`], this function interprets `input` as
    /// an inline signed message, and adds the new signatures to the
    /// existing signatures.
    ///
    /// If there are multiple signature layers (see [Section 10.3 of
    /// RFC
    /// 9580](https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3)
    /// or multiple groups (see [Section 5.4 of RFC
    /// 9580](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.4)),
    /// then this function adds the signatures to the outer-most layer
    /// and group.  (Adding it to an inner group or layer would break
    /// the signatures in outer groups, since they are over the data
    /// and the inner signature groups.)  Note: almost all signed
    /// messages only consist of a single signature layer and group.
    ///
    /// The signed data is written to `output`.  By default, the
    /// message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    ///
    /// If you don't want to implement [`Stream`], you can pass `&mut
    /// Vec<Output>` to collect the status messages, or `()` to ignore
    /// them.
    pub fn append<'a, I, O, S, P>(&self, input: I, output: O,
                                  prompt: P, mut stream: S)
                                  -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream + 'a,
        P: prompt::Prompt,
    {
        let &Builder {
            params: Params {
                sequoia,
                ref signers,
                ref hash_mode,
                notarize,
                ref notations,

                ref armor_headers,
            },
            t: _,
        } = self;

        if signers.is_empty() {
            return Err(anyhow::anyhow!("No signing keys specified"));
        }

        let mut signers = match sequoia.get_signing_keys(
            &signers, None, &prompt)
        {
            Ok(signers) => {
                let (output, signers) = signers.into_iter()
                    .fold((Vec::new(), Vec::new()),
                          |(mut output, mut signers), (cert, signer)| {
                              output.push((cert, signer.public().fingerprint()));
                              signers.push(signer);

                              (output, signers)
                          });

                stream.output(
                    &self.params,
                    Output::Signing(output::Signing {
                        signers: output,
                    }))?;

                signers
            }
            Err(err) => {
                // XXX: We want to clone err, but it doesn't implement
                // clone so we do a shallow copy.
                let err2 = anyhow::anyhow!("{}", err);

                stream.output(
                    self.params(),
                    Output::SigningFailed(
                        output::SigningFailed {
                            unusable_certs: vec![ err ],
                        }))?;

                return Err(err2);
            }
        };

        let mut message = Message::new(output);
        if let Some(armor_headers) = armor_headers {
            let mut armorer = Armorer::new(message)
                .kind(armor::Kind::Message);
            for (k, v) in armor_headers {
                armorer = armorer.add_header(k, v);
            }
            message = armorer.build()?;
        }

        // Create a parser for the message to be notarized.
        let mut ppr
            = openpgp::parse::PacketParser::from_reader(input)
            .context("Failed to build parser")?;

        // Once we see a signature, we can no longer strip compression.
        let mut seen_signature = false;
        #[derive(PartialEq, Eq, Debug)]
        enum State {
            InFirstSigGroup,
            AfterFirstSigGroup,
            Signing {
                // Counts how many signatures are being notarized.  If
                // this drops to zero, we pop the signer from the stack.
                signature_count: isize,
            },
            Done,
        }
        let mut state =
            if ! notarize {
                State::InFirstSigGroup
            } else {
                // Pretend we have passed the first signature group so
                // that we put our signature first.
                State::AfterFirstSigGroup
            };

        while let PacketParserResult::Some(mut pp) = ppr {
            if let Err(err) = pp.possible_message() {
                return Err(err.context("Malformed OpenPGP message"));
            }

            match pp.packet {
                Packet::PKESK(_) | Packet::SKESK(_) =>
                    return Err(anyhow::anyhow!(
                        "Signing encrypted data is not implemented")),

                Packet::Literal(_) =>
                    if let State::InFirstSigGroup = state {
                        // Cope with messages that have no signatures, or
                        // with a ops packet without the last flag.
                        state = State::AfterFirstSigGroup;
                    },

                // To implement this, we'd need to stream the
                // compressed data packet inclusive framing, but
                // currently the partial body filter transparently
                // removes the framing.
                //
                // If you do implement this, there is a half-disabled test
                // in tests/sq-sign.rs.
                Packet::CompressedData(_) if seen_signature =>
                    return Err(anyhow::anyhow!(
                        "Signing a compress-then-sign message is not implemented")),

                _ => (),
            }

            match state {
                State::AfterFirstSigGroup => {
                    // After the first signature group, we push the signer
                    // onto the writer stack.
                    let mut builder = SignatureBuilder::new(hash_mode.into());
                    for (critical, n) in notations.iter() {
                        builder = builder.add_notation(
                            n.name(),
                            n.value(),
                            Some(n.flags().clone()),
                            *critical)?;
                    }

                    let mut signer = Signer::with_template(
                        message, signers.pop().unwrap(), builder)?;
                    signer = signer.creation_time(sequoia.time());
                    for s in signers.drain(..) {
                        signer = signer.add_signer(s)?;
                    }
                    message = signer.build().context("Failed to create signer")?;
                    state = State::Signing { signature_count: 0, };
                },

                State::Signing { signature_count } if signature_count == 0 => {
                    // All signatures that are being notarized are
                    // written, pop the signer from the writer stack.
                    message = message.finalize_one()
                        .context("Failed to sign data")?
                        .unwrap();
                    state = State::Done;
                },

                _ => (),
            }

            if let Packet::Literal(_) = pp.packet {
                let l = if let Packet::Literal(l) = pp.packet.clone() {
                    l
                } else {
                    unreachable!()
                };
                // Create a literal writer to wrap the data in a literal
                // message packet.
                let mut literal = LiteralWriter::new(message).format(l.format());
                if let Some(f) = l.filename() {
                    literal = literal.filename(f)?;
                }
                if let Some(d) = l.date() {
                    literal = literal.date(d)?;
                }

                let mut literal = literal.build()
                    .context("Failed to create literal writer")?;

                // Finally, just copy all the data.
                pp.copy(&mut literal)
                    .context("Failed to sign data")?;

                // Pop the literal writer.
                message = literal.finalize_one()
                    .context("Failed to sign data")?
                    .unwrap();
            }

            let (packet, ppr_tmp) = if seen_signature {
                // Once we see a signature, we can no longer strip
                // compression.
                pp.next()
            } else {
                pp.recurse()
            }.context("Parsing failed")?;
            ppr = ppr_tmp;

            match packet {
                Packet::OnePassSig(mut ops) => {
                    let was_last = ops.last();
                    match state {
                        State::InFirstSigGroup => {
                            // We want to append our signature here, hence
                            // we set last to false.
                            ops.set_last(false);

                            if was_last {
                                // The signature group ends here.
                                state = State::AfterFirstSigGroup;
                            }
                        },

                        State::Signing { ref mut signature_count } =>
                            *signature_count += 1,

                        _ => (),
                    }

                    Packet::OnePassSig(ops).serialize(&mut message)?;
                    seen_signature = true;
                },

                Packet::Signature(sig) => {
                    Packet::Signature(sig).serialize(&mut message)
                        .context("Failed to serialize")?;
                    if let State::Signing { ref mut signature_count } = state {
                        *signature_count -= 1;
                    }
                },
                _ => (),
            }
        }

        if let PacketParserResult::EOF(ref eof) = ppr {
            if let Err(err) = eof.is_message() {
                return Err(err.context("Malformed OpenPGP message"));
            }
        } else {
            unreachable!()
        }

        // Force input to be dropped before output.  This way if
        // output is a `PartFileWriter` referring to the same file,
        // the file will not exist when `PartFileWriter` persists it.
        // This is only relevant on Windows where it is not possible
        // to replace a file that is open.
        drop(ppr);

        match state {
            State::Signing { signature_count } => {
                assert_eq!(signature_count, 0);
                message.finalize()
                    .context("Failed to sign data")?;
            },
            State::Done => {
                message.finalize()
                    .context("Failed to sign data")?;
            },
            _ => panic!("Unexpected state: {:?}", state),
        }

        stream.output(
            &self.params,
            Output::Signed(output::Signed {
            }))?;

        Ok(())
    }
}

impl<'sequoia> Builder<'sequoia, builder::CleartextSignature> {
    /// Clear signs a message.
    ///
    /// A clear-signed message is an inline signed text message that
    /// has not been ASCII-armored.  The result is that the message
    /// remains readable.
    ///
    /// The cleartext signature framework normalizes line endings,
    /// trims trailing whitespace, and dash escapes lines starting
    /// with a dash.
    ///
    /// The signed data is written to `output`.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    ///
    /// If you don't want to implement [`Stream`], you can pass `&mut
    /// Vec<Output>` to collect the status messages, or `()` to ignore
    /// them.
    pub fn sign<'a, I, O, S, P>(&self, mut input: I, mut output: O,
                                prompt: P, mut stream: S)
                                -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream + 'a,
        P: prompt::Prompt,
    {
        let &Builder {
            params: Params {
                sequoia,
                ref signers,
                hash_mode: _,
                notarize: _,
                ref notations,

                armor_headers: _,
            },
            t: _,
        } = self;

        if signers.is_empty() {
            return Err(anyhow::anyhow!("No signing keys specified"));
        }

        let mut signers = match sequoia.get_signing_keys(
            &signers, None, &prompt)
        {
            Ok(signers) => {
                let (output, signers) = signers
                    .into_iter()
                    .fold((Vec::new(), Vec::new()),
                          |(mut output, mut signers), (cert, signer)| {
                              output.push((cert.clone(),
                                           signer.public().fingerprint()));
                              signers.push(signer);

                              (output, signers)
                          });

                stream.output(
                    &self.params,
                    Output::Signing(output::Signing {
                        signers: output,
                    }))?;

                signers
            }
            Err(err) => {
                // XXX: We want to clone err, but it doesn't implement
                // clone so we do a shallow copy.
                let err2 = anyhow::anyhow!("{}", err);

                stream.output(
                    self.params(),
                    Output::SigningFailed(
                        output::SigningFailed {
                            unusable_certs: vec![ err ],
                        }))?;

                return Err(err2);
            }
        };

        // Prepare a signature template.
        let mut builder = SignatureBuilder::new(SignatureType::Text);
        for (critical, n) in notations.iter() {
            builder = builder.add_notation(
                n.name(),
                n.value(),
                Some(n.flags().clone()),
                *critical)?;
        }

        let message = Message::new(&mut output);
        let mut signer = Signer::with_template(
            message, signers.pop().unwrap(), builder)?
            .cleartext();
        signer = signer.creation_time(sequoia.time());
        for s in signers {
            signer = signer.add_signer(s)?;
        }
        let mut message = signer.build().context("Failed to create signer")?;

        // Finally, copy stdin to our writer stack to sign the data.
        std::io::copy(&mut input, &mut message)
            .context("Failed to sign")?;

        message.finalize()
            .context("Failed to sign")?;

        stream.output(
            &self.params,
            Output::Signed(output::Signed {
            }))?;

        Ok(())
    }
}
