//! Functionality for importing certificates.
//!
//! # Examples
//!
//! Import some certificates, a revocation certificate, or
//! certificates from an email with autocrypt headers:
//!
//! ```
//! # use sequoia::openpgp;
//! # use openpgp::cert::CertBuilder;
//! # use openpgp::serialize::Serialize;
//! #
//! # use sequoia::Sequoia;
//! use sequoia::prompt::Cancel;
//!
//! # fn main() -> sequoia::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! # let (alice, _alice_rev) = CertBuilder::new()
//! #     .add_userid("<alice@example.org>")
//! #     .generate()
//! #     .unwrap();
//! #
//! # let mut input = Vec::new();
//! # alice.serialize(&mut input).unwrap();
//! #
//! # let mut input = std::io::Cursor::new(&input[..]);
//! #
//! // The prompt is used to ask for a password when decrypting an
//! // Autocrypt message.  Here we suppress the prompt.
//! let prompt = Cancel::new();
//!
//! if let Err(err) = sq.cert_import().import(input, prompt, &mut ()) {
//!     eprintln!("Failed to import at least one certificate: {}", err);
//! }
//! # Ok(()) }
//! ```
//!
//! To get more information about what happened, we can implement
//! [`Stream`].  Note: if you don't require the information
//! asynchronously, you can also pass a [`&mut Vec<Output>`](Output)
//! to collect the output and examine it after the call returns.
//!
//! ```
//! # use sequoia::openpgp;
//! # use openpgp::cert::CertBuilder;
//! # use openpgp::serialize::Serialize;
//! #
//! # use sequoia::Sequoia;
//! use sequoia::cert::import::Output;
//! use sequoia::cert::import::output::*;
//! use sequoia::cert::import;
//! use sequoia::prompt::Cancel;
//!
//! # fn main() -> sequoia::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! # let (alice, _alice_rev) = CertBuilder::new()
//! #     .add_userid("<alice@example.org>")
//! #     .generate()
//! #     .unwrap();
//! #
//! # let mut input = Vec::new();
//! # alice.serialize(&mut input).unwrap();
//! #
//! # let mut input = std::io::Cursor::new(&input[..]);
//! #
//! pub struct Stream {
//!     // Local state.
//! }
//!
//! impl import::Stream for Stream {
//!     fn output(&mut self,
//!               _params: &import::Params,
//!               output: import::Output)
//!         -> sequoia::Result<()>
//!     {
//!         match output {
//!             Output::Imported(Imported { merged, .. }) => {
//!                 eprintln!("Imported {}", merged.fingerprint());
//!             }
//!             Output::Report(Report { stats, ..}) => {
//!                 eprintln!("New {}, updated: {}, unchanged: {}, errors: {}",
//!                           stats.certs.new_certs(),
//!                           stats.certs.updated_certs(),
//!                           stats.certs.unchanged_certs(),
//!                           stats.certs.errors());
//!                 # assert_eq!(stats.certs.new_certs(), 1);
//!                 # assert_eq!(stats.certs.errors(), 0);
//!             }
//!             _ => (),
//!         }
//!
//!         // Return an error to abort processing.
//!         Ok(())
//!     }
//! }
//!
//! // The prompt is used to ask for a password when decrypting an
//! // Autocrypt message.  Here we suppress the prompt.
//! let prompt = Cancel::new();
//!
//! let mut stream = Stream { };
//! if let Err(err) = sq.cert_import().import(input, prompt, &mut stream) {
//!     eprintln!("Failed to import at least one certificate: {}", err);
//! }
//! # Ok(()) }
//! ```

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::Arc;

use sequoia_openpgp::parse::buffered_reader;
use buffered_reader::BufferedReader;
use buffered_reader::Dup;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::raw::RawCert;
use openpgp::cert::raw::RawCertParser;
use openpgp::packet::Signature;
use openpgp::packet::UserID;
use openpgp::parse::Cookie;
use openpgp::parse::PacketParser;
use openpgp::parse::PacketParserResult;
use openpgp::parse::Parse;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use sequoia_autocrypt as autocrypt;

use crate::Sequoia;
use crate::decrypt;
use crate::prompt;
use crate::provenance::certify_downloads;
use crate::types::SessionKey;
use crate::types::import_stats::ImportStats;

/// The trait for collecting output.
pub trait Stream {
    /// Output from [`import`](Builder::import).
    fn output(&mut self, params: &Params, output: Output) -> Result<()>;
}

impl<T> Stream for Box<T>
where
    T: Stream + ?Sized
{
    fn output(&mut self, params: &Params, output: Output) -> Result<()> {
        AsMut::as_mut(self).output(params, output)
    }
}

impl<T> Stream for &mut T
where
    T: Stream + ?Sized
{
    fn output(&mut self, params: &Params, output: Output) -> Result<()> {
        (*self).output(params, output)
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

    /// Information about a certificate.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Cert {
        pub cert: openpgp::Cert,
    }

    /// Information about an imported revocation certificate.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Revocation {
        pub rev: Signature,
    }

    /// Information about a certificate imported from an autocrypt
    /// message.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Autocrypt {
        /// The sender.
        pub sender: Arc<openpgp::Cert>,
        /// The autocrypt header's attributes.
        pub sender_attributes: Arc<Vec<autocrypt::Attribute>>,
    }

    /// Information about a certificate imported from an autocrypt
    /// message.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct AutocryptGossip {
        /// The sender.
        pub sender: Arc<openpgp::Cert>,
        /// The sender header's attributes.
        pub sender_attributes: Arc<Vec<autocrypt::Attribute>>,
        /// The certificate transported in the gossip header.
        pub gossip: Arc<openpgp::Cert>,
        /// The gossip header's attributes.
        pub gossip_attributes: Arc<Vec<autocrypt::Attribute>>,
    }

    /// A certificate, revocation, autocrypt, or an error.
    ///
    /// Used by [`Imported`] and [`ImportingFailed`].
    #[non_exhaustive]
    #[derive(Debug)]
    pub enum Artifact {
        /// Information about a certificate.
        Cert(openpgp::Cert),

        /// Information about a revocation certificate.
        Revocation(Revocation),

        /// Information about a certificate from an autocrypt header.
        Autocrypt(Autocrypt),

        /// Information about a certificate from autocrypt gossip.
        AutocryptGossip(AutocryptGossip),
    }

    impl Artifact {
        /// If the artifact contains a `Cert`, returns it.
        ///
        /// This returns the certificate that is being merged into the
        /// certificate store.
        pub fn cert(&self) -> Option<&openpgp::Cert> {
            match self {
                Artifact::Cert(cert) => Some(cert),
                Artifact::Revocation(_rev) => None,
                Artifact::Autocrypt(ac) => Some(&ac.sender),
                Artifact::AutocryptGossip(ac) => Some(&ac.gossip),
            }
        }

        /// If this artifact is a revocation certificate, returns it.
        pub fn revocation(&self) -> Option<&Signature> {
            if let Artifact::Revocation(rev) = self {
                Some(&rev.rev)
            } else {
                None
            }
        }
    }

    /// We imported a certificate.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Imported {
        /// We imported the artifact.
        pub artifact: Artifact,

        /// The resulting certificate.
        ///
        /// The result after merging the artifact with any existing
        /// certificate in the certificate store.
        pub merged: openpgp::Cert,

        /// The certificate's provenance was recorded using the
        /// following intermediate CAs.
        pub recorded_provenance: Vec<Arc<openpgp::Cert>>,
    }

    /// We can't import anything, because we don't have a
    /// certificate store.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct NoCertStore {
    }

    /// We didn't find any artifacts.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct NoData {
    }

    /// An error occurred parsing the low-level repsentation of the
    /// artifact.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct ParseError {
    }

    /// Information about a broken certificate.
    ///
    /// We were able to parse some bytes into something that resembles
    /// a certificate, but upon closer inspection, the certificate is
    /// broken.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct BrokenCert {
        pub cert: RawCert<'static>,
    }

    /// Information about a broken revocation certificate.
    ///
    /// We were able to parse some bytes into an OpenPGP packet, but
    /// upon closer inspection, the certificate is broken.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct BrokenRevocation {
        pub packet: Packet,
    }

    /// Information about an email that does not contain an autocrypt
    /// header.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct BrokenAutocrypt {
    }

    #[non_exhaustive]
    #[derive(Debug)]
    pub enum BrokenArtifact {
        /// The certificate is broken.
        BrokenCert(BrokenCert),

        /// The packet is not a revocation certificate.
        BrokenRevocation(BrokenRevocation),

        /// The email does not contain autocrypt headers.
        BrokenAutocrypt(BrokenAutocrypt),
    }

    /// Information about the breakage.
    #[non_exhaustive]
    #[derive(Debug)]
    pub enum Breakage {
        /// We can't import anything, because we don't have a
        /// certificate store.
        NoCertStore(NoCertStore),

        /// We didn't find any artifacts, or we failed to parse the
        /// file.
        NoData(NoData),

        /// We failed to parse an artifact.
        ///
        /// Note: if we completely failed to parse the file, we emit
        /// [`Breakage::NoData`].
        ParseError(ParseError),

        /// An artifact is broken.
        BrokenArtifact(BrokenArtifact),

        /// We tried to import an otherwise valid artifact into the
        /// certificate store, but failed.
        ImportError(Artifact),
    }

    /// We failed to import something.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("{}: {}",
            match .breakage {
                Breakage::NoCertStore(_) =>
                    Cow::Borrowed("Certificate store not available"),
                Breakage::NoData(_) =>
                    Cow::Borrowed("Input is empty"),
                Breakage::ParseError(_) =>
                    Cow::Borrowed("Parse error"),
                Breakage::BrokenArtifact(artifact) => {
                    match artifact {
                        BrokenArtifact::BrokenCert(cert) => {
                            Cow::Owned(format!(
                                "Parsing certificate {}",
                                cert.cert.fingerprint()))
                        }
                        BrokenArtifact::BrokenRevocation(_) => {
                            Cow::Borrowed("Parsing revocation certificate")
                        }
                        BrokenArtifact::BrokenAutocrypt(_) => {
                            Cow::Borrowed("Parsing autocrypt message")
                        }
                    }
                }
                Breakage::ImportError(artifact) => {
                    match artifact {
                        Artifact::Cert(cert) => {
                            Cow::Owned(format!(
                                "Importing {}", cert.fingerprint()))
                        }
                        Artifact::Revocation(rev) => {
                            if let Some(issuer) = rev.rev.get_issuers().into_iter().next() {
                                Cow::Owned(format!(
                                    "Importing revocation certificate for {}",
                                    issuer))
                            } else {
                                Cow::Borrowed(
                                    "Importing revocation certificate")
                            }
                        }
                        Artifact::Autocrypt(_) => {
                            Cow::Borrowed("Importing autocrypt message")
                        }
                        Artifact::AutocryptGossip(_) => {
                            Cow::Borrowed("Importing autocrypt gossip")
                        }
                    }
                }
            },
            .error)]
    pub struct ImportingFailed {
        /// The thing that we tried to import.
        pub breakage: Breakage,

        /// The related error.
        pub error: anyhow::Error,
    }

    /// Decryption status.
    ///
    /// This is only emitted when processing an autocrypt message.
    /// Autocrypt messages are encrypted.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct DecryptedAutocrypt {
        /// The sender.
        pub sender: Arc<openpgp::Cert>,
        /// The sender's attributes.
        pub sender_attributes: Arc<Vec<autocrypt::Attribute>>,
        /// The output of the decryption operation.
        pub decryption_output: Vec<decrypt::Output>,
        /// Whether the decryption was successful.
        pub decrypted: bool,
    }

    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Report {
        /// Statistics.
        pub stats: ImportStats,
    }
}

/// The variants of this enum are the different types of output that
/// [`import`](Builder::import) emits.
#[non_exhaustive]
#[derive(Debug)]
pub enum Output {
    /// Emitted after the artifact being imported was successfully
    /// imported to the store.
    Imported(output::Imported),

    /// Emitted when something can't be imported to the store.
    ImportingFailed(output::ImportingFailed),

    /// Emitted after attempting to decrypt an autocrypt message.
    ///
    /// Autocrypt messages are encrypted.  To get at the autocrypt
    /// gossip, they need to be decrypted.
    ///
    /// This is emitted if decryption is successful or not.
    ///
    /// Any certifictes imported from the autocrypt message will also
    /// be reported via [`output::Imported`].  As such, you can
    /// usually ignore this.
    DecryptedAutocrypt(output::DecryptedAutocrypt),

    Report(output::Report),
}

impl Sequoia {
    /// Returns a builder providing control over how to import
    /// certificates.
    ///
    /// See [`Builder`] for details.
    pub fn cert_import(&self) -> Builder<'_>
    {
        Builder {
            params: Params {
                sequoia: self,
                secret_keys: Vec::new(),
                session_keys: Vec::new(),
            },
        }
    }
}

/// The certificate import parameters.
///
/// These parameters are used by [`import`](Builder::import).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
    secret_keys: Vec<Cert>,
    session_keys: Vec<SessionKey>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns the pre-loaded secret keys.
    ///
    /// See [`Builder::secret_keys`].
    pub fn secret_keys(&self) -> &[Cert] {
        &self.secret_keys[..]
    }

    /// Returns the pre-loaded session keys.
    pub fn session_keys(&self) -> &[SessionKey] {
        &self.session_keys[..]
    }
}

/// Imports certificates.
///
/// A builder providing control over how to import certificates.
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia>
{
    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Sets the secret keys to try when decrypting an autocrypt
    /// message.
    ///
    /// The secret keys are tried in addition to the key store, if it
    /// hasn't been disabled.
    ///
    /// Standards conformant autocrypt messages are always encrypted.
    /// To import certificates transported using [Autocrypt's gossip
    /// mechanism], it is necessary to decrypt the message.
    ///
    ///   [Autocrypt's gossip mechanism]: https://docs.autocrypt.org/level1.html#key-gossip
    ///
    /// Note: even if the autocrypt message can't be decrypted, any
    /// certificate found in the Autocrypt header is still imported.
    pub fn secret_keys(&mut self, secret_keys: Vec<Cert>) -> &mut Self {
        self.params.secret_keys = secret_keys;

        self
    }

    /// Sets session keys to try when decrypting an autocrypt message.
    ///
    /// The session keys are tried in addition to the key store, if
    /// it hasn't been disabled.
    ///
    /// Standards conformant autocrypt messages are always encrypted.
    /// To import certificates transported using [Autocrypt's gossip
    /// mechanism], it is necessary to decrypt the message.
    ///
    ///   [Autocrypt's gossip mechanism]: https://docs.autocrypt.org/level1.html#key-gossip
    ///
    /// Note: even if the autocrypt message can't be decrypted, any
    /// certificate found in the Autocrypt header is still imported.
    pub fn session_keys(&mut self, session_keys: Vec<SessionKey>) -> &mut Self {
        self.params.session_keys = session_keys;

        self
    }

    /// Import certificates or revocation certificates.
    ///
    /// This auto-detects if `input` contains an OpenPGP keyring, a
    /// bare revocation certificate, or an email, and calls
    /// [`Builder::import_certs`], [`Builder::import_revocation`], or
    /// [`Builder::import_autocrypt`], as appropriate.
    pub fn import<'a, P, S>(&self,
                            input: impl std::io::Read + Send + Sync + 'a,
                            prompt: P,
                            stream: S)
                            -> Result<()>
    where
        P: prompt::Prompt + 'a,
        S: Stream + 'a,
    {
        let &Builder {
            params: Params {
                sequoia: _,
                secret_keys: _,
                session_keys: _,
            },
        } = self;

        // XXX: There's a chance that input is already some
        // kind of BufferedReader.  We could try downcasting
        // to see if we could recover it.
        let mut input = buffered_reader::Generic::with_cookie(
            input, None, Cookie::default());

        if input.eof() {
            // Empty file.  Silently skip it.
            return Ok(());
        }

        enum Type {
            Signature,
            Keyring,
            Other,
        }

        // See if it is OpenPGP data.
        let dup = Dup::with_cookie(&mut input, Cookie::default());
        let mut typ = Type::Other;
        if let Ok(ppr) = PacketParser::from_buffered_reader(dup) {
            // See if it is a keyring, or a bare revocation
            // certificate.
            if let PacketParserResult::Some(ref pp) = ppr {
                if let Packet::Signature(sig) = &pp.packet {
                    typ = match sig.typ() {
                        SignatureType::KeyRevocation |
                        SignatureType::SubkeyRevocation |
                        SignatureType::CertificationRevocation =>
                        // Looks like a bare revocation.
                        Type::Signature,
                        _ => Type::Other,
                    };
                } else if pp.possible_keyring().is_ok() {
                    typ = Type::Keyring;
                } else {
                    // If we have a message, then it might
                    // actually be an email with autocrypt data.
                }
            }
        }

        let mut stats = ImportStats::default();

        let input = Box::new(input) as Box<dyn BufferedReader<Cookie> + 'a>;
        let prompt = Box::new(prompt) as Box<dyn prompt::Prompt + 'a>;
        let mut stream = Box::new(stream) as Box<dyn Stream + 'a>;
        let result = match typ {
            Type::Keyring => {
                self.import_certs_(input, &mut stats, &mut stream)
            }
            Type::Signature => {
                self.import_revocation_(input, &mut stats, &mut stream)
            }
            Type::Other => {
                self.import_autocrypt_(input, &mut stats, prompt, &mut stream)
            }
        };

        stream.output(
            self.params(),
            Output::Report(output::Report {
                stats,
            }))?;

        result
    }

    /// Report that importing something failed.
    fn report_failure<'a>(&self,
                          breakage: output::Breakage,
                          error: anyhow::Error,
                          stats: &mut ImportStats,
                          stream: &mut Box<dyn Stream + 'a>)
                          -> Result<()>
    {
        match breakage {
            output::Breakage::NoCertStore(_) => (),
            output::Breakage::NoData(_) => (),
            output::Breakage::ParseError(_)
                | output::Breakage::BrokenArtifact(_)
                | output::Breakage::ImportError(_) =>
            {
                stats.certs.inc_errors();
            }
        }
        stream.output(
            self.params(),
            Output::ImportingFailed(output::ImportingFailed {
                breakage,
                error,
            }))
    }

    /// Imports the certs and reports on the individual certs.
    fn import_and_report<'a>(&self,
                             cert: openpgp::Cert,
                             artifact: output::Artifact,
                             provenance: Vec<Arc<Cert>>,
                             stats: &mut ImportStats,
                             stream: &mut Box<dyn Stream + 'a>)
                             -> Result<bool>
    {
        let &Builder {
            params: Params {
                sequoia,
                secret_keys: _,
                session_keys: _,
            },
        } = self;

        let cert_store = match sequoia.cert_store_or_else() {
            Ok(cert_store) => cert_store,
            Err(err) => {
                // XXX: Make a shallow copy, because anyhow::Error
                // doesn't implement clone.
                let err_ = anyhow::anyhow!(err.to_string());
                self.report_failure(
                    output::Breakage::NoCertStore(
                        output::NoCertStore {
                        }),
                    err,
                    &mut *stats,
                    &mut *stream)?;
                return Err(err_);
            }
        };

        let cert = Arc::new(LazyCert::from(cert));
        match cert_store.update_by(cert.clone(), stats) {
            Err(err) => {
                self.report_failure(
                    output::Breakage::ImportError(artifact),
                    err,
                    &mut *stats,
                    &mut *stream)?;

                Ok(false)
            }
            Ok(merged) => {
                let merged = Arc::unwrap_or_clone(merged)
                    .into_cert().expect("is a cert");

                stream.output(
                    self.params(),
                    Output::Imported(output::Imported {
                        artifact,
                        merged,
                        recorded_provenance: provenance
                            .iter()
                            .map(|ca| Arc::clone(&ca))
                            .collect(),
                    }))?;

                Ok(true)
            }
        }
    }

    /// Imports certificates encoded as OpenPGP keyring.
    ///
    /// This function returns an error if the input is not an OpenPGP
    /// keyring.  If the OpenPGP keyring contains recoverable errors,
    /// these are reported using [`Output::ImportingFailed`], but
    /// parsing is not aborted.
    ///
    /// This function returns an error if the input is not an OpenPGP
    /// keyring, if there was an issue importing one or more
    /// certificates, or if the input contains no certificates.  In
    /// other words, if five certificates are imported and there is a
    /// problem with one certificate, this function conservatively
    /// returns an error.  Depending on the context, the error may not
    /// be fatal, and showing a warning may be sufficient.
    pub fn import_certs<'a, S>(&self,
                               source: impl std::io::Read + Send + Sync + 'a,
                               stream: S)
                               -> Result<()>
    where
        S: Stream + 'a,
    {
        // XXX: There's a chance that input is already some
        // kind of BufferedReader.  We could try downcasting
        // to see if we could recover it.
        let source = buffered_reader::Generic::with_cookie(
            source, None, Cookie::default());
        let source = Box::new(source) as Box<dyn BufferedReader<Cookie>>;

        let mut stream = Box::new(stream) as Box<dyn Stream>;

        let mut stats = ImportStats::default();

        let result = self.import_certs_(source, &mut stats, &mut stream);

        stream.output(
            self.params(),
            Output::Report(output::Report {
                stats,
            }))?;

        result
    }

    /// Imports certs encoded as OpenPGP keyring.
    fn import_certs_<'a>(&self,
                         source: Box<dyn BufferedReader<Cookie> + 'a>,
                         stats: &mut ImportStats,
                         stream: &mut Box<dyn Stream + 'a>)
                         -> Result<()>
    {
        let raw_certs = RawCertParser::from_buffered_reader(source)?;

        let mut ok = 0;
        let mut errors = 0;
        for raw_cert in raw_certs {
            let cert = match raw_cert {
                Err(err) => {
                    errors += 1;
                    self.report_failure(
                        output::Breakage::ParseError(
                            output::ParseError {
                            }),
                        err,
                        stats,
                        &mut *stream)?;
                    continue;
                }
                Ok(rawcert) => {
                    let lc = LazyCert::from(rawcert);
                    match lc.to_cert().cloned() {
                        Ok(cert) => cert,
                        Err(err) => {
                            errors += 1;
                            self.report_failure(
                                output::Breakage::BrokenArtifact(
                                    output::BrokenArtifact::BrokenCert(
                                        output::BrokenCert {
                                            cert: lc.into_raw_cert()
                                                .expect("have a rawcert")
                                                .into_owned(),
                                        })),
                                err,
                                &mut *stats,
                                &mut *stream)?;
                            continue;
                        }
                    }
                }
            };

            let imported = self.import_and_report(
                cert.clone(),
                output::Artifact::Cert(cert),
                Vec::new(), // No provenance.
                &mut *stats,
                &mut *stream)?;

            if imported {
                ok += 1;
            } else {
                errors += 1;
            }
        }

        match errors {
            0 => {
                if ok > 0 {
                    Ok(())
                } else {
                    // This likely wasn't a keyring.
                    Err(anyhow::anyhow!("No certificates found"))
                }
            }
            1 => Err(anyhow::anyhow!("Error importing a certificate")),
            _ => Err(anyhow::anyhow!("Error importing {} certificates",
                                     errors)),
        }
    }

    /// Imports a bare revocation certificate.
    ///
    /// A bare revocation certificate is a certificate revocation that
    /// is not bundled with the certificate.  A bare revocation
    /// certificate can only be imported if the certificate is already
    /// present in the certificate store (or specified using
    /// [`SequoiaBuilder::add_keyring`](crate::SequoiaBuilder::add_keyring)
    /// in which case the certificate is also imported into the
    /// certificate store).
    ///
    /// This function returns an error if the input does not contain
    /// exactly one revocation certificate.  Note: if the input
    /// contains multiple ASCII-armored blocks, only the first one is
    /// considered.
    pub fn import_revocation<'a, S>(
        &self,
        source: impl std::io::Read + Send + Sync,
        stream: S)
        -> Result<()>
    where
        S: Stream + 'a,
    {
        // XXX: There's a chance that input is already some
        // kind of BufferedReader.  We could try downcasting
        // to see if we could recover it.
        let source = buffered_reader::Generic::with_cookie(
            source, None, Cookie::default());
        let source = Box::new(source) as Box<dyn BufferedReader<Cookie>>;

        let mut stream = Box::new(stream) as Box<dyn Stream>;

        let mut stats = ImportStats::default();

        let result = self.import_revocation_(
            source, &mut stats, &mut stream);

        stream.output(
            self.params(),
            Output::Report(output::Report {
                stats,
            }))?;

        result
    }

    /// Import a bare revocation certificate.
    fn import_revocation_<'a>(
        &self,
        source: Box<dyn BufferedReader<Cookie> + 'a>,
        stats: &mut ImportStats,
        stream: &mut Box<dyn Stream + 'a>)
        -> Result<()>
    {
        let &Builder {
            params: Params {
                sequoia,
                secret_keys: _,
                session_keys: _,
            },
        } = self;

        let ppr = match PacketParser::from_buffered_reader(source) {
            Err(err) => {
                // anyhow doesn't implement clone; make a shallow
                // copy.
                let err_ = anyhow::anyhow!(err.to_string());
                self.report_failure(
                    output::Breakage::NoData(
                        output::NoData {
                        }),
                    err,
                    &mut *stats,
                    &mut *stream)?;
                return Err(err_);
            }
            Ok(ppr) => ppr,
        };
        let sig = if let PacketParserResult::Some(pp) = ppr {
            let (packet, next_ppr) = match pp.next() {
                Err(err) => {
                    // anyhow doesn't implement clone; make a shallow
                    // copy.
                    let err_ = anyhow::anyhow!(err.to_string());
                    self.report_failure(
                        output::Breakage::NoData(
                            output::NoData {
                            }),
                        err,
                        &mut *stats,
                        &mut *stream)?;
                    return Err(err_);
                }
                Ok(ppr) => ppr,
            };

            let sig = if let Packet::Signature(sig) = packet {
                sig
            } else {
                let tag = packet.tag();
                self.report_failure(
                    output::Breakage::BrokenArtifact(
                        output::BrokenArtifact::BrokenRevocation(
                            output::BrokenRevocation {
                                packet: packet.clone(),
                            })),
                    anyhow::anyhow!(
                        "Not a revocation certificate: got a {}",
                        tag),
                    &mut *stats,
                    &mut *stream)?;
                return Err(anyhow::anyhow!(
                    "Not a revocation certificate: got a {}",
                    tag));
            };

            if let PacketParserResult::Some(_) = next_ppr {
                self.report_failure(
                    output::Breakage::BrokenArtifact(
                        output::BrokenArtifact::BrokenRevocation(
                            output::BrokenRevocation {
                                packet: sig.clone().into(),
                            })),
                    anyhow::anyhow!(
                        "Not a revocation certificate: \
                         got more than one packet"),
                    &mut *stats,
                    &mut *stream)?;
                return Err(anyhow::anyhow!(
                    "Not a revocation certificate: \
                     got more than one packet"));
            }

            sig
        } else {
            self.report_failure(
                output::Breakage::NoData(
                    output::NoData {
                    }),
                anyhow::anyhow!(
                    "Unnexpected end of file"),
                &mut *stats,
                &mut *stream)?;
            return Err(anyhow::anyhow!(
                "Unexpected end of file"));
        };

        if sig.typ() != SignatureType::KeyRevocation {
            let typ = sig.typ();
            self.report_failure(
                output::Breakage::BrokenArtifact(
                    output::BrokenArtifact::BrokenRevocation(
                        output::BrokenRevocation {
                            packet: sig.into()
                        })),
                anyhow::anyhow!(
                    "Not a revocation certificate: got a {} signature",
                    typ),
                &mut *stats,
                &mut *stream)?;
            return Err(anyhow::anyhow!(
                "Not a revocation certificate: got a {} signature",
                typ));
        }

        let issuers = sig.get_issuers();
        let mut missing = Vec::new();
        let mut bad = Vec::new();
        for issuer in issuers.iter() {
            let certs = if let Ok(certs)
                = sequoia.lookup(std::iter::once(issuer), None, false, true)
            {
                certs
            } else {
                missing.push(issuer);
                continue;
            };

            for cert in certs.into_iter() {
                if let Ok(_) = sig.clone().verify_primary_key_revocation(
                    cert.primary_key().key(),
                    cert.primary_key().key())
                {
                    let cert = cert.insert_packets(sig.clone())?.0;

                    let artifact = output::Artifact::Revocation(
                        output::Revocation {
                            rev: sig,
                        });

                    self.import_and_report(
                        cert,
                        artifact,
                        vec![], // No provenance.
                        &mut *stats,
                        &mut *stream)?;

                    return Ok(());
                } else {
                    bad.push(issuer);
                }
            }
        }

        if let Some(&bad) = bad.first() {
            self.report_failure(
                output::Breakage::ImportError(
                    output::Artifact::Revocation(
                        output::Revocation {
                            rev: sig,
                        })),
                anyhow::anyhow!(
                    "Appears to be a revocation for {}, \
                     but the revocation certificate is not valid \
                     for that certificate",
                    bad),
                &mut *stats,
                &mut *stream)?;
        } else if ! missing.is_empty() {
            // Dedup issuers.  If we have a key ID that aliases a
            // fingerprint, only keep the fingerprint.
            let (keyids, fingerprints): (Vec<_>, _)
                = missing.into_iter().partition(|kh| {
                    match kh {
                        KeyHandle::KeyID(_) => true,
                        KeyHandle::Fingerprint(_) => false,
                    }
                });

            let fingerprints_as_keyids: BTreeSet<KeyID>
                = BTreeSet::from_iter(fingerprints.iter().map(|fpr| {
                    KeyID::from(*fpr)
                }));

            let keyids: Vec<&KeyHandle> = keyids
                .into_iter()
                .filter(|keyid| {
                    ! fingerprints_as_keyids.contains(&KeyID::from(*keyid))
                })
                .collect();

            let missing = fingerprints.into_iter()
                .chain(keyids.into_iter())
                .collect::<Vec<&KeyHandle>>();

            self.report_failure(
                output::Breakage::ImportError(
                    output::Artifact::Revocation(
                        output::Revocation {
                            rev: sig,
                        })),
                anyhow::anyhow!(
                    "Appears to be a revocation for {}, \
                     but no certificate is available",
                    missing.iter()
                        .map(|issuer| issuer.to_string())
                        .collect::<Vec<_>>()
                        .join(" or ")),
                &mut *stats,
                &mut *stream)?;
        } else {
            self.report_failure(
                output::Breakage::BrokenArtifact(
                    output::BrokenArtifact::BrokenRevocation(
                        output::BrokenRevocation {
                            packet: sig.into(),
                        })),
                anyhow::anyhow!(
                    "Revocation is malformed, missing issuer packet"),
                &mut *stats,
                &mut *stream)?;
        }

        Err(anyhow::anyhow!("Failed to import revocation certificate"))
    }

    /// Imports certificates from autocrypt headers.
    ///
    /// Autocrypt headers are email headers that a sender can set to
    /// communicate to the receiver what the sender's OpenPGP
    /// certificate is.  If the message is sent to multiple parties,
    /// the message may also include so-called gossip, which are the
    /// certificates that the sender used for each of the recipients.
    ///
    /// This function imports certificates found in autocrypt headers.
    /// As the gossip headers are stored in the message, it also
    /// decrypt the message, and verifies the signature.  If the
    /// plaintext was signed using the sender's certificate, it
    /// imports the gossip headers.
    ///
    /// This function processes a single email message.  If passed a
    /// mailbox, it will only process the first message.
    ///
    /// This function emits [`Output::ImportingFailed`] and returns an
    /// error if the input is not an email.  If the input is an email,
    /// and does not contain an autocrypt, this function emits
    /// [`Output::ImportingFailed`] and returns success.  If the
    /// message can't be decrypted or the signature can't be verified,
    /// the error is propagated using [`Output::DecryptedAutocrypt`],
    /// but it does not cause the function to return an error.
    pub fn import_autocrypt<'a, P, S>(
        &self,
        source: impl std::io::Read + Send + Sync,
        prompt: P,
        stream: S)
        -> Result<()>
    where
        P: prompt::Prompt + 'a,
        S: Stream + 'a,
    {
        // XXX: There's a chance that input is already some
        // kind of BufferedReader.  We could try downcasting
        // to see if we could recover it.
        let source = buffered_reader::Generic::with_cookie(
            source, None, Cookie::default());
        let source = Box::new(source) as Box<dyn BufferedReader<Cookie>>;

        let prompt = Box::new(prompt) as Box<dyn prompt::Prompt>;

        let mut stream = Box::new(stream) as Box<dyn Stream>;

        let mut stats = ImportStats::default();

        let result = self.import_autocrypt_(
            source, &mut stats, prompt, &mut stream);

        stream.output(
            self.params(),
            Output::Report(output::Report {
                stats,
            }))?;

        result
    }

    /// Imports certificates from autocrypt headers.
    fn import_autocrypt_<'a>(&self,
                             mut source: Box<dyn BufferedReader<Cookie> + 'a>,
                             mut stats: &mut ImportStats,
                             prompt: Box<dyn prompt::Prompt + 'a>,
                             stream: &mut Box<dyn Stream + 'a>)
                             -> Result<()>
    {
        let &Builder {
            params: Params {
                sequoia,
                ref secret_keys,
                ref session_keys,
            },
        } = self;

        // First, get the Autocrypt headers from the outside.
        let mut ac = || -> Result<_> {
            let mut dup = Dup::with_cookie(&mut source, Cookie::default());
            let ac = autocrypt::AutocryptHeaders::from_reader(&mut dup)?;
            let from = UserID::from(
                ac.from.as_ref().ok_or(anyhow::anyhow!("no From: header"))?
                    .as_str());
            let from_addr = from.email()?.ok_or(
                anyhow::anyhow!("no email address in From: header"))?
                .to_string();
            Ok((ac, from_addr))
        };
        let (ac, from_addr) = match ac() {
            Err(err) => {
                self.report_failure(
                    output::Breakage::BrokenArtifact(
                        output::BrokenArtifact::BrokenAutocrypt(
                            output::BrokenAutocrypt {
                            })),
                    err.context("Not an email"),
                    &mut *stats,
                    &mut *stream)?;
                return Err(anyhow::anyhow!("Input is not an email"));
            }
            Ok((ac, from_addr)) => (ac, from_addr),
        };

        // Get the autocrypt shadow CA.  Be careful to do it at most
        // once.
        let mut autocrypt_ca: Option<Option<Arc<LazyCert>>> = None;
        let mut autocrypt_ca = || {
            if let Some(autocrypt_ca) = autocrypt_ca.as_ref() {
                if let Some(autocrypt_ca) = autocrypt_ca {
                    Some(Arc::clone(autocrypt_ca))
                } else {
                    None
                }
            } else {
                if let Ok(ca) = sequoia.certd_or_else()
                    .and_then(|certd| {
                        certd.shadow_ca_autocrypt().map(|(ca, _)| ca)
                    })
                {
                    autocrypt_ca = Some(Some(Arc::clone(&ca)));
                    Some(ca)
                } else {
                    autocrypt_ca = Some(None);
                    None
                }
            }
        };

        use autocrypt::AutocryptHeaderType::*;
        let mut sender_attributes = None;

        for h in ac.headers.into_iter().filter(|h| h.header_type == Sender) {
            if let Some(addr) = h.attributes.iter()
                .find_map(|a| {
                    if &a.key == "addr"
                        && a.value.to_lowercase() == from_addr.to_lowercase()
                    {
                        Some(a.value.clone())
                    } else {
                        None
                    }
                })
            {
                if let Some(cert) = h.key {
                    let (cert, ca) = if let Some(ca) = autocrypt_ca() {
                        let cert = certify_downloads(
                            sequoia, false, ca.clone(),
                            vec![cert], Some(&addr[..]),
                            &prompt);
                        (cert.into_iter().next().expect("have cert"),
                         Some(ca))
                    } else {
                        (cert, None)
                    };

                    let sender = Arc::new(cert.clone());
                    let attributes = Arc::new(h.attributes);
                    sender_attributes
                        = Some((Arc::clone(&sender),
                                Arc::clone(&attributes)));

                    self.import_and_report(
                        cert,
                        output::Artifact::Autocrypt(
                            output::Autocrypt {
                                sender,
                                sender_attributes: attributes,
                            }),
                        if let Some(ca) = ca {
                            if let Ok(ca)
                                = Arc::unwrap_or_clone(ca).into_cert()
                            {
                                vec![ Arc::new(ca) ]
                            } else {
                                Vec::new()
                            }
                        } else {
                            Vec::new()
                        },
                        &mut stats,
                        &mut *stream)?;
                }
            }
        }

        // If there is no Autocrypt header, don't bother looking for
        // gossip.
        let sender_attributes = if let Some((sender, attributes))
            = sender_attributes
        {
            (sender, attributes)
        } else {
            self.report_failure(
                output::Breakage::BrokenArtifact(
                    output::BrokenArtifact::BrokenAutocrypt(
                        output::BrokenAutocrypt {
                        })),
                anyhow::anyhow!("No autocrypt header"),
                &mut *stats,
                &mut *stream)?;
            return Ok(());
        };

        let dup = Dup::with_cookie(source, Cookie::default());

        let mut decryption_output = Vec::new();
        let mut plaintext = Vec::new();
        let decryption_result = sequoia.decrypt()
            .designated_signers(
                vec![ (*sender_attributes.0).clone() ])
            .secret_keys(secret_keys.clone())
            .session_keys(session_keys.clone())
            .signatures(1)
            .decrypt(
                dup,
                &mut plaintext,
                &prompt,
                &mut decryption_output);

        let decrypted = decryption_output.iter().any(|o| {
            matches!(o, decrypt::Output::Decrypted(_))
        });

        stream.output(
            self.params(),
            Output::DecryptedAutocrypt(output::DecryptedAutocrypt {
                sender: Arc::clone(&sender_attributes.0),
                sender_attributes: Arc::clone(&sender_attributes.1),
                decryption_output,
                decrypted,
            }))?;

        if let Err(_err) = decryption_result {
            // The decryption failed, but we imported the Autocrypt
            // header, which is fine.
            return Ok(());
        }

        let ac = match autocrypt::AutocryptHeaders::from_bytes(&plaintext) {
            Err(err) => {
                // anyhow doesn't implement clone; make a shallow
                // copy.
                let err_ = anyhow::anyhow!(err.to_string())
                    .context("Parsing email");
                self.report_failure(
                    output::Breakage::BrokenArtifact(
                        output::BrokenArtifact::BrokenAutocrypt(
                            output::BrokenAutocrypt {
                            })),
                    err,
                    &mut *stats,
                    &mut *stream)?;
                return Err(err_);
            }
            Ok(ac) => {
                ac
            }
        };

        // We know there has been one good signature from the sender.  Now
        // check that the message was encrypted.  Note: it doesn't have to
        // be encrypted for the purpose of the certification, but
        // Autocrypt requires messages to be signed and encrypted.
        if ! decrypted {
            return Ok(());
        }

        for h in ac.headers.into_iter().filter(|h| h.header_type == Gossip) {
            if let Some(_addr) = h.attributes.iter()
                .find_map(|a| (&a.key == "addr").then(|| a.value.clone()))
            {
                if let Some(cert) = h.key {
                    self.import_and_report(
                        cert.clone(),
                        output::Artifact::AutocryptGossip(
                            output::AutocryptGossip {
                                sender: Arc::clone(&sender_attributes.0),
                                sender_attributes:
                                    Arc::clone(&sender_attributes.1),
                                gossip: Arc::new(cert),
                                gossip_attributes: Arc::new(h.attributes),
                            }),
                        vec![], // No provenance information.
                        &mut stats,
                        &mut *stream)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use openpgp::cert::CertBuilder;
    use openpgp::serialize::Serialize;

    fn check(output: Vec<Output>,
             imports_expected: usize, errors_expected: usize)
    {
        let mut saw_report = false;
        let mut imports_count = 0;
        let mut errors_count = 0;

        eprintln!("Start of import");
        for o in output.iter() {
            match o {
                Output::Imported(_) => {
                    assert!(! saw_report);
                    eprintln!("- Imported");
                    imports_count += 1;
                }
                Output::ImportingFailed(failure) => {
                    assert!(! saw_report);
                    eprintln!("- ImportingFailed: {}", failure);
                    match failure.breakage {
                        output::Breakage::NoCertStore(_) => (),
                        output::Breakage::NoData(_) => (),
                        output::Breakage::ParseError(_)
                            | output::Breakage::BrokenArtifact(_)
                            | output::Breakage::ImportError(_) =>
                        {
                            errors_count += 1;
                        }
                    }
                }
                Output::DecryptedAutocrypt(_) => {
                    assert!(! saw_report);
                    eprintln!("- DecryptedAutocrypt");
                }
                Output::Report(report) => {
                    eprintln!("- Report");
                    assert!(! saw_report);
                    saw_report = true;

                    eprintln!("  Imported {}, updated {}, \
                               {} unchanged, {} errors.",
                              report.stats.certs.new_certs(),
                              report.stats.certs.updated_certs(),
                              report.stats.certs.unchanged_certs(),
                              report.stats.certs.errors());

                    let stats_imported = report.stats.certs.new_certs()
                        + report.stats.certs.unchanged_certs()
                        + report.stats.certs.updated_certs();
                    assert_eq!(stats_imported,
                               imports_count,
                               "imports: stats: {}; count: {}",
                               stats_imported, imports_count);
                    assert_eq!(report.stats.certs.errors(),
                               errors_count,
                               "errors: stats {}; count: {}",
                               report.stats.certs.errors(), errors_count);

                    if imports_expected != imports_count
                        || errors_expected != errors_count
                    {
                        panic!("Imported {}, expected {}; \
                                {} errors, expected: {}",
                               imports_count, imports_expected,
                               errors_count, errors_expected);
                    }
                }
            }
        }
        eprintln!("End of import");

        assert!(saw_report);
    }

    #[test]
    fn certs() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Empty file.
        let mut output = Vec::new();
        let result = sq.cert_import().import_certs(
            std::io::Cursor::new(b""),
            &mut output);

        check(output, 0, 0);
        assert!(result.is_err());

        // Junk.
        let input = vec![b'!'; 16 * 1024];
        let mut output = Vec::new();
        let result = sq.cert_import().import_certs(
            std::io::Cursor::new(&input),
            &mut output);

        check(output, 0, 0);
        assert!(result.is_err());

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let (bob, _bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();

        // Import Alice's certificate.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import().import_certs(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 1, 0);
        assert!(result.is_ok());

        // Import Alice's and Bob's certificates.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        bob.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import().import_certs(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 2, 0);
        assert!(result.is_ok());

        // Add some junk in between and try again.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        write!(&mut input, "foobar").unwrap();
        bob.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import().import_certs(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 2, 1);
        // An error is returned if there are any problems.
        assert!(result.is_err());
    }

    #[test]
    fn revocation() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Empty file.
        let mut output = Vec::new();
        let result = sq.cert_import().import_revocation(
            std::io::Cursor::new(b""),
            &mut output);

        check(output, 0, 0);
        assert!(result.is_err());

        // Junk.
        let input = vec![b'!'; 16 * 1024];
        let mut output = Vec::new();
        let result = sq.cert_import().import_revocation(
            std::io::Cursor::new(&input),
            &mut output);

        check(output, 0, 0);
        assert!(result.is_err());

        let (alice, alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let alice_rev = Packet::from(alice_rev);
        let (_bob, bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();
        let bob_rev = Packet::from(bob_rev);

        // Try to import a bare revocation certificate, but fail
        // because the certificate is not imported.
        let mut input = Vec::new();
        alice_rev.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import().import_revocation(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 0, 1);
        assert!(result.is_err());

        // Try to import two bare revocation certificates, which is
        // not allowed.
        let mut input = Vec::new();
        alice_rev.serialize(&mut input).unwrap();
        bob_rev.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import().import_revocation(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 0, 1);
        assert!(result.is_err());

        // Import Alice's certificate as a revocation certificate.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import().import_revocation(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 0, 1);
        assert!(result.is_err());

        // Import Alice's certificate.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import().import_certs(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 1, 0);
        assert!(result.is_ok());

        // Import Alice's bare revocation certificate.
        let mut input = Vec::new();
        alice_rev.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import().import_revocation(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 1, 0);
        assert!(result.is_ok());

        // Import it a second time.
        let mut output = Vec::new();
        let result = sq.cert_import().import_revocation(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 1, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn autocrypt() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Empty file.
        let mut output = Vec::new();
        let result = sq.cert_import().import_autocrypt(
            std::io::Cursor::new(b""),
            prompt::Cancel::new(),
            &mut output);

        check(output, 0, 1);
        assert!(result.is_err());

        // Not an email.
        let mut output = Vec::new();
        let result = sq.cert_import().import_autocrypt(
            std::io::Cursor::new(b"not an email"),
            prompt::Cancel::new(),
            &mut output);

        check(output, 0, 1);
        assert!(result.is_err());

        // Looks a bit like an email, but no autocrypt header.
        let mut output = Vec::new();
        let result = sq.cert_import().import_autocrypt(
            std::io::Cursor::new(b"\
From: Alice <alice@example.org>
To: Bob <bob@example.org>

Hi!
"),
            prompt::Cancel::new(),
            &mut output);

        check(output, 0, 1);
        if let Err(err) = result {
            panic!("Failed to import certificates: {:?}", err);
        }

        // Autocrypt header.
        let mut output = Vec::new();
        let result = sq.cert_import().import_autocrypt(
            std::io::Cursor::new(b"\
Date: Sat, 7 Dec 2024 12:38:37 +0100
From: Patrick Brunschwig <patrick@enigmail.net>
Autocrypt: addr=patrick@enigmail.net; prefer-encrypt=mutual; keydata=
 xjMEZmQU3RYJKwYBBAHaRw8BAQdA4/l57O4gUweBOgVW9S1yutfgMHF1iURviG1jcb+/3z7N
 KVBhdHJpY2sgQnJ1bnNjaHdpZyA8cGF0cmlja0BlbmlnbWFpbC5uZXQ+wpIEEBYKAEQFgmZk
 FN0FiQlmAYAECwkHCAmQoPyuK0NGVXYDFQgKBBYAAgECGQECmwMCHgEWIQRk9N12hm6miW5K
 hpug/K4rQ0ZVdgAAM+UA/1brtqyREKa65BRMYaxiySCYTPRObIkOWAWBKjUt/N/7APwNhkV4
 MzcNdCU1qGJWEJGPQCY8tF3xI7H+Bqg12UuRBM44BGZkFN0SCisGAQQBl1UBBQEBB0B1cnik
 tl07/9iRJLfy4AzCxM2sxByke0TXivmjKxodXQMBCAfCfgQYFgoAMAWCZmQU3QWJCWYBgAmQ
 oPyuK0NGVXYCmwwWIQRk9N12hm6miW5Khpug/K4rQ0ZVdgAAYksBAIUetCBOgiegbKKBPhah
 oONLAjAqbLlkGZZW54HaVTiUAQDbiHnmrXQ6dWpdMfjUeO9xvSgZ2b2Yup7vE4C4k/b7DA==

Hi!
"),
            prompt::Cancel::new(),
            &mut output);

        check(output, 1, 0);
        if let Err(err) = result {
            panic!("Failed to import certificates: {:?}", err);
        }
    }
}
