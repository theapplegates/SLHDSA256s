//! Functionality for importing keys.
//!
//! A key is a certificate with secret key material.  When using
//! [`Sequoia::cert_import`] to import a certificate, any secret key
//! material is silently ignored.  The functionality here first
//! imports the secret key material into the key store, and then
//! imports the certificate into the certificate store.
//!
//! # Examples
//!
//! Import a secret key material from an OpenPGP keyring:
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
//! # alice.as_tsk().serialize(&mut input).unwrap();
//! #
//! # let mut input = std::io::Cursor::new(&input[..]);
//! #
//! if let Err(err) = sq.key_import().import_keyring(input, &mut ()) {
//!     eprintln!("Failed to import at least one key: {}", err);
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
//! use sequoia::key::import::Output;
//! use sequoia::key::import::output::*;
//! use sequoia::key::import;
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
//! # alice.as_tsk().serialize(&mut input).unwrap();
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
//!             Output::Imported(Imported { cert, .. }) => {
//!                 eprintln!("Imported {}", cert.fingerprint());
//!             }
//!             Output::Report(Report { stats, ..}) => {
//!                 eprintln!("New {}, updated: {}, unchanged: {}, errors: {}",
//!                           stats.keys.new,
//!                           stats.keys.updated,
//!                           stats.keys.unchanged,
//!                           stats.keys.errors);
//!                 # assert_eq!(stats.keys.new, 1);
//!                 # assert_eq!(stats.keys.errors, 0);
//!             }
//!             _ => (),
//!         }
//!
//!         // Return an error to abort processing.
//!         Ok(())
//!     }
//! }
//!
//! let mut stream = Stream { };
//! if let Err(err) = sq.key_import().import_keyring(input, &mut stream) {
//!     eprintln!("Failed to import at least one key: {}", err);
//! }
//! # Ok(()) }
//! ```

use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use crate::Result;
use crate::Sequoia;
use crate::clone_anyhow;
use crate::clone_error;
use crate::types::import_stats::ImportStats;
use crate::types::import_stats::ImportStatus;

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

/// Data structures related to [`Error`].
///
/// The errors are divided into categories, and the categories contain
/// more precise errors.  In this way, if you match on a category, and
/// a new error is added you can still react.
pub mod error {
    use super::*;

    /// An unrecoverable error occurred parsing the input.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("Error parsing input")]
    pub struct ParseError {
        #[source]
        pub error: anyhow::Error,
    }

    /// We can't import anything, because we don't have a
    /// key store.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("No key store")]
    pub struct NoKeyStore {
        /// The related error.
        #[source]
        pub error: anyhow::Error,
    }

    /// We can't import anything, because the key store is not usable.
    ///
    /// This error is returned if there is no soft key backend.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("Error using key store")]
    pub struct KeyStoreUnusable {
        /// The related error.
        #[source]
        pub error: anyhow::Error,
    }

    /// We can't import the certificate, because we don't have a
    /// certificate store.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("No certificate store")]
    pub struct NoCertStore {
        #[source]
        pub error: anyhow::Error,
    }

    /// We didn't find any certificates.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("Input does not contain any certificates")]
    pub struct NoData {
    }

    /// A system-related (as opposed to key- or certificate-related)
    /// error.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    pub enum SystemError {
        /// An unrecoverable error occurred parsing the input.
        #[error(transparent)]
        ParseError(#[from] ParseError),

        /// We can't import anything, because we don't have a key
        /// store.
        #[error(transparent)]
        NoKeyStore(#[from] NoKeyStore),

        /// We can't import anything, because the key store is not usable.
        #[error(transparent)]
        KeyStoreUnusable(#[from] KeyStoreUnusable),

        /// We can't import the certificate, because we don't have a
        /// certificate store.
        #[error(transparent)]
        NoCertStore(#[from] NoCertStore),

        /// We didn't find any certificates.
        #[error(transparent)]
        NoData(#[from] NoData),
    }

    /// An error parsing the low-level repsentation of the
    /// certificate.
    ///
    /// This is often recoverable and the parse is able to skip to the
    /// next certificate.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("Error parsing input")]
    pub struct CertParseError {
        #[source]
        pub error: anyhow::Error,
    }

    /// A certificate is broken, and can't be imported.
    ///
    /// We were able to parse some bytes into something that resembles
    /// a certificate, but upon closer inspection, the certificate is
    /// broken.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("Error parsing the certificate {}", .cert.fingerprint())]
    pub struct BrokenCert {
        // XXX: Make this a raw cert so that in the future we can
        // parallelize the parsing.
        pub cert: Cert, // RawCert<'static>,
        #[source]
        pub error: anyhow::Error,
    }

    /// The certificate does not contain any secret key material.
    ///
    /// If the certificate does not contain secret key material, then
    /// there is nothing to import.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("{} does not contain any secret key material",
            .cert.fingerprint())]
    pub struct MissingSecretKeyMaterial {
        // XXX: Make this a raw cert so that in the future we can
        // parallelize the parsing.
        pub cert: Cert, // RawCert<'static>,
    }

    /// An error occurred importing the key into the key store.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("Error importing the certificate {} into the key store",
            .cert.fingerprint())]
    pub struct ImportError {
        pub cert: Cert,
        #[source]
        pub error: anyhow::Error,
    }

    /// An error related to importing a key.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error(transparent)]
    pub enum KeyError {
        CertParseError(CertParseError),
        BrokenCert(BrokenCert),
        MissingSecretKeyMaterial(MissingSecretKeyMaterial),
        ImportError(ImportError),
    }

    impl KeyError {
        /// Returns the certificate's fingerprint, if known.
        pub fn fingerprint(&self) -> Option<Fingerprint> {
            match self {
                KeyError::CertParseError(CertParseError { .. }) => None,
                KeyError::BrokenCert(BrokenCert { cert, .. })
                    | KeyError::MissingSecretKeyMaterial(
                        MissingSecretKeyMaterial { cert, .. })
                    | KeyError::ImportError(ImportError { cert, .. })
                    =>
                {
                    Some(cert.fingerprint())
                }
            }
        }

        /// Returns the certificate, if it could be parsed.
        pub fn cert(&self) -> Option<&Cert> {
            match self {
                KeyError::CertParseError(CertParseError { .. }) => None,
                KeyError::BrokenCert(BrokenCert { cert, .. })
                    | KeyError::MissingSecretKeyMaterial(
                        MissingSecretKeyMaterial { cert, .. })
                    | KeyError::ImportError(ImportError { cert, .. })
                    =>
                {
                    Some(cert)
                }
            }
        }
    }

    /// We failed to import a certificate into the certificate store.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("Error importing the certificate {} into the certificate store",
            .cert.fingerprint())]
    pub struct CertImportError {
        /// The certificate that we were trying to import.
        ///
        /// Any secret material has been stripped.
        pub cert: Cert,
        /// The underlying error.
        #[source]
        pub error: anyhow::Error,
    }

    /// An error related to importing a certificate to the certificate
    /// store.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error(transparent)]
    pub enum CertError {
        /// We failed to import a certificate into the certificate store.
        CertImportError(CertImportError),
    }
}


/// Errors related to importing keys.
///
/// Errors are divided into categories and each category contains more
/// precise errors.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub enum Error {
    /// A system-related error.
    ///
    /// This is contrast to the other errors, which are related to a
    /// specific key or certificate.
    #[error(transparent)]
    SystemError(#[from] error::SystemError),
    /// Errors related to importing a key.
    #[error(transparent)]
    KeyError(#[from] error::KeyError),
    /// Errors related to importing a certificate.
    #[error(transparent)]
    CertError(#[from] error::CertError),
}

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// We imported a key.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Imported {
        /// What we imported.
        pub cert: Cert,

        /// The merged certificate on the certificate store.
        ///
        /// This is the result after merging the certificate with any
        /// existing certificate in the certificate store.  Note:
        /// secret key material will have been stripped.
        ///
        /// If merging into the key store succeeds, but merging into
        /// the certificate store fails, we emit [`Imported`] and set
        /// this to the error.
        pub merged: Result<Cert, Error>,

        pub cert_import_status: ImportStatus,

        /// The keys and their import status.
        pub key_import_status: Vec<(Fingerprint, ImportStatus)>,
    }

    /// We failed to import a key.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error(transparent)]
    pub struct ImportFailed {
        /// The related error.
        pub error: Error,
    }

    /// A report about the operation.
    ///
    /// This is emitted once after attempting to import all of the
    /// specified keys.
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
    /// Emitted after the key being imported was successfully imported
    /// to the key store.
    Imported(output::Imported),

    /// Emitted when the key can't be imported to the key store.
    ImportFailed(output::ImportFailed),

    /// Emitted at the end.
    ///
    /// This is always emitted whether anything is imported or not.
    Report(output::Report),
}

impl Sequoia {
    /// Returns a builder providing control over how to import
    /// keys.
    ///
    /// See [`Builder`] for details.
    pub fn key_import(&self) -> Builder<'_>
    {
        Builder {
            params: Params {
                sequoia: self,
            },
        }
    }
}

/// The key import parameters.
///
/// These parameters are used by [`import`](Builder::import).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }
}

/// Imports keys.
///
/// A builder providing control over how to import keys.
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

    /// Report that importing something failed.
    ///
    /// This also increments the stats, if appropriate.
    fn report_failure<'a>(&self,
                          error: Error,
                          stats: &mut ImportStats,
                          stream: &mut Box<dyn Stream + 'a>)
                          -> Result<()>
    {
        if matches!(error, Error::KeyError(_)) {
            stats.keys.errors += 1;
            stats.certs.inc_errors();
        }
        stream.output(
            self.params(),
            Output::ImportFailed(output::ImportFailed {
                error,
            }))
    }

    /// Imports keys encoded as OpenPGP keyring.
    ///
    /// This function imports keys into the key store.  If a key can
    /// be imported, then the certificate is imported into the
    /// certificate store.  Whether the latter succeeds can be
    /// determined by examining
    /// [`output::Imported::merged`](output::Imported) field.  If the
    /// key cannot be imported, e.g., because it does not contain any
    /// secret key material, the certificate is not imported into the
    /// certificate store.
    ///
    /// This function returns an error if the input is not an OpenPGP
    /// keyring.  If the OpenPGP keyring contains recoverable errors,
    /// these are reported using [`Output::ImportFailed`], but parsing
    /// is not aborted.
    ///
    /// This function returns an error if the input is not an OpenPGP
    /// keyring, if there was an issue importing one or more keys, or
    /// if the input contains no keys.  In other words, if five keys
    /// are imported and there is a problem with one of them, this
    /// function conservatively returns an error.  Depending on the
    /// context, the error may not be fatal, and showing a warning may
    /// be sufficient.
    pub fn import_keyring<'a, I, S>(&self, input: I, stream: S) -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        S: Stream + 'a,
    {
        let &Builder {
            params: Params {
                sequoia: _,
            },
        } = self;

        let mut stream = Box::new(stream) as Box<dyn Stream>;

        let mut stats = ImportStats::default();

        // Return the first error.
        let mut ret: Result<()> = Ok(());

        let parser = match CertParser::from_reader(input) {
            Ok(parser) => parser,
            Err(err) => {
                let err_ = clone_anyhow(&err);
                self.report_failure(
                    Error::SystemError(
                        error::SystemError::ParseError(
                            error::ParseError {
                                error: err,
                            })),
                    &mut stats,
                    &mut stream)?;
                stream.output(
                    self.params(),
                    Output::Report(output::Report {
                        stats,
                    }))?;
                return Err(err_);
            }
        };

        let mut have_one = false;
        for r in parser {
            have_one = true;

            let cert = match r {
                Ok(cert) => cert,
                Err(err) => {
                    // Error parsing a key.
                    if ret.is_ok() {
                        ret = Err(anyhow::Error::from(
                            Error::KeyError(
                                error::KeyError::CertParseError(
                                    error::CertParseError {
                                        error: clone_anyhow(&err),
                                    }))));
                    }

                    self.report_failure(
                        Error::KeyError(
                            error::KeyError::CertParseError(
                                error::CertParseError {
                                    error: err,
                                })),
                        &mut stats,
                        &mut stream)?;
                    continue;
                }
            };

            match self.import_key(cert, &mut stats) {
                Ok(imported) => {
                    stream.output(
                        self.params(),
                        Output::Imported(imported))?;
                }

                Err(err) => {
                    // Error importing the key.
                    if ret.is_ok() {
                        ret = Err(clone_error(&err));
                    }

                    self.report_failure(
                        err,
                        &mut stats,
                        &mut stream)?;
                }
            }
        }

        if ! have_one {
            self.report_failure(
                Error::SystemError(
                    error::SystemError::NoData(
                        error::NoData {
                        })),
                &mut stats,
                &mut stream)?;

            if ret.is_ok() {
                ret = Err(Error::SystemError(
                    error::SystemError::NoData(
                        error::NoData {
                        })).into());
            }
        }

        stream.output(
            self.params(),
            Output::Report(output::Report {
                stats,
            }))?;

        Ok(ret?)
    }

    /// Imports the cert into the key store and the cert store.
    fn import_key(&self, cert: Cert, stats: &mut ImportStats)
        -> Result<output::Imported, Error>
    {
        let &Builder {
            params: Params {
                sequoia,
            },
        } = self;

        if ! cert.is_tsk() {
            return Err(Error::KeyError(
                error::KeyError::MissingSecretKeyMaterial(
                    error::MissingSecretKeyMaterial {
                        cert,
                    })));
        }

        let keystore = sequoia.key_store_or_else()
            .map_err(|err| {
                Error::SystemError(
                    error::SystemError::NoKeyStore(
                        error::NoKeyStore {
                            error: err,
                        }))
            })?;
        let mut keystore = keystore.lock().unwrap();

        let softkeys = || {
            let mut softkeys = None;
            for mut backend in keystore.backends()?.into_iter() {
                if backend.id()? == "softkeys" {
                    softkeys = Some(backend);
                    break;
                }
            }

            drop(keystore);

            if let Some(softkeys) = softkeys {
                Ok(softkeys)
            } else {
                Err(anyhow::anyhow!("softkeys backend is not configured"))
            }
        };

        let mut softkeys = softkeys()
            .map_err(|err| {
                Error::SystemError(
                    error::SystemError::KeyStoreUnusable(
                        error::KeyStoreUnusable {
                            error: err,
                        }))
            })?;

        let result = match softkeys.import(&cert) {
            Ok(result) => result,
            Err(err) => {
                return Err(Error::KeyError(
                    error::KeyError::ImportError(
                        error::ImportError {
                            cert: cert,
                            error: err,
                        })));
            }
        };

        let mut key_import_status = Vec::with_capacity(result.len());
        let mut import_status = ImportStatus::Unchanged;
        for (s, key) in result.into_iter() {
            let s: ImportStatus = s.into();

            import_status = import_status.max(s.clone());

            key_import_status.push(
                (key.fingerprint(), s));
        }

        match import_status {
            ImportStatus::New => stats.keys.new += 1,
            ImportStatus::Unchanged => stats.keys.unchanged += 1,
            ImportStatus::Updated => stats.keys.updated += 1,
        }

        // Also insert the certificate into the certificate store.
        // If we can't, we don't fail.  This allows, in
        // particular, `sq --cert-store=none key import` to work.
        let cert = cert.strip_secret_key_material();
        let cert = Arc::new(LazyCert::from(cert));

        let mut cert_import_status = ImportStatus::Unchanged;
        let merged = match sequoia.cert_store_or_else() {
            Ok(cert_store) => {
                let new_certs = stats.certs.new_certs();
                let updated_certs = stats.certs.updated_certs();

                match cert_store.update_by(Arc::clone(&cert), stats) {
                    Ok(merged) => {
                        let merged = Arc::unwrap_or_clone(merged)
                            .into_cert().expect("is a cert");

                        if stats.certs.new_certs() > new_certs {
                            cert_import_status = ImportStatus::New;
                        } else if stats.certs.updated_certs() > updated_certs {
                            cert_import_status = ImportStatus::Updated;
                        }

                        Ok(merged)
                    }
                    Err(err) => {
                        let cert = Arc::unwrap_or_clone(cert.clone())
                            .into_cert().expect("is a cert");

                        Err(Error::CertError(
                            error::CertError::CertImportError(
                                error::CertImportError {
                                    cert: cert,
                                    error: err,
                                })))
                    }
                }
            }
            Err(err) => {
                // No cert store.
                stats.certs.inc_errors();
                Err(Error::SystemError(
                    error::SystemError::NoCertStore(
                        error::NoCertStore {
                            error: err,
                        })))
            }
        };

        // As long as we can import to the key store, we return Imported.
        Ok(output::Imported {
            cert: Arc::unwrap_or_clone(cert)
                .into_cert().expect("is a cert"),
            merged,
            key_import_status,
            cert_import_status,
        })
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
                Output::ImportFailed(failure) => {
                    assert!(! saw_report);
                    eprintln!("- ImportingFailed: {}", failure);
                    match failure.error {
                        Error::KeyError(_) => {
                            errors_count += 1;
                        }
                        _ => (),
                    }
                }
                Output::Report(report) => {
                    eprintln!("- Report");
                    assert!(! saw_report);
                    saw_report = true;

                    eprintln!("  Imported {}, updated {}, \
                               {} unchanged, {} errors.",
                              report.stats.keys.new,
                              report.stats.keys.updated,
                              report.stats.keys.unchanged,
                              report.stats.keys.errors);

                    let stats_imported = report.stats.keys.new
                        + report.stats.keys.unchanged
                        + report.stats.keys.updated;
                    assert_eq!(stats_imported,
                               imports_count,
                               "imports: stats: {}; count: {}",
                               stats_imported, imports_count);
                    assert_eq!(report.stats.keys.errors,
                               errors_count,
                               "errors: stats {}; count: {}",
                               report.stats.keys.errors, errors_count);

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
        let result = sq.key_import().import_keyring(
            std::io::Cursor::new(b""),
            &mut output);

        check(output, 0, 0);
        assert!(result.is_err());

        // Junk.
        let input = vec![b'!'; 16 * 1024];
        let mut output = Vec::new();
        let result = sq.key_import().import_keyring(
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

        // Import Alice's certificate (not key!).
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import().import_keyring(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 0, 1);
        assert!(result.is_err());

        // Import Alice's key.
        let mut input = Vec::new();
        alice.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import().import_keyring(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 1, 0);
        assert!(result.is_ok());

        // Import Alice's and Bob's keys.
        let mut input = Vec::new();
        alice.as_tsk().serialize(&mut input).unwrap();
        bob.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import().import_keyring(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 2, 0);
        assert!(result.is_ok());

        // Import Alice's cert and Bob's key.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        bob.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import().import_keyring(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 1, 1);
        assert!(result.is_err());

        // Add some junk in between and try again.
        let mut input = Vec::new();
        alice.as_tsk().serialize(&mut input).unwrap();
        write!(&mut input, "foobar").unwrap();
        bob.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import().import_keyring(
            std::io::Cursor::new(&input[..]),
            &mut output);

        check(output, 2, 1);
        // An error is returned if there are any problems.
        assert!(result.is_err());
    }
}
