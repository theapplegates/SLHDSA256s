use std::borrow::Cow;
use std::error::Error as _;
use std::path::Path;
use std::path::PathBuf;

use sequoia::key::import::Error;
use sequoia::key::import::error;
use sequoia::key::import;
use sequoia::types::PreferredUserID;
use sequoia::types::import_stats::ImportStatus;

use import::output::*;
use import::Output;

use sequoia::types::import_stats::ImportStats;

use crate::Result;
use crate::Sq;

pub struct Stream<'a> {
    sq: &'a Sq,
    source: Option<PathBuf>,
    output: Box<dyn std::io::Write + Send + Sync + 'a>,
    print_stats: bool,
    pub stats: Option<ImportStats>,
}

impl<'a> Stream<'a> {
    /// `source` is the filename of the source.  This is only used for
    /// display purposes.
    ///
    /// `output` is where to write the human readable output.  This is
    /// normally `stdout` or `stderr`.
    ///
    /// `print_stats` controls whether the statistics are shown at the
    /// end.
    pub fn new(sq: &'a Sq,
               source: Option<&Path>,
               output: impl std::io::Write + Send + Sync + 'a,
               print_stats: bool)
        -> Self
    {
        Self {
            sq,
            source: source.map(|s| s.to_path_buf()),
            output: Box::new(output),
            print_stats,
            stats: None,
        }
    }
}

impl import::Stream for Stream<'_> {
    fn output(&mut self,
              _params: &import::Params,
              output: import::Output)
        -> Result<()>
    {
        match output {
            Output::Imported(
                Imported {
                    cert,
                    merged,
                    key_import_status,
                    cert_import_status,
                    ..
                }) =>
            {
                let fp = cert.fingerprint();
                let id = format!("{} {}",
                                 cert.fingerprint(),
                                 self.sq.best_userid(&cert, true).display());

                let key_import_status_max = key_import_status
                    .iter()
                    .map(|(_fpr, status)| status.clone())
                    .max()
                    .unwrap_or(ImportStatus::Unchanged);

                wwriteln!(&mut self.output,
                          "Imported {} from {}: {}",
                          id,
                          if let Some(filename) = self.source.as_ref() {
                              Cow::Owned(filename.display().to_string())
                          } else {
                              Cow::Borrowed("stdin")
                          },
                          if key_import_status_max == cert_import_status {
                              key_import_status_max.to_string()
                          } else {
                              format!("key {}, cert {}",
                                      key_import_status_max, cert_import_status)
                          });

                for (fpr, status) in key_import_status.iter() {
                    self.sq.info(format_args!(
                        "Importing {} into key store: {:?}",
                        fpr, status));
                }

                if let Err(err) = merged {
                    wwriteln!(&mut self.output,
                              "Warning: Imported the key into the key store, \
                               but failed to import the certificate into the \
                               certificate store: {}",
                              err);
                }

                self.sq.hint(format_args!("If this is your key, you should  \
                                           mark it as a fully trusted \
                                           introducer:"))
                    .sq().arg("pki").arg("link").arg("authorize")
                    .arg("--unconstrained")
                    .arg_value("--cert", &fp)
                    .arg("--all")
                    .done();

                self.sq.hint(format_args!("Otherwise, consider marking it as \
                                           authenticated:"))
                    .sq().arg("pki").arg("link").arg("add")
                    .arg_value("--cert", &fp)
                    .arg("--all")
                    .done();
            }

            Output::ImportFailed(
                ImportFailed {
                    error,
                    ..
                }) =>
            {
                let input = if let Some(source) = self.source.as_ref() {
                    Cow::Owned(source.display().to_string())
                } else {
                    Cow::Borrowed("input")
                };

                match error {
                    Error::SystemError(error) => {
                        match error {
                            error::SystemError::NoKeyStore(
                                error::NoKeyStore {
                                    error,
                                    ..
                                }) =>
                            {
                                // Return immediately.  This is fatal;
                                // we can't do anything else.
                                return Err(error);
                            }
                            error::SystemError::ParseError(
                                error::ParseError {
                                    error,
                                    ..
                                }) =>
                            {
                                return Err(error.context(format!(
                                    "Reading {}", input)));
                            }
                            error::SystemError::NoData(
                                error::NoData {
                                    ..
                                }) =>
                            {
                                if ! self.sq.quiet() {
                                    wwriteln!(&mut self.output,
                                              "Warning: {} does not contain any certificates",
                                              input);
                                }
                            }
                            // No special handling for these errors.
                            _ => {
                                wwriteln!(&mut self.output,
                                          "Error importing key from {}: {}",
                                          input, error);
                            }
                        }
                    }
                    Error::KeyError(error) => {
                        let id = error.fingerprint()
                            .map(|fpr| {
                                let userid = error
                                    .cert()
                                    .map(|cert| {
                                        self.sq.best_userid(cert, true)
                                    })
                                    .unwrap_or_else(|| {
                                        PreferredUserID::unknown()
                                    });

                                Cow::Owned(format!(
                                    "{} {}",
                                    fpr, userid.display()))
                            })
                            .unwrap_or(Cow::Borrowed("key"));

                        let mut chain = Vec::new();
                        chain.push(error.to_string());
                        let mut source = error.source();
                        while let Some(s) = source {
                            chain.push(s.to_string());
                            source = s.source();
                        }

                        wwriteln!(&mut self.output,
                                  "Error importing {} from {}:{}{}",
                                  id,
                                  input,
                                  if chain.len() == 1 {
                                      " "
                                  } else {
                                      ""
                                  },
                                  if chain.len() == 1 {
                                      Cow::Owned(error.to_string())
                                  } else {
                                      Cow::Borrowed("")
                                  });
                        if chain.len() > 1 {
                            for c in chain {
                                wwriteln!(stream = &mut self.output,
                                          indent = "    ",
                                          "{}", c);
                            }
                        }

                        match error {
                            error::KeyError::MissingSecretKeyMaterial(
                                error::MissingSecretKeyMaterial {
                                    cert,
                                    ..
                                }) =>
                            {
                                if ! cert.is_tsk() {
                                    self.sq.hint(format_args!(
                                        "To import certificates, do:"))
                                        .sq().arg("cert").arg("import")
                                        .arg(input)
                                        .done();
                                }
                            }
                            // No special handling for these errors.
                            _ => (),
                        }
                    }
                    // No special handling for these errors.
                    error => {
                        wwriteln!(&mut self.output,
                                  "Error importing key from {}: {}",
                                  input, error);
                    },
                }
            }

            Output::Report(
                Report {
                    stats,
                    ..
                }) =>
            {
                if self.print_stats {
                    wwriteln!(&mut self.output);
                    stats.print_summary(&mut self.output, &self.sq.sequoia)?;
                }
                self.stats = Some(stats);
            }

            _output => {
                // eprintln!("Unknown output: {:?}", output);
            }
        }

        Ok(())
    }
}
