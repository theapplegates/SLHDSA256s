use std::borrow::Cow;
use std::path::Path;
use std::path::PathBuf;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::types::KeyFlags;

use sequoia::cert::import;
use sequoia::decrypt;

use import::output::*;
use import::Output;

use sequoia::types::import_stats::ImportStats;

use crate::Result;
use crate::Sq;
use crate::common::ui::emit_cert;
use crate::common::ui::emit_cert_key_handle_userid_str;

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
                    artifact,
                    merged,
                    recorded_provenance,
                    ..
                }) =>
            {
                emit_cert(&mut self.output, self.sq, &merged)?;

                match &artifact {
                    Artifact::Cert(cert) => {
                        wwriteln!(stream = &mut self.output,
                                  initial_indent = "   - ", "imported");

                        if cert.is_tsk() {
                            let mut cmd = self.sq.hint(format_args!(
                                "Certificate {} contains secret key material.  \
                                 To import keys, do:",
                                merged.fingerprint()))
                                .sq().arg("key").arg("import");

                            if let Some(file) = self.source.as_ref() {
                                cmd = cmd.arg(file.display());
                            }

                            cmd.done();
                        }
                    }
                    Artifact::Revocation(_sig) => {
                        wwriteln!(stream = &mut self.output,
                                  initial_indent = "   - ",
                                  "imported revocation certificate");
                    }
                    Artifact::Autocrypt(_ac) => {
                        wwriteln!(stream = &mut self.output,
                                  initial_indent = "   - ", "imported");
                    }
                    Artifact::AutocryptGossip(_ac) => {
                        wwriteln!(stream = &mut self.output,
                                  initial_indent = "   - ", "imported");
                    }
                    _ => (),
                }

                if ! recorded_provenance.is_empty() {
                    wwriteln!(stream = &mut self.output,
                              initial_indent = "   - ",
                              "provenance information recorded");
                }

                // XXX: We should always separate records with a new line.
                if ! matches!(artifact, Artifact::Revocation(_sig)) {
                    wwriteln!(stream = &mut self.output);
                }
            }

            Output::ImportingFailed(
                ImportingFailed {
                    breakage,
                    error,
                    ..
                }) =>
            {
                match breakage {
                    // Certificates
                    Breakage::ImportError(Artifact::Cert(cert)) => {
                        emit_cert(&mut self.output, self.sq, &cert)?;

                        wwriteln!(stream = &mut self.output,
                                  initial_indent = "   - ", "failed: {}",
                                  error);
                        wwriteln!(&mut self.output);
                    }
                    Breakage::BrokenArtifact(
                        BrokenArtifact::BrokenCert(cert)) =>
                    {
                        emit_cert_key_handle_userid_str(
                            &mut self.output,
                            &KeyHandle::from(cert.cert.fingerprint()),
                            &cert.cert.userids().next()
                                .map(|userid| {
                                    Cow::Owned(format!(
                                        "{} (UNAUTHENTICATED)",
                                        String::from_utf8_lossy(userid.value())))
                                })
                                .unwrap_or_else(|| {
                                    Cow::Borrowed("<unknown>")
                                }))?;

                        wwriteln!(stream = &mut self.output,
                                  initial_indent = "   - ", "failed: {}",
                                  error);
                        wwriteln!(&mut self.output);
                    }

                    // Revocations.
                    Breakage::ImportError(Artifact::Revocation(rev)) => {
                        wwriteln!(stream = &mut self.output,
                                  initial_indent = "   - ",
                                  "Error importing revocation certificate: {}",
                                  error);

                        if let Some(issuer) = rev.rev.get_issuers()
                            .into_iter().next()
                        {
                            self.sq.hint(
                                format_args!("{}", "To search for a certificate, try:"))
                                .sq().arg("network").arg("search")
                                .arg(issuer.to_string())
                                .done();
                        }
                    }
                    Breakage::BrokenArtifact(
                        BrokenArtifact::BrokenRevocation(
                            BrokenRevocation {
                                packet: _,
                                ..
                            })) =>
                    {
                        wwriteln!(stream = &mut self.output,
                                  initial_indent = "   - ",
                                  "Error importing revocation certificate: {}",
                                  error);
                    }

                    // Autocrypt.
                    Breakage::ImportError(
                        Artifact::Autocrypt(
                            Autocrypt {
                                sender: _,
                                sender_attributes: _,
                                ..
                            })) => {
                    }
                    Breakage::BrokenArtifact(
                        BrokenArtifact::BrokenAutocrypt(
                            BrokenAutocrypt {
                                ..
                            })) => {
                    }
                    _ => (),
                }
            }

            Output::DecryptedAutocrypt(
                DecryptedAutocrypt {
                    sender: _,
                    decryption_output,
                    decrypted,
                    ..
                }) if ! decrypted =>
            {
                // We unconditionally write to stderr.
                let mut stderr = std::io::stderr();

                let mut error = None;
                for o in decryption_output.iter() {
                    let decrypt::Output::Info(info)
                        = o else { continue };
                    error = Some(Cow::Owned(info.to_string()));
                    break;
                }

                let mut failure = None;
                for o in decryption_output.iter() {
                    if let decrypt::Output::DecryptionFailed(f) = o {
                        failure = Some(f);
                        break;
                    }
                }
                let Some(failure) = failure else { return Ok(()); };

                let mut printed = false;
                match failure {
                    decrypt::output::DecryptionFailed::MissingSecretKeyMaterial(
                        decrypt::output::MissingSecretKeyMaterial {
                            pkesks,
                            skesks: _,
                            ..
                        }) =>
                    {
                        let e = if let Some(e) = error.as_ref() {
                            e
                        } else {
                            error = Some(Cow::Borrowed(
                                "No key to decrypt message"));
                            error.as_ref().unwrap()
                        };

                        wwriteln!(stream = &mut stderr,
                                  "{}.  The message appears to be encrypted to:",
                                  e);
                        wwriteln!(stream = &mut stderr);

                        let mut wildcard = false;
                        for pkesk in pkesks {
                            if let Some(r) = pkesk.recipient() {
                                let (userid, cert) = self.sq.best_userid_for(
                                    &r,
                                    &KeyFlags::transport_encryption()
                                        | &KeyFlags::storage_encryption(),
                                    true);
                                if let Ok(cert) = cert {
                                    emit_cert_key_handle_userid_str(
                                        &mut stderr,
                                        &cert.key_handle(),
                                        &userid.display().to_string())?;
                                } else {
                                    wwriteln!(stream = &mut stderr,
                                              initial_indent = " - ",
                                              "{}, certificate not found",
                                              r);
                                }

                                printed = true;
                            } else {
                                wildcard = true;
                            }
                        }

                        if wildcard {
                            printed = true;

                            wwriteln!(stream = &mut stderr,
                                      initial_indent = " - ",
                                      "unknown, anonymous recipients");
                        }
                        if ! printed {
                            wwriteln!(stream = &mut stderr,
                                      initial_indent = " - ",
                                      "passwords");
                        }
                        wwriteln!(stream = &mut stderr);
                    }
                    decrypt::output::DecryptionFailed::MalformedMessage(
                        decrypt::output::MalformedMessage {
                            error: e,
                            ..
                        }) =>
                    {
                        error = Some(Cow::Owned(e.to_string()));
                    }
                    _ => (),
                }

                if self.sq.config().verbose() {
                    wwriteln!(stream = &mut stderr,
                              "Note: Processing of message failed: {}",
                              if let Some(error) = error.as_ref() {
                                  &error
                              } else {
                                  "unable to decrypt message"
                              });
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
