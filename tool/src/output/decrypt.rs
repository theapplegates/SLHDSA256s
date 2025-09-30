use sequoia::openpgp;
use openpgp::fmt::hex;
use openpgp::types::KeyFlags;

use sequoia::cert_store as cert_store;
use cert_store::store::StoreError;

use sequoia::decrypt;
use sequoia::decrypt::output::Decryptor;
use sequoia::verify::Stream as _;

use crate::Result;
use crate::Sq;
use crate::common::ui::emit_cert;
use crate::output::verify::VerifyContext;
use crate::output::verify;

/// The context in which decrypt is called.
///
/// This controls the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptContext {
    /// sq decrypt
    Decrypt,
    /// sq packet decrypt
    PacketDecrypt,
}

impl From<DecryptContext> for VerifyContext {
    fn from(context: DecryptContext) -> VerifyContext {
        match context {
            DecryptContext::Decrypt => VerifyContext::Decrypt,
            DecryptContext::PacketDecrypt => VerifyContext::PacketDecrypt,
        }
    }
}

pub struct Stream<'a> {
    vstream: verify::Stream<'a>,
    context: DecryptContext,
    dump_session_key: bool,
}

impl<'a> Stream<'a> {
    pub fn new(sq: &'a Sq, context: DecryptContext,
               dump_session_key: bool,
    ) -> Self
    {
        Self {
            vstream: verify::Stream::new(sq, context.clone().into()),
            context,
            dump_session_key,
        }
    }
}

impl sequoia::verify::Stream for Stream<'_> {
    fn output(&mut self,
              params: &sequoia::verify::Params,
              output: sequoia::verify::Output)
        -> Result<()>
    {
        self.vstream.output(params, output)
    }
}

impl decrypt::Stream for Stream<'_> {
    fn output(&mut self,
              params: &decrypt::Params,
              output: decrypt::Output)
        -> Result<()>
    {
        let quiet = self.vstream.sq.quiet();
        make_qprintln!(quiet);

        match output {
            decrypt::Output::MessageStructure(structure) => {
                self.vstream.output(
                    params.verify_params(),
                    sequoia::verify::Output::MessageStructure(structure))?;
            }

            decrypt::Output::Report(decrypt::output::Report {
                verification,
                ..
            }) => {
                self.vstream.output(
                    params.verify_params(),
                    sequoia::verify::Output::Report(verification))?;
            }

            decrypt::Output::Info(info) => {
                eprintln!("{}", info);
            }

            decrypt::Output::Decrypted(decrypt::output::Decrypted {
                decryptor,
                session_key,
                ..
            }) => {
                match decryptor {
                    Decryptor::Cert(cert, _key) => {
                        if self.dump_session_key {
                            weprintln!("Session key: {}",
                                       hex::encode(&session_key));
                        }

                        if self.context != DecryptContext::PacketDecrypt {
                            qprintln!("Decrypted by {}, {}",
                                      cert.fingerprint(),
                                      self.vstream.sq.sequoia.best_userid(
                                          &cert, true).display());
                        }
                    }
                    Decryptor::Key(key) => {
                        if self.dump_session_key {
                            weprintln!("Session key: {}",
                                       hex::encode(&session_key));
                        }
                        if ! quiet && self.context != DecryptContext::PacketDecrypt {
                            if let Ok(cert) = self.vstream.sq.sequoia.lookup_one(
                                key.key_handle(), None, true)
                            {
                                qprintln!("Decrypted by {}, {}",
                                          cert.fingerprint(),
                                          self.vstream.sq.sequoia.best_userid(
                                              &cert, true).display());
                            } else {
                                qprintln!("Decrypted by {}, unknown",
                                          key.fingerprint());
                            }
                        }
                    }
                    Decryptor::SKESK(_skesk) => {
                        if self.dump_session_key {
                            weprintln!("Session key: {}",
                                       hex::encode(&session_key));
                        }
                    }
                    Decryptor::SessionKey(sk) => {
                        qprintln!("Encrypted with Session Key {}",
                                  sk.display_sensitive());
                    }
                    _ => (),
                }
            }
            decrypt::Output::DecryptionFailed(decrypt::output::DecryptionFailed {
                pkesks,
                skesks,
                ..
            }) => {
                // Only show a diagnostic hint if we have no SKESKs.
                if ! skesks.is_empty() {
                    return Ok(());
                }

                weprintln!("No key to decrypt message.  The message appears \
                            to be encrypted to:");
                weprintln!();

                for recipient in pkesks.iter().map(|p| p.recipient()) {
                    if let Some(r) = recipient {
                        let certs = self.vstream.sq.sequoia.lookup(
                            std::iter::once(&r),
                            Some(KeyFlags::empty()
                                 .set_storage_encryption()
                                 .set_transport_encryption()),
                            false,
                            true);

                        match certs {
                            Ok(certs) => {
                                for cert in certs {
                                    emit_cert(&mut std::io::stderr(),
                                              &self.vstream.sq, &cert)?;
                                }
                            }
                            Err(err) => {
                                if let Some(StoreError::NotFound(_))
                                    = err.downcast_ref()
                                {
                                    weprintln!(initial_indent = " - ",
                                               "{}, certificate not found", r);
                                } else {
                                    weprintln!(initial_indent = " - ",
                                               "{}, error looking up certificate: {}",
                                               r, err);
                                }
                            }
                        }
                    } else {
                        weprintln!(initial_indent = " - ",
                                   "anonymous recipient, certificate not found");
                    }
                }

                weprintln!();
            }

            _output => {
                // eprintln!("Unknown output: {:?}", output);
            }
        }

        Ok(())
    }
}
