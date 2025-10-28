use sequoia::cert;
use sequoia::sign;

use crate::Result;
use crate::Sq;
use crate::error_chain;

pub struct Stream<'a> {
    sq: &'a Sq,
}

impl<'a> Stream<'a> {
    pub fn new(sq: &'a Sq) -> Self {
        Self {
            sq,
        }
    }
}

impl sign::Stream for Stream<'_> {
    fn output(&mut self,
              _params: &sign::Params,
              output: sign::Output)
        -> Result<()>
    {
        make_qprintln!(self.sq.quiet());

        match output {
            sign::Output::SigningFailed(
                sign::output::SigningFailed {
                    unusable_certs,
                    ..
                }) =>
            {
                for unusable_cert in unusable_certs {
                    let cert::CertError {
                        cert,
                        problems,
                        ..
                    } = unusable_cert;

                    weprintln!("Cannot sign using {}, {}:",
                               cert.fingerprint(),
                               self.sq.best_userid(&cert, true).display());
                    for problem in problems {
                        for (i, err)
                            in error_chain(&anyhow::Error::from(problem))
                                .into_iter()
                                .enumerate()
                        {
                            if i == 0 {
                                weprintln!(initial_indent="  - ",
                                           "{}", err);
                            } else {
                                weprintln!(initial_indent="    ",
                                           "because: {}", err);
                            }
                        }
                    }
                }
            }

            sign::Output::Signing(
                sign::output::Signing {
                    signers,
                    ..
                }) =>
            {
                for (signer, _) in signers {
                    qprintln!();
                    qprintln!(initial_indent = " - ", "signed by {}",
                              self.sq.best_userid(&signer, true).display());
                    qprintln!(initial_indent = "   - ", "using {}",
                              signer.fingerprint());
                }

                // A newline to make it look nice.
                qprintln!();
            }

            sign::Output::Signed(
                sign::output::Signed {
                    ..
                }) =>
            {
            }

            _output => {
                // eprintln!("Unknown output: {:?}", output);
            }
        }

        Ok(())
    }
}
