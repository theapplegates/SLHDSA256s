use sequoia::cert_store::Store;

use sequoia::list;
use sequoia::list::required_trust_amount;
use sequoia::types::QueryKind;

use crate::Result;
use crate::Sq;
use crate::common::pki::output::ConciseHumanReadableOutputNetwork;
use crate::common::pki::output::OutputType;

/// The context in which authenticate is called.
///
/// This controls the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListContext {
    PKI,
    Download,
}

pub struct Stream<'a> {
    context: ListContext,
    network: ConciseHumanReadableOutputNetwork<'a>,
}

impl<'a> Stream<'a> {
    pub fn new(sq: &'a Sq,
               params: &list::Params,
               context: ListContext,
               show_paths: bool,
               output: &'a mut dyn std::io::Write)
        -> Self
    {
        let required_amount = required_trust_amount(
            params.trust_amount(), params.certification_network());

        let network = ConciseHumanReadableOutputNetwork::new(
            output, &sq, required_amount, show_paths);

        Self {
            context,
            network,
        }
    }
}

impl<'a> sequoia::list::Stream for Stream<'a> {
    fn output(&mut self,
              params: &list::Params,
              output: list::Output)
        -> Result<()>
    {
        use list::Output::*;

        make_qprintln!(params.sequoia().config().quiet());

        match output {
            StartOfBindings => (),
            Binding(list::Binding {
                fingerprint,
                userid,
                paths,
                aggregate_trust_amount,
                ..
            }) => {
                self.network.add_cert(&fingerprint)?;
                if let Some(userid) = userid {
                    self.network.add_paths(paths, &fingerprint, &userid,
                                           aggregate_trust_amount)?;
                }
            }
            EndOfBindings => self.network.finalize()?,

            Report(list::Report {
                missing_trust_roots,
                query_lints,
                matching_bindings,
                unsatisfied_queries,
                authenticated_bindings,
                unusable_bindings,
                unauthenticated_bindings: _,
                ..
            }) if self.context == ListContext::PKI => {
                if let Some((roots, missing)) = missing_trust_roots {
                    if ! params.gossip() {
                        let missing_count = missing.len();
                        for (fpr, err) in missing.into_iter() {
                            qprintln!("Looking up trust root ({}): {}.",
                                      fpr, err);
                        }
                        if roots.iter().count() == missing_count {
                            qprintln!("Warning: No trust roots found.");
                        }
                    }
                }

                for q in unsatisfied_queries.iter() {
                    if params.gossip() {
                        qprintln!("No valid bindings match {}.",
                                  q.argument.as_deref().unwrap_or("the query"))
                    } else {
                        qprintln!("No bindings matching {} could be \
                                   authenticated.",
                                  q.argument.as_deref().unwrap_or("the query"));
                    }
                }

                for (_query, lint) in query_lints.into_iter() {
                    qprintln!(initial_indent = "  - ",
                              "Warning: {}",
                              crate::one_line_error_chain(lint));
                }

                if matching_bindings == 0 {
                    // There are no matching bindings.

                    qprintln!("No valid bindings match the query.");

                    if params.queries().len() == 1 {
                        if let QueryKind::Pattern(pattern)
                            = &unsatisfied_queries[0].kind
                        {
                            // Tell the user about `sq network fetch`.
                            params.sequoia().hint(format_args!(
                                "Try searching public directories:"))
                                .sq().arg("network").arg("search")
                                .arg(pattern)
                                .done();
                        }
                    } else if params.sequoia().cert_store_or_else()?
                        .certs().next().is_none()
                    {
                        qprintln!("Warning: The certificate store does not \
                                   contain any certificates.");

                        let return_all = params.queries().iter()
                            .any(|q| matches!(q.kind, QueryKind::All));
                        if return_all {
                            params.sequoia().hint(format_args!(
                                "Consider creating a key for yourself:"))
                                .sq().arg("key").arg("generate")
                                .arg_value("--name", "your-name")
                                .arg_value("--email", "your-email-address")
                                .arg("--own-key")
                                .done();

                            params.sequoia().hint(format_args!(
                                "Consider importing other peoples' \
                                 certificates:"))
                                .sq().arg("cert").arg("import")
                                .arg("a-cert-file.pgp")
                                .done();

                            params.sequoia().hint(format_args!(
                                "Try searching public directories for other \
                                 peoples' certificates:"))
                                        .sq().arg("network").arg("search")
                                        .arg("some-mail-address")
                                        .done();
                        }
                    }
                } else if params.gossip() {
                    // We are in gossip mode.  Mention `sq pki link`
                    // as a way to mark bindings as authenticated.
                    if authenticated_bindings > 0 {
                        qprintln!("After checking that a user ID really \
                                   belongs to a certificate, use \
                                   `sq pki link add` to mark the binding as \
                                   authenticated, or use \
                                   `sq network search FINGERPRINT|EMAIL` to \
                                   look for new certifications.");
                    } else {
                        qprintln!("No bindings are valid.");
                    }
                }

                if matching_bindings - authenticated_bindings > 0 {
                    // Some of the matching bindings were not shown.  Tell the
                    // user about the `--gossip` option.
                    assert!(matching_bindings > 0);
                    let bindings_not_authenticated
                        = matching_bindings - authenticated_bindings - unusable_bindings;

                    if matching_bindings == 1 {
                        qprintln!("1 binding found.");
                    } else {
                        qprintln!("{} bindings found.", matching_bindings);
                    }

                    if unusable_bindings == 1 {
                        qprintln!("Skipped 1 binding, which is unusable.");
                    } else if unusable_bindings > 1 {
                        qprintln!("Skipped {} bindings, which are unusable.",
                                  unusable_bindings);
                    }

                    if bindings_not_authenticated == 1 {
                        qprintln!("Skipped 1 binding, which could not be authenticated.");
                        qprintln!("Pass `--gossip` to see the unauthenticated binding.");
                    } else if bindings_not_authenticated > 1 {
                        qprintln!("Skipped {} bindings, which could not be authenticated.",
                                  bindings_not_authenticated);
                        qprintln!("Pass `--gossip` to see the unauthenticated bindings.");
                    }
                }
            }

            // Unknown.  Ignore.
            _ => (),
        }

        Ok(())
    }
}

