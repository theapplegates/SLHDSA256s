//! Operations on certs.

use sequoia::openpgp;
use openpgp::{
    Fingerprint,
    KeyHandle,
};

use sequoia::list::ListContext;
use sequoia::types::Query;
use sequoia::types::QueryKind;

use crate::{
    Result,
    Sq,
    cli::cert::{Command, list, Subcommands},
};

pub mod import;
pub mod export;
pub mod lint;

pub fn dispatch(sq: Sq, command: Command) -> Result<()>
{
    match command.subcommand {
        Subcommands::Import(command) =>
            import::dispatch(sq, command),

        Subcommands::Export(command) =>
            export::dispatch(sq, command),

        // List all authenticated bindings.
        Subcommands::List(list::Command {
            certs, pattern, gossip, unusable, certification_network,
            trust_amount, show_paths,
        }) => {
            let mut certs: Vec<Query> = certs.cert_query(true);

            if let Some(pattern) = pattern.as_ref() {
                let mut query_kind = None;
                if let Ok(kh) = pattern.parse::<KeyHandle>() {
                    if matches!(kh, KeyHandle::Fingerprint(Fingerprint::Unknown { .. })) {
                        let hex = pattern.chars()
                            .map(|c| {
                                if c == ' ' { 0 } else { 1 }
                            })
                            .sum::<usize>();

                        if hex >= 16 {
                            weprintln!("Warning: {} looks like a fingerprint or key ID, \
                                        but it is invalid.  Treating it as a text pattern.",
                                       pattern);
                        }
                    } else {
                        query_kind = Some(QueryKind::AuthenticatedCert(kh));
                    }
                };

                let query_kind = query_kind.unwrap_or_else(|| {
                    QueryKind::Pattern(pattern.clone())
                });
                certs.push(Query {
                    argument: Some(format!("{:?}", pattern)),
                    kind: query_kind,
                });
            }

            sq.sequoia.list_builder(certs)
                .context(ListContext::PKI)
                .gossip(*gossip)
                .unusable(*unusable)
                .certification_network(*certification_network)
                .trust_amount(*trust_amount)
                .show_paths(*show_paths)
                .execute(&mut std::io::stdout())
        },

        Subcommands::Lint(command) =>
            lint::lint(sq, command),
    }
}
