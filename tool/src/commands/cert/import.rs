use anyhow::Context;

use std::path::PathBuf;

use sequoia::openpgp;
use openpgp::Result;

use sequoia::types::import_stats::ImportStats;

use crate::Sq;
use crate::cli::cert::import;
use crate::common::password;
use crate::output::cert::import::Stream;

pub fn dispatch(sq: Sq, cmd: import::Command) -> Result<()> {
    // We're going to save the input to the certificate store.
    // Make sure it is enabled.
    sq.cert_store_or_else()?;

    let stdin_path = PathBuf::from("-");

    let inputs = if cmd.input.is_empty() {
        vec![ stdin_path.clone() ]
    } else {
        cmd.input
    };

    // Then, try to decrypt the message, and look for gossip headers.
    let prompt = password::Prompt::new(&sq, true);

    let importer = sq.sequoia.cert_import();

    let mut stats = ImportStats::default();

    let mut stdout = std::io::stdout();

    let inner = || {
        for input_path in inputs {
            let mut stream = Stream::new(
                &sq, Some(&input_path), &mut stdout, false);

            if input_path == stdin_path {
                importer.import(std::io::stdin(), &prompt, &mut stream)?;
            } else {
                let input = std::fs::File::open(&input_path)
                    .with_context(|| {
                        format!("Failed to open {}", input_path.display())
                    })?;

                importer.import(input, &prompt, &mut stream)
                    .with_context(|| {
                        format!("Reading {}", input_path.display())
                    })?;
            }

            if let Some(s) = stream.stats {
                stats += s;
            }
        }

        Ok(())
    };

    let result = inner();

    println!();
    stats.print_summary(&mut stdout, &sq.sequoia)?;

    result
}
