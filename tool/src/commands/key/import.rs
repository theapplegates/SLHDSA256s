use std::path::PathBuf;

use sequoia::types::FileOrStdin;
use sequoia::types::import_stats::ImportStats;

use crate::cli;
use crate::Sq;
use crate::Result;
use crate::output::key::import::Stream;

pub fn import(sq: Sq, command: cli::key::import::Command)
    -> Result<()>
{
    let inputs = if command.input.is_empty() {
        vec![ PathBuf::from("-") ]
    } else {
        command.input
    };

    let mut output = std::io::stdout();

    let mut stats = ImportStats::default();

    let mut result = Ok(());
    for file in inputs {
        let input = FileOrStdin::from(file.clone());
        let input = input.open("OpenPGP keys")?;

        let mut stream = Stream::new(
            &sq, Some(file.as_path()), &mut output, false);

        let r = sq.sequoia.key_import().import_keyring(input, &mut stream);

        if let Some(s) = stream.stats {
            stats += s;
        }

        // Save the first error.
        if result.is_ok() && r.is_err() {
            result = r;
        }
    }

    stats.print_summary(&mut output, &sq.sequoia)?;

    result
}
