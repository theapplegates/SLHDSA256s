use std::path::PathBuf;

use sequoia::types::FileOrStdin;
use sequoia::types::import_stats::ImportStats;

use crate::cli;
use crate::Sq;
use crate::Result;

pub fn import(sq: Sq, command: cli::key::import::Command)
    -> Result<()>
{
    let o = &mut std::io::stdout();
    let mut stats: ImportStats = Default::default();

    let inputs = if command.input.is_empty() {
        vec![ PathBuf::from("-") ]
    } else {
        command.input
    };

    let mut result = Ok(());
    for file in inputs {
        let input = FileOrStdin::from(file.clone());
        let input = input.open("OpenPGP keys")?;

        result = sequoia::key::import::import(
            o, &sq.sequoia, input, Some(file.as_path()), &mut stats);
        if result.is_err() {
            break;
        }
    }

    stats.print_summary(o, &sq.sequoia)?;

    result
}
