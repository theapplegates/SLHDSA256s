//! Recursively list commands.

use clap::Command;

use crate::{
    Sq,
    Result,
    cli,
    cli::toc,
};

pub fn dispatch(_sq: Sq, _c: toc::Command)
                -> Result<()>
{
    fn list(output: &mut Vec<(String, String)>,
            path: &[&str], command: &Command) {
        if path.len() == 2 && path.get(1) == Some(&"help") {
            // Skip "binary help".
            return;
        }

        let mut path = path.to_vec();
        path.push(command.get_name());

        if command.has_subcommands() {
            for sc in command.get_subcommands() {
                list(output, &path[..], sc);
            }
        } else {
            output.push(
                (path.to_vec().join(" "),
                 command.get_about().expect("have about")
                 .ansi().to_string()));
        }
    }

    let mut cli = cli::build(false);
    cli.build();

    let mut output = Vec::with_capacity(128);
    list(&mut output, &[], &cli);

    let width = output.iter()
        .map(|(command, _about)| command.chars().count())
        .max()
        .unwrap_or(0);
    for (command, about) in output.into_iter() {
        println!("{:width$} {}", command, about, width=width);
    }

    Ok(())
}
