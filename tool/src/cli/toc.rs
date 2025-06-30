//! Command-line parser for `sq toc`.

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(
    name = "toc",
    about = "Recursively list all commands",
    long_about =
        "Recursively list all commands

Recursively List all commands and show their short help.
",
)]
pub struct Command {
}
