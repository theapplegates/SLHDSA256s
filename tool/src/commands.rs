use clap::ArgMatches;

use sequoia::openpgp;
use openpgp::Result;

use crate::Sq;
use crate::cli::types::FileOrStdout;
use crate::cli::{SqCommand, SqSubcommands};

pub mod cert;
pub mod config;
pub mod decrypt;
pub mod download;
pub mod encrypt;
pub mod keyring;
pub mod sign;
pub mod inspect;
pub mod key;
pub mod network;
pub mod packet;
pub mod pki;
pub mod toc;
pub mod verify;
pub mod version;

/// Dispatches the top-level subcommand.
pub fn dispatch(sq: Sq, command: SqCommand, matches: &ArgMatches) -> Result<()>
{
    let matches = matches.subcommand().unwrap().1;
    match command.subcommand {
        SqSubcommands::Encrypt(mut command) => {
            command.profile_source = matches.value_source("profile");
            encrypt::dispatch(sq, command)
        },
        SqSubcommands::Decrypt(command) =>
            decrypt::dispatch(sq, command),
        SqSubcommands::Sign(command) =>
            sign::dispatch(sq, command),
        SqSubcommands::Verify(command) =>
            verify::dispatch(sq, command),
        SqSubcommands::Download(command) =>
            download::dispatch(sq, command),

        SqSubcommands::Inspect(command) =>
            inspect::dispatch(sq, command),

        SqSubcommands::Cert(command) =>
            cert::dispatch(sq, command),
        SqSubcommands::Key(command) =>
            key::dispatch(sq, command, matches),

        SqSubcommands::Pki(command) =>
            pki::dispatch(sq, command, matches),

        SqSubcommands::Network(command) =>
            network::dispatch(sq, command, matches),
        SqSubcommands::Keyring(command) =>
            keyring::dispatch(sq, command),
        SqSubcommands::Packet(command) =>
            packet::dispatch(sq, command),

        SqSubcommands::Config(command) =>
            config::dispatch(sq, command),

        SqSubcommands::Toc(command) =>
            toc::dispatch(sq, command),

        SqSubcommands::Version(command) =>
            version::dispatch(sq, command),
    }
}
