use clap::ArgMatches;

use sequoia_openpgp as openpgp;
use openpgp::{Cert, Result};
use openpgp::packet::prelude::*;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;

use crate::Sq;

use crate::cli::encrypt::CompressionMode;
use crate::cli::types::FileOrStdout;
use crate::cli::types::MyAsRef;
use crate::cli::{SqCommand, SqSubcommands};

pub mod autocrypt;
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

/// Returns the active certification, if any, for the specified bindings.
///
/// Note: if `n` User IDs are provided, then the returned vector has
/// `n` elements.
pub fn active_certification<U>(
    sq: &Sq,
    cert: &Cert, userids: impl Iterator<Item=U>,
    issuer: &Key<openpgp::packet::key::PublicParts,
                 openpgp::packet::key::UnspecifiedRole>)
    -> Vec<(U, Option<Signature>)>
where
    U: MyAsRef<UserID>
{
    let issuer_kh = issuer.key_handle();

    userids.map(|userid_ref| {
        let userid = userid_ref.as_ref();

        let ua = match cert.userids()
            .filter(|ua| ua.userid() == userid).next()
        {
            Some(ua) => ua,
            None => return (userid_ref, None),
        };

        // Get certifications that:
        //
        //  - Have a creation time,
        //  - Are not younger than the reference time,
        //  - Are not expired,
        //  - Alias the issuer, and
        //  - Satisfy the policy.
        let mut certifications = ua.bundle().certifications()
            .filter(|sig| {
                if let Some(ct) = sig.signature_creation_time() {
                    ct <= sq.time()
                        && sig.signature_validity_period()
                        .map(|vp| {
                            sq.time() < ct + vp
                        })
                        .unwrap_or(true)
                        && sig.get_issuers().iter().any(|i| i.aliases(&issuer_kh))
                        && sq.policy().signature(
                            sig, HashAlgoSecurity::CollisionResistance).is_ok()
                } else {
                    false
                }
            })
            .collect::<Vec<&Signature>>();

        // Sort so the newest signature is first.
        certifications.sort_unstable_by(|a, b| {
            a.signature_creation_time().unwrap()
                .cmp(&b.signature_creation_time().unwrap())
                .reverse()
                .then(a.mpis().cmp(&b.mpis()))
        });

        // Return the first valid signature, which is the most recent one
        // that is no younger than sq.time().
        let pk = ua.cert().primary_key().key();
        let certification = certifications.into_iter()
            .filter_map(|sig| {
                let sig = sig.clone();
                if sig.verify_userid_binding(issuer, pk, userid).is_ok() {
                    Some(sig)
                } else {
                    None
                }
            })
            .next();
        (userid_ref, certification)
    }).collect()
}
