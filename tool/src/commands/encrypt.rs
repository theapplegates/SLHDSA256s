use sequoia::openpgp;
use openpgp::armor;

use sequoia::encrypt::encrypt;
use sequoia::types::TrustThreshold;

use crate::Result;
use crate::Sq;
use crate::cli;
use crate::common::password;
use crate::print_error_chain;

pub fn dispatch(sq: Sq, command: cli::encrypt::Command) -> Result<()> {
    tracer!(TRACE, "encrypt::dispatch");

    let (recipients, errors) = sq.resolve_certs(
        &command.recipients, TrustThreshold::Full)?;
    for error in errors.iter() {
        print_error_chain(error);
    }
    if ! errors.is_empty() {
        return Err(anyhow::anyhow!("Failed to resolve certificates"));
    }

    let output = command.output.create_pgp_safe(
        &sq,
        command.binary,
        armor::Kind::Message,
    )?;

    let signers =
        sq.resolve_certs_or_fail(&command.signers,
                                 TrustThreshold::Full)?;
    let signers = sq.get_signing_keys(&signers, None)?;

    let notations = command.signature_notations.parse()?;

    if signers.is_empty() && ! notations.is_empty() {
        return Err(anyhow::anyhow!("--signature-notation requires signers, \
                                    but none are given"));
    }

    // Profile.  XXX: Currently, this is not actionable.
    let _profile = sq.config().resolve_encrypt_profile(
        &command.profile, command.profile_source);

    let npasswords = command.recipients.with_passwords();

    let prompt = password::Prompt::npasswords(&sq, npasswords);

    encrypt(
        &sq.sequoia,
        sq.policy(),
        command.input,
        output,
        npasswords,
        command.recipients.with_password_files(),
        &recipients,
        signers,
        notations,
        command.mode,
        command.compression,
        Some(sq.time()),
        command.use_expired_subkey,
        command.set_metadata_filename,
        prompt,
    )?;

    Ok(())
}
