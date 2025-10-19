use anyhow::Context;

use sequoia::types::TrustThreshold;

use crate::Result;
use crate::Sq;
use crate::cli;
use crate::common::password;
use crate::print_error_chain;
use crate::output::encrypt::Stream;

pub fn dispatch(sq: Sq, command: cli::encrypt::Command) -> Result<()> {
    tracer!(TRACE, "encrypt::dispatch");

    make_qprintln!(sq.sequoia.config().quiet());

    let (recipients, errors) = sq.resolve_certs(
        &command.recipients, TrustThreshold::Full)?;
    for error in errors.iter() {
        print_error_chain(error);
    }
    if ! errors.is_empty() {
        return Err(anyhow::anyhow!("Failed to resolve certificates"));
    }

    let output = command.output.create_safe(&sq)?;

    let signers =
        sq.resolve_certs_or_fail(&command.signers,
                                 TrustThreshold::Full)?;

    let notations = command.signature_notations.parse()?;

    if signers.is_empty() && ! notations.is_empty() {
        return Err(anyhow::anyhow!("--signature-notation requires signers, \
                                    but none are given"));
    }

    // Profile.  XXX: Currently, this is not actionable.
    let _profile = sq.config().resolve_encrypt_profile(
        &command.profile, command.profile_source);

    let mut passwords = Vec::new();
    for password_file in command.recipients.with_password_files() {
        let password = std::fs::read(&password_file)
            .with_context(|| {
                format!("Reading {}", password_file.display())
            })?;
        passwords.push(password.into());
    }

    let npasswords = command.recipients.with_passwords();

    let prompt = password::Prompt::npasswords(&sq, npasswords);

    qprintln!("Composing a message...");

    let stream = Stream::new(&sq);

    sq.sequoia.encrypt()
        .add_signers(signers.into_iter())
        .add_notations(notations.into_iter())
        .prompt_for_passwords(npasswords)
        .add_passwords(passwords.into_iter())
        .add_recipients(recipients.into_iter())
        .encryption_purpose(command.mode)
        .compression_mode(command.compression)
        .use_expired_encryption_keys(command.use_expired_subkey)
        .ascii_armor(! command.binary)
        .unsafe_filename(
            command.set_metadata_filename
                .as_ref()
                .map(|f| f.as_bytes())
                .unwrap_or(b""))?
        .encrypt(command.input.open("data to encrypt")?,
                 output,
                 prompt,
                 stream)?;

    Ok(())
}
