use sequoia::openpgp;
use openpgp::Result;

use sequoia::decrypt::decrypt;
use sequoia::types::TrustThreshold;

use crate::{
    Sq,
    cli,
    common::password,
    load_keys,
    output::verify::Stream,
    output::verify::VerifyContext,
};

pub fn dispatch(sq: Sq, command: cli::decrypt::Command) -> Result<()> {
    tracer!(TRACE, "decrypt::dispatch");

    let mut input = command.input.open("an encrypted message")?;
    let mut output = command.output.create_safe(&sq)?;

    let signers =
        sq.resolve_certs_or_fail(&command.signers, TrustThreshold::Full)?;

    // Fancy default for --signatures.  If you change this,
    // also change the description in the CLI definition.
    let signatures = command.signatures.unwrap_or_else(|| {
        if signers.is_empty() {
            // No certs are given for verification, use 0 as
            // threshold so we handle only-encrypted messages
            // gracefully.
            0
        } else {
            // At least one cert given, expect at least one
            // valid signature.
            1
        }
    });
    let secrets =
        load_keys(command.secret_key_file.iter())?;
    let session_keys = command.session_key;
    let prompt = password::Prompt::new(&sq, true);
    let verify_output = Stream::new(&sq, VerifyContext::Decrypt);
    let result = decrypt(&sq.sequoia, &mut input, &mut output,
                         signatures, signers, secrets,
                         command.dump_session_key,
                         session_keys,
                         sq.batch,
                         prompt,
                         verify_output);
    if result.is_err() {
        if let Some(path) = command.output.path() {
            // Drop output here so that the file is persisted and
            // can be deleted.
            drop(output);

            if let Err(err) = std::fs::remove_file(path) {
                weprintln!("Decryption failed, failed to remove \
                            output saved to {}: {}",
                           path.display(), err);
            }
        }
    }

    result
}
