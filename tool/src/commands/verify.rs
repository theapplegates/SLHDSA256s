use sequoia::types::TrustThreshold;

use crate::Sq;
use crate::Result;
use crate::cli;

pub fn dispatch(sq: Sq, command: cli::verify::Command)
    -> Result<()>
{
    tracer!(TRACE, "verify::dispatch");

    let input = command.input.open("a signed message")?;
    let mut output = command.output.create_safe(&sq)?;
    let signatures = command.signatures;

    let signers =
        sq.resolve_certs_or_fail(&command.signers, TrustThreshold::Full)?;

    let result = sq.sequoia.verify(input,
                                   command.detached.clone(),
                                   "--signature-file",
                                   command.detached,
                                   &mut output, signatures, signers);
    if result.is_err() {
        if let Some(path) = command.output.path() {
            // Drop output here so that the file is persisted and
            // can be deleted.
            drop(output);

            if let Err(err) = std::fs::remove_file(path) {
                weprintln!("Verification failed, failed to remove \
                            unverified output saved to {}: {}",
                           path.display(), err);
            }
        }
    }
    result
}
