use std::path::PathBuf;

use sequoia::openpgp;
use openpgp::Result;

use sequoia::cert::import::import;

use crate::Sq;
use crate::cli::cert::import;
use crate::common::password;

pub fn dispatch(sq: Sq, cmd: import::Command) -> Result<()> {
    // We're going to save the input to the certificate store.
    // Make sure it is enabled.
    sq.cert_store_or_else()?;

    let inputs = if cmd.input.is_empty() {
        vec![ PathBuf::from("-") ]
    } else {
        cmd.input
    };

    // Then, try to decrypt the message, and look for gossip headers.
    let prompt = password::Prompt::new(&sq, true);

    import(&sq.sequoia, inputs, prompt)?;

    Ok(())
}
