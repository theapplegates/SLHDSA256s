use anyhow::Context;

use sequoia::openpgp;
use openpgp::{KeyHandle, Result};
use openpgp::serialize::Serialize;

use sequoia::inspect::inspect;
use sequoia::types::TrustThreshold;

use crate::Sq;

use crate::cli::inspect;
use crate::cli::types::FileOrStdout;

pub fn dispatch(sq: Sq, c: inspect::Command)
    -> Result<()>
{
    // sq inspect does not have --output, but commands::inspect does.
    // Work around this mismatch by always creating a stdout output.
    let output_type = FileOrStdout::default();
    let output = &mut output_type.create_unsafe(&sq)?;

    let print_certifications = c.certifications;

    let input = c.input;
    let dump_bad_signatures = c.dump_bad_signatures;

    let mut bytes: Vec<u8> = Vec::new();
    if c.certs.is_empty() {
        if let Some(path) = input.inner() {
            if ! path.exists() &&
                format!("{}", input).parse::<KeyHandle>().is_ok()
            {
                weprintln!("The file {} does not exist, \
                            did you mean \"sq inspect --cert {}\"?",
                           input, input);
            }
        }

        inspect(&sq.sequoia, input.open("OpenPGP or autocrypt data")?,
                Some(&input.to_string()), output,
                print_certifications, dump_bad_signatures)?;
    } else {
        for cert in sq.resolve_certs_or_fail(&c.certs, TrustThreshold::Full)? {
            // Include non-exportable signatures, etc.
            cert.serialize(&mut bytes).context("Serializing certificate")?;
        }

        let br = sequoia::openpgp::parse::buffered_reader::Memory::with_cookie(
            &bytes, sequoia::openpgp::parse::Cookie::default());
        inspect(&sq.sequoia, br, None, output,
                print_certifications, dump_bad_signatures)?;
    }

    Ok(())
}
