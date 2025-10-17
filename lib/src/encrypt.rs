use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::crypto;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::policy::Policy;
use openpgp::serialize::stream::Compressor;
use openpgp::serialize::stream::Encryptor;
use openpgp::serialize::stream::LiteralWriter;
use openpgp::serialize::stream::Message;
use openpgp::serialize::stream::Signer;
use openpgp::serialize::stream::padding::Padder;
use openpgp::types::CompressionAlgorithm;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use crate::types::EncryptPurpose;
use crate::types::CompressionMode;
use crate::Result;
use crate::Sequoia;
use crate::config::Config;
use crate::prompt::Prompt;
use crate::prompt::check::CheckNewPassword;
use crate::prompt;
use crate::transitional::one_line_error_chain;
use crate::transitional::output::pluralize::Pluralize;
use crate::types::Convert;
use crate::types::FileOrStdin;

pub fn encrypt<'a, 'b: 'a, P>(
    sequoia: &Sequoia,
    policy: &'b dyn Policy,
    input: FileOrStdin,
    message: Message<'a>,
    npasswords: usize,
    password_files: &[PathBuf],
    recipients: &'b [openpgp::Cert],
    mut signers: Vec<(openpgp::Cert, Box<dyn crypto::Signer + Send + Sync>)>,
    notations: Vec<(bool, NotationData)>,
    mode: EncryptPurpose,
    compression: CompressionMode,
    time: Option<SystemTime>,
    use_expired_subkey: bool,
    set_metadata_filename: Option<String>,
    prompt: P,
)
    -> Result<()>
where
    P: Prompt
{
    make_qprintln!(sequoia.config().quiet());

    let mut passwords: Vec<crypto::Password> = Vec::with_capacity(npasswords);
    for _ in 0..npasswords {
        loop {
            let mut checker = CheckNewPassword::new();

            let mut context = prompt::ContextBuilder::password(
                prompt::Reason::EncryptMessage)
                .sequoia(sequoia)
                .build();

            match prompt.prompt(&mut context, &mut checker)? {
                prompt::Response::Password(password) => {
                    passwords.push(password);
                    break;
                }
                prompt::Response::NoPassword => {
                    weprintln!("You must enter a password.");
                    continue;
                }
            };
        }
    }

    for password_file in password_files {
        let password = std::fs::read(&password_file)
            .with_context(|| {
                format!("Reading {}", password_file.display())
            })?;
        passwords.push(password.into());
    }

    if recipients.len() + passwords.len() == 0 {
        return Err(anyhow::anyhow!(
            "Neither recipient nor password given"));
    }

    let mode = KeyFlags::from(mode);

    qprintln!("Composing a message...");

    // Track whether we have a secret for one of the encryption
    // subkeys.
    let mut have_one_secret = false;

    // Build a vector of recipients to hand to Encryptor.
    let mut recipient_subkeys = Vec::new();
    for cert in recipients.iter() {
        // XXX: In this block, instead of using sequoia.best_userid(&cert,
        // true), it'd be nice to use the cert designator that the
        // user used, instead or additionally.

        let mut encryption_keys = 0;
        let mut bad: Vec<String> = Vec::new();

        // This cert's subkeys we selected for encryption.
        let mut selected_keys = Vec::new();

        // As a fallback, we may consider expired keys.
        let mut expired_keys = Vec::new();

        if let RevocationStatus::Revoked(_)
            = cert.revocation_status(policy, time)
        {
            return Err(anyhow::anyhow!(
                "Can't encrypt to {}, {}: it is revoked",
                cert.fingerprint(),
                sequoia.best_userid(&cert, true).display()));
        }

        let vc = cert.with_policy(policy, time)
            .with_context(|| {
                format!("{}, {} is not valid according to the \
                         current policy",
                        cert.fingerprint(),
                        sequoia.best_userid(&cert, true).display())
            })?;

        for ka in vc.keys() {
            let fpr = ka.key().fingerprint();
            let ka = match ka.with_policy(policy, time) {
                Ok(ka) => ka,
                Err(err) => {
                    bad.push(format!("{} is not valid: {}",
                                     fpr,
                                     one_line_error_chain(err)));
                    continue;
                }
            };

            if let Some(key_flags) = ka.key_flags() {
                if (&key_flags & &mode).is_empty() {
                    // Not for encryption.
                    continue;
                }
            } else {
                // No key flags.  Not for encryption.
                continue;
            }
            encryption_keys += 1;

            if ! ka.key().pk_algo().is_supported() {
                bad.push(format!("{} uses {}, which is not supported",
                                 ka.key().fingerprint(),
                                 ka.key().pk_algo()));
                continue;
            }
            if let RevocationStatus::Revoked(_sigs) = ka.revocation_status() {
                bad.push(format!("{} is revoked", ka.key().fingerprint()));
                continue;
            }
            if let Err(err) = ka.alive() {
                if let Some(t) = ka.key_expiration_time() {
                    if t < sequoia.time() {
                        expired_keys.push((ka, t));
                        bad.push(format!("{} expired on {}",
                                         fpr, t.convert().to_string()));
                    } else {
                        bad.push(format!("{} is not alive: {}",
                                         fpr, err));
                    }
                } else {
                    bad.push(format!("{} is not alive: {}",
                                     fpr, err));
                }
                continue;
            }

            selected_keys.push(ka);
        }
        if selected_keys.is_empty() && use_expired_subkey
            && ! expired_keys.is_empty()
        {
            expired_keys.sort_by_key(|(_key, t)| *t);

            if let Some((key, _expiration_time)) = expired_keys.pop() {
                selected_keys.push(key);
            }
        }

        if selected_keys.is_empty() {
            // We didn't find any keys for this certificate.
            for ka in cert.keys() {
                let fpr = ka.key().fingerprint();
                if let Err(err) = ka.with_policy(policy, time) {
                    bad.push(format!("{} is not valid: {}",
                                     fpr,
                                     one_line_error_chain(err)));
                }
            }

            if ! bad.is_empty() {
                weprintln!("Cannot encrypt to {}, {}:",
                           cert.fingerprint(),
                           sequoia.best_userid(&cert, true).display());
                for message in bad.into_iter() {
                    weprintln!(initial_indent="  - ", "{}", message);
                }
            }
            if ! use_expired_subkey && ! expired_keys.is_empty() {
                sequoia.hint(format_args!(
                    "To use an expired key anyway, pass \
                     --use-expired-subkey"));
            }

            if encryption_keys > 0 {
                return Err(anyhow::anyhow!(
                    "Cert {}, {} has no suitable encryption key",
                    cert,
                    sequoia.best_userid(&cert, true).display()));
            } else {
                return Err(anyhow::anyhow!(
                    "Cert {}, {} has no encryption-capable keys",
                    cert,
                    sequoia.best_userid(&cert, true).display()));
            }
        } else {
            qprintln!();
            qprintln!(initial_indent = " - ", "encrypted for {}",
                      sequoia.best_userid(&cert, true).display());
            qprintln!(initial_indent = "   - ", "using {}",
                      cert.fingerprint());

            for ka in selected_keys {
                have_one_secret |= sequoia.have_secret_key(ka.amalgamation());
                recipient_subkeys.push(ka);
            }
        }
    }

    if ! passwords.is_empty() {
        qprintln!();
        qprintln!(initial_indent = " - ", "encrypted using {}",
                  passwords.len().of("password"));
    }

    if signers.is_empty() {
        sequoia.hint(format_args!(
            "The message will not be signed.  \
             While the message integrity will be protected \
             by the encryption, there will be no way for the \
             recipient to tell whether the message is \
             authentic.  Consider signing the message."));
    } else {
        for (signer, _) in &signers {
            qprintln!();
            qprintln!(initial_indent = " - ", "signed by {}",
                      sequoia.best_userid(signer, true).display());
            qprintln!(initial_indent = "   - ", "using {}",
                      signer.fingerprint());
        }
    }

    if ! have_one_secret && passwords.is_empty() && ! recipients.iter()
        .any(|c| sequoia.config().encrypt_for_self().contains(&c.fingerprint()))
    {
        if let Some(home) = sequoia.home() {
            sequoia.hint(format_args!(
                "It looks like you won't be able to decrypt the message.  \
                 Consider adding yourself as recipient, for example by \
                 adding your cert to `{}` in the configuration file ({}), \
                 and using the `--for-self` argument.",
                Config::encrypt_for_self_config_key(),
                crate::config::ConfigFile::file_name(home).display()));
        } else {
            sequoia.hint(format_args!(
                "It looks like you won't be able to decrypt the message.  \
                 Consider adding yourself as recipient."));
        }
    }

    // A newline to make it look nice.
    qprintln!();

    // We want to encrypt a literal data packet.
    let encryptor =
        Encryptor::for_recipients(message, recipient_subkeys)
        .add_passwords(passwords);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    match compression {
        CompressionMode::None => (),
        CompressionMode::Pad => sink = Padder::new(sink).build()?,
        CompressionMode::Zip => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?,
        CompressionMode::Zlib => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zlib).build()?,
        CompressionMode::Bzip2 => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::BZip2).build()?,
    }

    // Optionally sign message.
    if let Some(first) = signers.pop() {
        // Create a signature template.
        let mut builder = SignatureBuilder::new(SignatureType::Binary);
        for (critical, n) in notations.iter() {
            builder = builder.add_notation(
                n.name(),
                n.value(),
                Some(n.flags().clone()),
                *critical)?;
        }

        let mut signer = Signer::with_template(sink, first.1, builder)?;

        if let Some(time) = time {
            signer = signer.creation_time(time);
        }
        for s in signers {
            signer = signer.add_signer(s.1)?;
        }
        for r in recipients.iter() {
            signer = signer.add_intended_recipient(r);
        }
        sink = signer.build()?;
    }

    let literal_writer = LiteralWriter::new(sink)
        .filename(set_metadata_filename.unwrap_or_default())?;

    let mut writer_stack = literal_writer
        .build()
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    input.open("data to encrypt")?.copy(&mut writer_stack)
        .context("Failed to encrypt")?;

    writer_stack.finalize().context("Failed to encrypt")?;

    Ok(())
}
