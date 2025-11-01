//! Functionality for importing certificates.

use std::sync::Arc;
use std::path::PathBuf;

use anyhow::Context;

use sequoia_openpgp::parse::buffered_reader::BufferedReader;
use sequoia_openpgp::parse::buffered_reader::Dup;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::raw::RawCertParser;
use openpgp::packet::UserID;
use openpgp::parse::Cookie;
use openpgp::parse::PacketParser;
use openpgp::parse::PacketParserResult;
use openpgp::parse::Parse;
use openpgp::parse::stream::DecryptorBuilder;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use sequoia_autocrypt as autocrypt;

use crate::Sequoia;
use crate::prompt;
use crate::provenance::certify_downloads;
use crate::transitional::output::cert::emit_cert;
use crate::types::FileOrStdin;
use crate::types::import_stats::ImportStats;

pub fn import<P>(sequoia: &Sequoia, inputs: Vec<PathBuf>,
                 prompt: P)
    -> Result<()>
where
    P: prompt::Prompt,
{
    let mut stats = ImportStats::default();

    let o = &mut std::io::stdout();

    let inner = || -> Result<()> {
        for input in inputs.into_iter() {
            let input = FileOrStdin::from(input);
            let mut input_reader = input.open("OpenPGP certificates")?;

            if input_reader.eof() {
                // Empty file.  Silently skip it.
                continue;
            }

            enum Type {
                Signature,
                Keyring,
                Other,
            }

            // See if it is OpenPGP data.
            let dup = Dup::with_cookie(&mut input_reader, Cookie::default());
            let mut typ = Type::Other;
            if let Ok(ppr) = PacketParser::from_buffered_reader(dup) {
                // See if it is a keyring, or a bare revocation
                // certificate.
                if let PacketParserResult::Some(ref pp) = ppr {
                    if let Packet::Signature(sig) = &pp.packet {
                        typ = match sig.typ() {
                            SignatureType::KeyRevocation |
                            SignatureType::SubkeyRevocation |
                            SignatureType::CertificationRevocation =>
                            // Looks like a bare revocation.
                                Type::Signature,
                            _ => Type::Other,
                        };
                    } else if pp.possible_keyring().is_ok() {
                        typ = Type::Keyring;
                    } else {
                        // If we have a message, then it might
                        // actually be an email with autocrypt data.
                    }
                }
            }

            let result = match typ {
                Type::Signature => {
                    import_rev(
                        o, sequoia, &mut input_reader, &mut stats)
                }
                Type::Keyring => {
                    import_certs(
                        o, sequoia, &mut input_reader,
                        input.path(), &mut stats)
                }
                Type::Other => {
                    import_autocrypt(
                        sequoia, &mut input_reader, &mut stats, &prompt)
                }
            };

            if result.is_err() {
                if let Some(path) = input.path() {
                    result.with_context(|| {
                        format!("Reading {}", path.display())
                    })
                } else {
                    result
                }?;
            }
        }

        Ok(())
    };

    let result = inner();

    wwriteln!(o);
    stats.print_summary(o, sequoia)?;

    Ok(result?)
}

/// Imports the certs and reports on the individual certs.
pub fn import_and_report<F>(o: &mut dyn std::io::Write,
                            sequoia: &Sequoia,
                            certs: Vec<openpgp::Cert>,
                            source_path: Option<&PathBuf>,
                            stats: &mut ImportStats,
                            additional: F)
                            -> Result<()>
where
    F: Fn(&mut dyn std::io::Write, &openpgp::Cert)
          -> Result<()>,
{
    let cert_store = sequoia.cert_store_or_else()?;

    for cert in certs {
        emit_cert(o, sequoia, &cert)?;
        let cert = Arc::new(LazyCert::from(cert));
        if let Err(err) = cert_store.update_by(cert.clone(), stats) {
            wwriteln!(stream = o,
                      initial_indent = "   - ", "failed: {}", err);
            wwriteln!(o);
            stats.certs.inc_errors();
            continue;
        } else {
            wwriteln!(stream = o,
                      initial_indent = "   - ", "imported");
        }

        additional(o, cert.to_cert().expect("was a cert"))?;

        if cert.is_tsk() {
            let mut cmd = sequoia.hint(format_args!(
                "Certificate {} contains secret key material.  \
                 To import keys, do:", cert.fingerprint()))
                    .sq().arg("key").arg("import");

            if let Some(file) = source_path {
                cmd = cmd.arg(file.display());
            }

            cmd.done();
        }
    }

    wwriteln!(o);
    Ok(())
}

/// Imports certs encoded as OpenPGP keyring.
fn import_certs(o: &mut dyn std::io::Write,
                sequoia: &Sequoia,
                source: &mut Box<dyn BufferedReader<Cookie>>,
                source_path: Option<&PathBuf>,
                stats: &mut ImportStats)
    -> Result<()>
{
    let dup = Dup::with_cookie(source, Cookie::default());
    let raw_certs = RawCertParser::from_buffered_reader(dup)?;

    let mut one_ok = false;
    let mut errors = Vec::new();
    for raw_cert in raw_certs {
        let cert = match raw_cert
            .and_then(|raw| LazyCert::from(raw).to_cert().cloned())
        {
            Ok(cert) => {
                one_ok = true;
                cert
            },
            Err(err) => {
                errors.push(err);
                stats.certs.inc_errors();
                continue;
            }
        };

        import_and_report(o, sequoia, vec![cert], source_path, stats,
                          |_, _| Ok(()))?;
    }

    if ! one_ok {
        // This likely wasn't a keyring.
        errors.reverse();
        Err(errors.pop().ok_or_else(|| anyhow::anyhow!("no cert found"))?)
    } else {
        for err in errors {
            wwriteln!(o, "Error parsing input: {}", err);
        }
        Ok(())
    }
}

/// Import a bare revocation certificate.
fn import_rev(o: &mut dyn std::io::Write,
              sequoia: &Sequoia,
              source: &mut Box<dyn BufferedReader<Cookie>>,
              stats: &mut ImportStats)
              -> Result<()>
{
    let dup = Dup::with_cookie(source, Cookie::default());
    let cert_store = sequoia.cert_store_or_else()?;

    let ppr = PacketParser::from_buffered_reader(dup)?;
    let sig = if let PacketParserResult::Some(pp) = ppr {
        let (packet, next_ppr) = pp.next()?;

        let sig = if let Packet::Signature(sig) = packet {
            sig
        } else {
            return Err(anyhow::anyhow!(
                "Not a revocation certificate: got a {}.",
                packet.tag()));
        };

        if let PacketParserResult::Some(_) = next_ppr {
            return Err(anyhow::anyhow!(
                "Not a revocation certificate: \
                 got more than one packet."));
        }

        sig
    } else {
        return Err(anyhow::anyhow!(
            "Not a bare revocation certificate."));
    };

    if sig.typ() != SignatureType::KeyRevocation {
        return Err(anyhow::anyhow!(
            "Not a revocation certificate: got a {} signature.",
            sig.typ()));
    }

    let issuers = sig.get_issuers();
    let mut missing = Vec::new();
    let mut bad = Vec::new();
    for issuer in issuers.iter() {
        let certs = if let Ok(certs)
            = sequoia.lookup(std::iter::once(issuer), None, false, true)
        {
            certs
        } else {
            missing.push(issuer);
            continue;
        };

        for cert in certs.into_iter() {
            if let Ok(_) = sig.clone().verify_primary_key_revocation(
                cert.primary_key().key(),
                cert.primary_key().key())
            {
                let cert = cert.insert_packets(sig.clone())?.0;

                emit_cert(o, sequoia, &cert)?;
                if let Err(err) = cert_store.update_by(Arc::new(cert.into()),
                                                       stats)
                {
                    wwriteln!(stream = o, initial_indent = "   - ",
                              "error importing revocation certificate: {}",
                               err);
                    stats.certs.inc_errors();
                    continue;
                } else {
                    wwriteln!(stream = o, initial_indent = "   - ",
                              "imported revocation certificate");
                }

                return Ok(());
            } else {
                bad.push(issuer);
            }
        }
    }

    let search: Option<&KeyHandle> = if let Some(bad) = bad.first() {
        wwriteln!(o,
                  "Appears to be a revocation for {}, \
                   but the certificate is not available.",
                  bad);
        Some(bad)
    } else if ! missing.is_empty() {
        wwriteln!(o,
                  "Appears to be a revocation for {}, \
                   but the certificate is not available.",
                  missing.iter()
                  .map(|issuer| issuer.to_string())
                  .collect::<Vec<_>>()
                  .join(" or "));
        Some(missing[0])
    } else {
        None
    };

    if let Some(search) = search {
        sequoia.hint(format_args!("{}", "To search for a certificate, try:"))
            .sq().arg("network").arg("search")
            .arg(search.to_string())
            .done();
    }

    Err(anyhow::anyhow!("Failed to import revocation certificate."))
}

/// Imports certs encoded as Autocrypt headers.
///
/// We also try to decrypt the message, and collect the gossip headers.
pub fn import_autocrypt<P>(sequoia: &Sequoia, source: &mut Box<dyn BufferedReader<Cookie>>,
                           stats: &mut ImportStats, prompt: P)
    -> Result<()>
where
    P: prompt::Prompt,
{
    let o = &mut std::io::stdout();
    let mut acc = Vec::new();

    // First, get the Autocrypt headers from the outside.
    let mut dup = Dup::with_cookie(&mut *source, Cookie::default());
    let ac = autocrypt::AutocryptHeaders::from_reader(&mut dup)?;
    let from = UserID::from(
        ac.from.as_ref().ok_or(anyhow::anyhow!("no From: header"))?
            .as_str());
    let from_addr = from.email()?.ok_or(
        anyhow::anyhow!("no email address in From: header"))?;

    use autocrypt::AutocryptHeaderType::*;
    let mut sender_cert = None;
    let mut provenance_recorded = false;
    for h in ac.headers.into_iter().filter(|h| h.header_type == Sender) {
        if let Some(addr) = h.attributes.iter()
            .find_map(|a| (&a.key == "addr"
                           && a.value.to_lowercase() == from_addr.to_lowercase())
                      .then(|| a.value.clone()))
        {
            if let Some(cert) = h.key {
                sender_cert = Some(cert.clone());

                if let Ok((ca, _)) = sequoia.certd_or_else()
                    .and_then(|certd| certd.shadow_ca_autocrypt())
                {
                    acc.append(&mut certify_downloads(
                        sequoia, false, ca,
                        vec![cert], Some(&addr[..]),
                        &prompt));
                    provenance_recorded = true;
                } else {
                    acc.push(cert);
                }
            }
        }
    }

    import_and_report(o, sequoia, acc, None, stats, |o, _| {
        if provenance_recorded {
            wwriteln!(stream = o, initial_indent = "   - ",
                      "provenance information recorded");
        }

        Ok(())
    })?;

    // If there is no Autocrypt header, don't bother looking for
    // gossip.
    let sender_cert = match sender_cert {
        Some(c) => c,
        None => return Ok(()),
    };

    use crate::decrypt::Helper;
    let mut helper = Helper::new(
        sequoia,
        1, // Require one trusted signature...
        Some(vec![sender_cert.clone()]), // ... from this cert.
        vec![], vec![], &prompt);
    helper.quiet(true);

    let policy = sequoia.policy().clone();
    let dup = Dup::with_cookie(source, Cookie::default());
    let mut decryptor = match DecryptorBuilder::from_buffered_reader(dup)?
        .with_policy(&policy, None, helper)
    {
        Ok(d) => d,
        Err(e) => {
            // The decryption failed, but we should still import the
            // Autocrypt header.
            if sequoia.config().verbose() {
                weprintln!("Note: Processing of message failed: {}", e);
            }

            return Ok(());
        },
    };

    let ac = autocrypt::AutocryptHeaders::from_reader(&mut decryptor)?;
    let helper = decryptor.into_helper();

    // We know there has been one good signature from the sender.  Now
    // check that the message was encrypted.  Note: it doesn't have to
    // be encrypted for the purpose of the certification, but
    // Autocrypt requires messages to be signed and encrypted.
    if helper.sym_algo.is_none() {
        if sequoia.config().verbose() {
            weprintln!("Note: Message is not encrypted, ignoring message");
        }

        return Ok(());
    }

    let mut acc = Vec::new();
    for h in ac.headers.into_iter().filter(|h| h.header_type == Gossip) {
        if let Some(_addr) = h.attributes.iter()
            .find_map(|a| (&a.key == "addr").then(|| a.value.clone()))
        {
            if let Some(cert) = h.key {
                acc.push(cert);
            }
        }
    }

    import_and_report(o, sequoia, acc, None, stats, |_, _| Ok(()))?;

    Ok(())
}
