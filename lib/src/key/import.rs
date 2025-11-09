use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;
use openpgp::Cert;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use crate::Result;
use crate::Sequoia;
use crate::types::import_stats::ImportStats;
use crate::types::import_stats::ImportStatus;

pub fn import<I>(o: &mut dyn std::io::Write,
                 sequoia: &Sequoia,
                 input: I,
                 filename: Option<&Path>,
                 stats: &mut ImportStats)
    -> Result<()>
where
    I: std::io::Read + Send + Sync,
{
    // Return the first error.
    let mut ret = Ok(());

    let filename = filename
        .map(|filename| Cow::Owned(filename.display().to_string()))
        .unwrap_or_else(|| Cow::Borrowed("input"));

    for r in CertParser::from_reader(input)? {
        let cert = match r {
            Ok(cert) => cert,
            Err(err) => {
                wwriteln!(o, "Error reading {}: {}", filename, err);
                if ret.is_ok() {
                    ret = Err(err);
                }
                continue;
            }
        };

        let fp = cert.fingerprint();
        let id = format!("{} {}",
                         cert.fingerprint(),
                         sequoia.best_userid(&cert, true).display());

        let cert_is_tsk = cert.is_tsk();
        match import_key(sequoia, cert, stats) {
            Ok((key, cert)) => {
                wwriteln!(o, "Imported {} from {}: {}",
                          id, filename,
                          if key == cert {
                              key.to_string()
                          } else {
                              format!("key {}, cert {}", key, cert)
                          });

                sequoia.hint(format_args!("If this is your key, you should  \
                                      mark it as a fully trusted \
                                      introducer:"))
                    .sq().arg("pki").arg("link").arg("authorize")
                    .arg("--unconstrained")
                    .arg_value("--cert", &fp)
                    .arg("--all")
                    .done();

                sequoia.hint(format_args!("Otherwise, consider marking it as \
                                      authenticated:"))
                    .sq().arg("pki").arg("link").arg("add")
                    .arg_value("--cert", &fp)
                    .arg("--all")
                    .done();
            }

            Err(err) => {
                wwriteln!(o, "Error importing {} from {}: {}",
                          id, filename, err);

                if ! cert_is_tsk {
                    sequoia.hint(format_args!(
                        "To import certificates, do:"))
                        .sq().arg("cert").arg("import")
                        .arg(&filename)
                        .done();
                }

                if ret.is_ok() {
                    ret = Err(err);
                }
            }
        }
    }

    ret
}

fn import_key(sequoia: &Sequoia, cert: Cert, stats: &mut ImportStats)
              -> Result<(ImportStatus, ImportStatus)>
{
    if ! cert.is_tsk() {
        return Err(anyhow::anyhow!(
            "Nothing to import: certificate does not contain \
             any secret key material"));
    }

    let keystore = sequoia.key_store_or_else()?;
    let mut keystore = keystore.lock().unwrap();

    let mut softkeys = None;
    for mut backend in keystore.backends()?.into_iter() {
        if backend.id()? == "softkeys" {
            softkeys = Some(backend);
            break;
        }
    }

    drop(keystore);

    let mut softkeys = if let Some(softkeys) = softkeys {
        softkeys
    } else {
        return Err(anyhow::anyhow!("softkeys backend is not configured."));
    };

    let mut key_import_status = ImportStatus::Unchanged;
    for (s, key) in softkeys.import(&cert)
        .map_err(|e| {
            stats.keys.errors += 1;
            e
        })?
    {
        sequoia.info(format_args!(
            "Importing {} into key store: {:?}",
            key.fingerprint(), s));

        key_import_status = key_import_status.max(s.into());
    }

    match key_import_status {
        ImportStatus::New => stats.keys.new += 1,
        ImportStatus::Unchanged => stats.keys.unchanged += 1,
        ImportStatus::Updated => stats.keys.updated += 1,
    }

    // Also insert the certificate into the certificate store.
    // If we can't, we don't fail.  This allows, in
    // particular, `sq --cert-store=none key import` to work.
    let cert = cert.strip_secret_key_material();
    let fpr = cert.fingerprint();
    let mut cert_import_status = ImportStatus::Unchanged;
    match sequoia.cert_store_or_else() {
        Ok(cert_store) => {
            let new_certs = stats.certs.new_certs();
            let updated_certs = stats.certs.updated_certs();

            if let Err(err) = cert_store.update_by(
                Arc::new(LazyCert::from(cert)), stats)
            {
                sequoia.info(format_args!(
                    "While importing {} into cert store: {}",
                    fpr, err));
            }

            if stats.certs.new_certs() > new_certs {
                cert_import_status = ImportStatus::New;
            } else if stats.certs.updated_certs() > updated_certs {
                cert_import_status = ImportStatus::Updated;
            }
        }
        Err(err) => {
            sequoia.info(format_args!(
                "Not importing {} into cert store: {}",
                fpr, err));
        }
    }

    Ok((key_import_status, cert_import_status))
}
