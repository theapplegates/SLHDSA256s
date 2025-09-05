use std::time::SystemTime;

use anyhow::Context as _;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::Policy;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;

use sequoia_cert_store as cert_store;
use cert_store::Store;
use cert_store::store::StoreError;
use cert_store::store::UserIDQueryParams;

use sequoia_wot as wot;
use wot::store::Store as _;

use crate::Sequoia;
use crate::transitional::print_error_chain;
use crate::types::FileStdinOrKeyHandle;
use crate::types::Safe;

impl Sequoia {
    /// Looks up an identifier.
    ///
    /// This matches on both the primary key and the subkeys.
    ///
    /// If `keyflags` is not `None`, then only returns certificates
    /// where the matching key has at least one of the specified key
    /// flags.  If `or_by_primary` is set, then certificates with the
    /// specified key handle and a subkey with the specified flags
    /// also match.
    ///
    /// If `allow_ambiguous` is true, then all matching certificates
    /// are returned.  Otherwise, if an identifier matches multiple
    /// certificates an error is returned.
    ///
    /// An error is also returned if any of the identifiers does not
    /// match at least one certificate.
    pub fn lookup<'a, I>(&self, handles: I,
                         keyflags: Option<KeyFlags>,
                         or_by_primary: bool,
                         allow_ambiguous: bool)
        -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Into<FileStdinOrKeyHandle>,
    {
        self.lookup_with_policy(
            handles, keyflags, or_by_primary, allow_ambiguous,
            self.policy(), self.time())
    }

    /// Looks up an identifier.
    ///
    /// Like [`Sequoia::lookup`], but uses an alternate policy and an
    /// alternate reference time.
    pub fn lookup_with_policy<'a, I>(&self, handles: I,
                                     keyflags: Option<KeyFlags>,
                                     or_by_primary: bool,
                                     allow_ambiguous: bool,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Into<FileStdinOrKeyHandle>,
    {
        let mut results = Vec::new();

        for handle in handles {
            let (kh, mut certs) = match handle.into() {
                FileStdinOrKeyHandle::FileOrStdin(file) => {
                    let br = file.open("an OpenPGP certificate")?;
                    let cert = Cert::from_buffered_reader(br)?;
                    (cert.key_handle(), vec![ cert ])
                }
                FileStdinOrKeyHandle::KeyHandle(kh) => {
                    let certs = self.cert_store_or_else()?
                        .lookup_by_cert_or_subkey(&kh)
                        .with_context(|| {
                            format!("Failed to load {} from certificate store", kh)
                        })?
                        .into_iter()
                        .filter_map(|cert| {
                            match cert.to_cert() {
                                Ok(cert) => Some(cert.clone()),
                                Err(err) => {
                                    let err = err.context(
                                        format!("Failed to parse {} as loaded \
                                                 from certificate store", kh));
                                    print_error_chain(&err);
                                    None
                                }
                            }
                        })
                        .collect::<Vec<Cert>>();

                    (kh.clone(), certs)
                }
            };

            if let Some(keyflags) = keyflags.as_ref() {
                certs.retain(|cert| {
                    let vc = match cert.with_policy(policy, time)
                    {
                        Ok(vc) => vc,
                        Err(err) => {
                            let err = err.context(
                                format!("{} is not valid according \
                                         to the current policy, ignoring",
                                        kh));
                            print_error_chain(&err);
                            return false;
                        }
                    };

                    let checked_id = or_by_primary
                        && vc.cert().key_handle().aliases(&kh);

                    for ka in vc.keys() {
                        if checked_id || ka.key().key_handle().aliases(&kh) {
                            if &ka.key_flags().unwrap_or(KeyFlags::empty())
                                & keyflags
                                != KeyFlags::empty()
                            {
                                return true;
                            }
                        }
                    }

                    if checked_id {
                        weprintln!("Error: {} does not have a key with \
                                    the required capabilities ({:?})",
                                   cert.keyid(), keyflags);
                    } else {
                        weprintln!("Error: The subkey {} (cert: {}) \
                                    does not have the required capabilities \
                                    ({:?})",
                                   kh, cert.keyid(), keyflags);
                    }
                    return false;
                })
            }

            if ! allow_ambiguous && certs.len() > 1 {
                return Err(anyhow::anyhow!(
                    "{} is ambiguous; it matches: {}",
                    kh,
                    certs.into_iter()
                        .map(|cert| cert.fingerprint().to_string())
                        .collect::<Vec<String>>()
                        .join(", ")));
            }

            if certs.len() == 0 {
                return Err(StoreError::NotFound(kh.clone()).into());
            }

            results.extend(certs);
        }

        Ok(results)
    }

    /// Looks up a certificate.
    ///
    /// Like [`Sequoia::lookup`], but looks up a certificate, which must be
    /// uniquely identified by `handle` and `keyflags`.
    pub fn lookup_one<H>(&self, handle: H,
                      keyflags: Option<KeyFlags>, or_by_primary: bool)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_one_with_policy(handle, keyflags, or_by_primary,
                                    self.policy(), self.time())
    }

    /// Looks up a certificate.
    ///
    /// Like [`Sequoia::lookup_one_with_policy`], but uses an alternate
    /// policy and an alternate reference time.
    pub fn lookup_one_with_policy<H>(&self, handle: H,
                                     keyflags: Option<KeyFlags>,
                                     or_by_primary: bool,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_with_policy(std::iter::once(handle.into()),
                                keyflags, or_by_primary, false,
                                policy, time)
            .map(|certs| {
                assert_eq!(certs.len(), 1);
                certs.into_iter().next().expect("have one")
            })
    }


    /// Looks up certificates by User ID or email address.
    ///
    /// This only returns certificates that can be authenticate for
    /// the specified User ID (or email address, if `email` is true).
    /// If no certificate can be authenticated for some User ID,
    /// returns an error.  If multiple certificates can be
    /// authenticated for a given User ID or email address, then
    /// returns them all.
    pub fn lookup_by_userid(&self, userid: &[String], email: bool)
        -> Result<Vec<Cert>>
    {
        if userid.is_empty() {
            return Ok(Vec::new())
        }

        let cert_store = self.cert_store_or_else()?;

        // Build a WoT network.

        let cert_store = wot::store::CertStore::from_store(
            cert_store, self.policy(), self.time());
        let n = wot::NetworkBuilder::rooted(&cert_store, &*self.trust_roots())
            .build();

        let mut results: Vec<Cert> = Vec::new();
        // We try hard to not just stop at the first error, but lint
        // the input so that the user gets as much feedback as
        // possible.  The first error that we encounter is saved here,
        // and returned.  The rest are printed directly.
        let mut error: Option<anyhow::Error> = None;

        // Iterate over each User ID address, find any certificates
        // associated with the User ID, validate the certificates, and
        // finally authenticate them for the User ID.
        for userid in userid.iter() {
            let matches: Vec<(Fingerprint, UserID)> = if email {
                if let Err(err) = UserIDQueryParams::is_email(userid) {
                    weprintln!("{:?} is not a valid email address", userid);
                    if error.is_none() {
                        error = Some(err);
                    }

                    continue;
                }

                // Get all certificates that are associated with the email
                // address.
                cert_store.lookup_synopses_by_email(userid)
            } else {
                let userid = UserID::from(&userid[..]);
                cert_store.lookup_synopses_by_userid(userid.clone())
                    .into_iter()
                    .map(|fpr| (fpr, userid.clone()))
                    .collect()
            };

            if matches.is_empty() {
                return Err(anyhow::anyhow!(
                    "No certificates are associated with {:?}",
                    userid));
            }

            struct Entry {
                fpr: Fingerprint,
                userid: UserID,
                cert: Result<Cert>,
            }
            let entries = matches.into_iter().map(|(fpr, userid)| {
                // We've got a match, or two, or three...  Lookup the certs.
                let cert = match cert_store.lookup_by_cert_fpr(&fpr) {
                    Ok(cert) => cert,
                    Err(err) => {
                        let err = err.context(format!(
                            "Error fetching {} ({})",
                            fpr, Safe(&userid)));
                        return Entry { fpr, userid, cert: Err(err), };
                    }
                };

                // Parse the LazyCerts.
                let cert = match cert.to_cert() {
                    Ok(cert) => cert.clone(),
                    Err(err) => {
                        let err = err.context(format!(
                            "Error parsing {} ({})",
                            fpr, Safe(&userid)));
                        return Entry { fpr, userid, cert: Err(err), };
                    }
                };

                // Check the certs for validity.
                let vc = match cert.with_policy(self.policy(), self.time()) {
                    Ok(vc) => vc,
                    Err(err) => {
                        let err = err.context(format!(
                            "Certificate {} ({}) is invalid",
                            fpr, Safe(&userid)));
                        return Entry { fpr, userid, cert: Err(err) };
                    }
                };

                if let Err(err) = vc.alive() {
                    let err = err.context(format!(
                        "Certificate {} ({}) is invalid",
                        fpr, Safe(&userid)));
                    return Entry { fpr, userid, cert: Err(err), };
                }

                if let RevocationStatus::Revoked(_) = vc.revocation_status() {
                    let err = anyhow::anyhow!(
                        "Certificate {} ({}) is revoked",
                        fpr, Safe(&userid));
                    return Entry { fpr, userid, cert: Err(err), };
                }

                if let Some(ua) = vc.userids().find(|ua| {
                    ua.userid() == &userid
                })
                {
                    if let RevocationStatus::Revoked(_) = ua.revocation_status() {
                        let err = anyhow::anyhow!(
                            "User ID {} on certificate {} is revoked",
                            Safe(&userid), fpr);
                        return Entry { fpr, userid, cert: Err(err), };
                    }
                }

                // Authenticate the bindings.
                let paths = n.authenticate(
                    &userid, cert.fingerprint(),
                    // XXX: Make this user configurable.
                    wot::FULLY_TRUSTED);
                let r = if paths.amount() < wot::FULLY_TRUSTED {
                    Err(anyhow::anyhow!(
                        "{}, {} cannot be authenticated at the \
                         required level ({} of {}).  After checking \
                         that {} really controls {}, you could certify \
                         their certificate by running \
                         `sq pki link add --cert {} --userid {:?}`.",
                        cert.fingerprint(),
                        Safe(&userid),
                        paths.amount(), wot::FULLY_TRUSTED,
                        Safe(&userid),
                        cert.fingerprint(),
                        cert.fingerprint(),
                        String::from_utf8_lossy(userid.value())))
                } else {
                    Ok(cert)
                };

                Entry { fpr, userid, cert: r, }
            });

            // Partition into good (successfully authenticated) and
            // bad (an error occurred).
            let (good, bad): (Vec<Entry>, _)
                = entries.partition(|entry| entry.cert.is_ok());

            if good.is_empty() {
                // We've only got errors.

                let err = if bad.is_empty() {
                    // We got nothing :/.
                    if email {
                        anyhow::anyhow!(
                            "No known certificates have the email address {}",
                            Safe(userid))
                    } else {
                        anyhow::anyhow!(
                            "No known certificates have the User ID {}",
                            Safe(userid))
                    }
                } else {
                    if email {
                        anyhow::anyhow!(
                            "None of the certificates with the email \
                             address {} can be authenticated using \
                             the configured trust model",
                            Safe(userid))
                    } else {
                        anyhow::anyhow!(
                            "None of the certificates with the User ID \
                             {} can be authenticated using \
                             the configured trust model",
                            Safe(userid))
                    }
                };

                weprintln!("{:?}:\n", err);
                if error.is_none() {
                    error = Some(err);
                }

                // Print the errors.
                for (i, Entry { fpr, userid, cert }) in bad.into_iter().enumerate() {
                    weprintln!("{}. When considering {} ({}):",
                               i + 1, fpr,
                               Safe(&userid));
                    let err = match cert {
                        Ok(_) => unreachable!(),
                        Err(err) => err,
                    };

                    print_error_chain(&err);
                }
            } else {
                // We have at least one authenticated certificate.
                // Silently ignore any errors.
                results.extend(
                    good.into_iter().filter_map(|Entry { cert, .. }| {
                        cert.ok()
                    }));
            }
        }

        if let Some(error) = error {
            Err(error)
        } else {
            Ok(results)
        }
    }
}
