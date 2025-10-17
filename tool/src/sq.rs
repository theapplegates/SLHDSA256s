use std::borrow::Borrow;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use typenum::Unsigned;

use anyhow::anyhow;
use anyhow::Context as _;

use sequoia::config::Config;
use sequoia::config::ConfigFile;

use sequoia::openpgp;
use openpgp::Cert;
use openpgp::crypto;
use openpgp::crypto::Password;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::key::PublicParts;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;
use openpgp::policy::NullPolicy;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;
use openpgp::types::RevocationType;

use sequoia::cert_store;
use cert_store::LazyCert;
use cert_store::Store;
use cert_store::store::MergePublicCollectStats;
use cert_store::store::StoreUpdate;

use sequoia::wot;

use sequoia::key_store as keystore;
use keystore::Protection;

use sequoia::Sequoia;
use sequoia::prompt;
use sequoia::prompt::Prompt as _;
use sequoia::types::FileStdinOrKeyHandle;
use sequoia::types::PreferredUserID;
use sequoia::types::TrustThreshold;

use crate::cli::types::CertDesignators;
use crate::cli::types::KeyDesignators;
use crate::cli::types::SpecialName;
use crate::cli::types::StdinWarning;
use crate::cli::types::cert_designator;
use crate::cli::types::key_designator;
use crate::common::password::CheckRemoteKey;
use crate::common::password;
use crate::common::ui;
use crate::output::hint::Hint;
use crate::output::import::{ImportStats, ImportStatus};
use crate::print_error_chain;

const TRACE: bool = false;

pub static NULL_POLICY: NullPolicy = unsafe { NullPolicy::new() };

/// Flags for Sq::get_keys and related functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetKeysOptions {
    /// Don't ignore keys that are not alive.
    AllowNotAlive,
    /// Don't ignore keys that are not revoke.
    AllowRevoked,
    /// Use the NULL Policy.
    NullPolicy,
}

/// Flag for Sq::get_keys and related function.
enum KeyType {
    /// Only consider primary key.
    Primary,
    /// Only consider keys that have at least one of the specified
    /// capabilities.
    KeyFlags(KeyFlags),
}

// A shorthand for our store type.
type WotStore
    = wot::store::CertStore<'static, 'static, cert_store::CertStore<'static>>;

pub struct Sq {
    pub sequoia: Sequoia,

    /// Overwrite existing files.
    pub overwrite: bool,

    /// Prevent any kind of interactive prompting.
    pub batch: bool,
}

impl Sq {
    /// Returns the policy.
    pub fn policy(&self) -> &StandardPolicy<'static> {
        self.sequoia.policy()
    }

    /// Returns the current time.
    pub fn time(&self) -> SystemTime {
        self.sequoia.time()
    }

    /// Returns whether the time approximates the current time.
    pub fn time_is_now(&self) -> bool {
        self.sequoia.time_is_now()
    }

    /// Returns the configuration.
    pub fn config(&self) -> &Config {
        self.sequoia.config()
    }

    /// Returns the configuration file.
    pub fn config_file(&self) -> &ConfigFile {
        self.sequoia.config_file()
    }

    /// Be verbose.
    pub fn verbose(&self) -> bool {
        self.config().verbose()
    }

    /// Be quiet.
    pub fn quiet(&self) -> bool {
        self.config().quiet()
    }

    /// Returns the cert store's base directory, if it is enabled.
    pub fn cert_store_base(&self) -> Option<PathBuf> {
        self.sequoia.cert_store_base()
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn cert_store(&self) -> Result<Option<&WotStore>> {
        self.sequoia.cert_store()
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns an error.
    pub fn cert_store_or_else<'s>(&'s self) -> Result<&'s WotStore> {
        self.sequoia.cert_store_or_else()
    }

    /// Returns a reference to the underlying certificate directory,
    /// if it is configured.
    ///
    /// If the cert direcgory is disabled, returns an error.
    pub fn certd_or_else(&self)
        -> Result<&cert_store::store::certd::CertD<'static>>
    {
        self.sequoia.certd_or_else()
    }

    /// Returns a web-of-trust query builder.
    ///
    /// The trust roots are already set appropriately.
    pub fn wot_query(&self)
        -> Result<wot::NetworkBuilder<&WotStore>>
    {
        self.sequoia.wot_query()
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns `Ok(None)`.
    pub fn key_store_path(&self) -> Result<Option<PathBuf>> {
        self.sequoia.key_store_path()
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_path_or_else(&self) -> Result<PathBuf> {
        self.sequoia.key_store_path_or_else()
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn key_store(&self) -> Result<Option<&Mutex<keystore::Keystore>>> {
        self.sequoia.key_store()
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_or_else(&self) -> Result<&Mutex<keystore::Keystore>> {
        self.sequoia.key_store_or_else()
    }

    /// Returns the secret keys found in any specified keyrings.
    pub fn keyring_tsks(&self)
        -> Result<&BTreeMap<Fingerprint,
                            (Fingerprint, Key<key::PublicParts, key::UnspecifiedRole>)>>
    {
        self.sequoia.keyring_tsks()
    }


    pub fn lookup<'a, I>(&self, handles: I,
                         keyflags: Option<KeyFlags>,
                         or_by_primary: bool,
                         allow_ambiguous: bool)
        -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Into<FileStdinOrKeyHandle>,
    {
        self.sequoia.lookup(handles, keyflags, or_by_primary, allow_ambiguous)
    }

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
        self.sequoia.lookup_with_policy(handles, keyflags, or_by_primary,
                                        allow_ambiguous, policy, time)
    }

    pub fn lookup_one<H>(&self, handle: H,
                         keyflags: Option<KeyFlags>, or_by_primary: bool)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.sequoia.lookup_one(handle, keyflags, or_by_primary)
    }

    pub fn lookup_one_with_policy<H>(&self, handle: H,
                                     keyflags: Option<KeyFlags>,
                                     or_by_primary: bool,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.sequoia.lookup_one_with_policy(
            handle, keyflags, or_by_primary, policy, time)
    }

    pub fn lookup_by_userid(&self, userid: &[String], email: bool)
        -> Result<Vec<Cert>>
    {
        self.sequoia.lookup_by_userid(userid, email)
    }

    /// Returns the local trust root, creating it if necessary.
    pub fn local_trust_root(&self) -> Result<Arc<LazyCert<'static>>> {
        self.sequoia.local_trust_root()
    }

    /// Returns the trust roots, including the cert store's trust
    /// root, if any.
    pub fn trust_roots(&self) -> Vec<Fingerprint> {
        self.sequoia.trust_roots()
    }

    /// Imports the TSK into the soft key backend.
    ///
    /// On success, returns whether the key was imported, updated, or
    /// unchanged and whether the cert was imported, updated, or
    /// unchanged.
    pub fn import_key(&self, cert: Cert, stats: &mut ImportStats)
                      -> Result<(ImportStatus, ImportStatus)>
    {
        if ! cert.is_tsk() {
            return Err(anyhow::anyhow!(
                "Nothing to import: certificate does not contain \
                 any secret key material"));
        }

        let keystore = self.key_store_or_else()?;
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
            self.info(format_args!(
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
        match self.cert_store_or_else() {
            Ok(cert_store) => {
                let new_certs = stats.certs.new_certs();
                let updated_certs = stats.certs.updated_certs();

                if let Err(err) = cert_store.update_by(
                    Arc::new(LazyCert::from(cert)), stats)
                {
                    self.info(format_args!(
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
                self.info(format_args!(
                    "Not importing {} into cert store: {}",
                    fpr, err));
            }
        }

        Ok((key_import_status, cert_import_status))
    }

    /// Imports the certificate into the certificate store.
    ///
    /// On success, returns whether the key was imported, updated, or
    /// unchanged.
    pub fn import_cert(&self, cert: Cert) -> Result<ImportStatus> {
        let fpr = cert.fingerprint();
        let cert_store = self.cert_store_or_else()?;

        let stats = MergePublicCollectStats::new();
        cert_store.update_by(Arc::new(LazyCert::from(cert)), &stats)
            .with_context(|| {
                format!("Failed to import {} into the certificate store",
                        fpr)
            })?;

        let import_status = if stats.new_certs() > 0 {
            ImportStatus::New
        } else if stats.updated_certs() > 0 {
            ImportStatus::Updated
        } else {
            ImportStatus::Unchanged
        };

        Ok(import_status)
    }

    pub fn best_userid<'u>(&self, cert: &'u Cert, use_wot: bool)
        -> PreferredUserID
    {
        self.sequoia.best_userid(cert, use_wot)
    }

    pub fn best_userid_for<'u, F>(&self,
                                  key_handle: &KeyHandle,
                                  key_flags: F,
                                  use_wot: bool)
                                  -> (PreferredUserID, Result<Cert>)
    where
        F: Into<Option<KeyFlags>>,
    {
        self.sequoia.best_userid_for(key_handle, key_flags, use_wot)
    }

    /// Caches a password.
    pub fn cache_password(&self, password: Password) {
        self.sequoia.cache_password(password)
    }

    /// Returns the cached passwords.
    pub fn cached_passwords(&self) -> impl Iterator<Item=Password> {
        self.sequoia.cached_passwords()
    }

    /// Decrypts a key, if possible.
    ///
    /// If the key is not decrypted, this just returns the key as is.
    /// Otherwise, the password cache is tried.  If the key can't be
    /// decrypted using those passwords and `may_prompt` is true, the
    /// user is prompted.  If a valid password is entered, it is added
    /// to the password cache.
    ///
    /// If `allow_skipping` is true, then the user is given the option
    /// to skip decrypting the key.  If the user skips decrypting the
    /// key, then an error is returned.
    pub fn decrypt_key<R>(&self, cert: Option<&Cert>,
                          key: Key<key::SecretParts, R>,
                          may_prompt: bool,
                          allow_skipping: bool)
        -> Result<Key<key::SecretParts, R>>
    where R: key::KeyRole + Clone,
    {
        if may_prompt {
            let prompt = password::Prompt::new(self, allow_skipping);
            self.sequoia.decrypt_key(cert, key, allow_skipping, prompt)
        } else {
            let prompt = prompt::Cancel::new();
            self.sequoia.decrypt_key(cert, key, allow_skipping, prompt)
        }
    }

    /// Gets a signer for the specified key.
    ///
    /// If `ka` includes secret key material, that is preferred.
    /// Otherwise, we look for the key on the key store.
    ///
    /// If the key is locked, we try to unlock it.  If the key isn't
    /// protected by a retry counter, then the password cache is
    /// tried.  Otherwise, or if that fails, the user is prompted to
    /// unlock the key.  The correct password is added to the password
    /// cache.
    pub fn get_signer<P, R, R2>(&self, ka: &KeyAmalgamation<P, R, R2>)
        -> Result<Box<dyn crypto::Signer + Send + Sync>>
        where P: key::KeyParts + Clone, R: key::KeyRole + Clone
    {
        let try_tsk = |cert: &Cert, key: &Key<_, _>|
            -> Result<_>
        {
            if let Ok(key) = key.parts_as_secret() {
                let key = self.decrypt_key(
                    Some(cert), key.clone(), true, false)?;
                let keypair = Box::new(key.into_keypair()
                    .expect("decrypted secret key material"));
                Ok(keypair)
            } else {
                Err(anyhow!("No secret key material."))
            }
        };
        let try_keyrings = |cert: &Cert, key: &Key<_, _>|
            -> Result<_>
        {
            let keyring_tsks = self.keyring_tsks()?;
            if let Some((cert_fpr, key))
                = keyring_tsks.get(&key.fingerprint())
            {
                if cert_fpr == &cert.fingerprint() {
                    return try_tsk(cert, key);
                }
            }

            Err(anyhow!("No secret key material."))
        };
        let try_keystore = |ka: &KeyAmalgamation<_, _, R2>|
            -> Result<_>
        {
            let ks = self.key_store_or_else()?;

            let mut ks = ks.lock().unwrap();

            let remote_keys = ks.find_key(ka.key().key_handle())?;

            // XXX: Be a bit smarter.  If there are multiple
            // keys, sort them so that we try the easiest one
            // first (available, no password).

            'key: for mut key in remote_keys.into_iter() {
                if let Protection::Password(hint) = key.locked()? {
                    if self.cached_passwords()
                        .find(|password| {
                            key.unlock(password.clone()).is_ok()
                        })
                        .is_some()
                    {
                        return Ok(Box::new(key));
                    } else {
                        if let Some(hint) = hint {
                            weprintln!("{}", hint);
                        }

                        let prompt = password::Prompt::new(self, true);

                        let mut context
                            = prompt::ContextBuilder::password(
                                prompt::Reason::UnlockKey)
                            .sequoia(&self.sequoia)
                            .cert(Cow::Borrowed(ka.cert()))
                            .key(key.fingerprint())
                            .build();

                        let mut checker = CheckRemoteKey::optional(&mut key);

                        match prompt.prompt(&mut context, &mut checker) {
                            Ok(prompt::Response::Password(p)) => {
                                assert!(checker.resolve());
                                self.cache_password(p.clone());
                                return Ok(Box::new(key));
                            },
                            Ok(prompt::Response::NoPassword)
                                | Err(prompt::Error::Cancelled(_)) =>
                            {
                                continue 'key;
                            }
                            Ok(unknown) => {
                                unreachable!("Internal error: UnlockKey \
                                              should return a password, \
                                              but got: {:?}",
                                             unknown);
                            }
                            Err(err) => {
                                return Err(err)
                                    .context("Prompting password");
                            }
                        }
                    }
                } else {
                    // Not locked.
                    return Ok(Box::new(key));
                }
            }

            Err(anyhow!("Key not managed by keystore."))
        };

        let key = ka.key().parts_as_public().role_as_unspecified();

        if let Ok(key) = try_tsk(ka.cert(), key) {
            Ok(key)
        } else if let Ok(key) = try_keyrings(ka.cert(), key) {
            Ok(key)
        } else if let Ok(key) = try_keystore(ka) {
            Ok(key)
        } else {
            Err(anyhow!("No secret key material."))
        }
    }

    /// Returns a signer for each certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the key type specified in `keytype` (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    fn get_keys<C>(&self, certs: &[C],
                   keytype: KeyType,
                   options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>>
    where C: Borrow<Cert>
    {
        let mut bad = Vec::new();

        let options = options.unwrap_or(&[][..]);
        let allow_not_alive = options.contains(&GetKeysOptions::AllowNotAlive);
        let allow_revoked = options.contains(&GetKeysOptions::AllowRevoked);
        let null_policy = options.contains(&GetKeysOptions::NullPolicy);

        let policy = if null_policy {
            &NULL_POLICY as &dyn Policy
        } else {
            self.policy() as &dyn Policy
        };

        let mut keys = vec![];

        'next_cert: for cert in certs {
            let cert = cert.borrow();
            let vc = match cert.with_policy(policy, self.time()) {
                Ok(vc) => vc,
                Err(err) => {
                    return Err(
                        err.context(format!("Found no suitable key on {}", cert)));
                }
            };

            let keyiter = match keytype {
                KeyType::Primary => {
                    Box::new(
                        std::iter::once(
                            vc.keys()
                                .next()
                                .expect("a valid cert has a primary key")))
                        as Box<dyn Iterator<Item=ValidErasedKeyAmalgamation<openpgp::packet::key::PublicParts>>>
                },
                KeyType::KeyFlags(ref flags) => {
                    Box::new(vc.keys().key_flags(flags.clone()))
                        as Box<dyn Iterator<Item=_>>
                },
            };
            for ka in keyiter {
                let mut bad_ = [
                    ! allow_not_alive && matches!(ka.alive(), Err(_)),
                    ! allow_revoked && matches!(ka.revocation_status(),
                                                RevocationStatus::Revoked(_)),
                    ! ka.key().pk_algo().is_supported(),
                    false,
                ];
                if bad_.iter().any(|x| *x) {
                    bad.push((ka.key().fingerprint(), bad_));
                    continue;
                }

                if let Ok(key) = self.get_signer(ka.amalgamation()) {
                    keys.push((cert.clone(), key));
                    continue 'next_cert;
                } else {
                    bad_[3] = true;
                    bad.push((ka.key().fingerprint(), bad_));
                    continue;
                }
            }

            // We didn't get a key.  Lint the cert.

            let time = chrono::DateTime::<chrono::offset::Utc>::from(self.time());

            let mut context = Vec::new();
            for (fpr, [not_alive, revoked, not_supported, no_secret_key]) in bad {
                let id: String = if fpr == cert.fingerprint() {
                    fpr.to_string()
                } else {
                    format!("{}/{}", cert.fingerprint(), fpr)
                };

                let preface = if ! self.time_is_now() {
                    format!("{} was not considered because\n\
                             at the specified time ({}) it was",
                            id, time)
                } else {
                    format!("{} was not considered because\nit is", fpr)
                };

                let mut reasons = Vec::new();
                if not_alive {
                    reasons.push("not alive");
                }
                if revoked {
                    reasons.push("revoked");
                }
                if not_supported {
                    reasons.push("not supported");
                }
                if no_secret_key {
                    reasons.push("missing the secret key");
                }

                context.push(format!("{}: {}",
                                     preface, reasons.join(", ")));
            }

            if context.is_empty() {
                return Err(anyhow::anyhow!(
                    format!("Found no suitable key on {}", cert)));
            } else {
                let context = context.join("\n");
                return Err(
                    anyhow::anyhow!(
                        format!("Found no suitable key on {}", cert))
                        .context(context));
            }
        }

        Ok(keys)
    }

    /// Returns a signer for each certificate's primary key.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_primary_keys<C>(&self, certs: &[C],
                               options: Option<&[GetKeysOptions]>)
        -> Result<Vec<Box<dyn crypto::Signer + Send + Sync>>>
    where C: std::borrow::Borrow<Cert>
    {
        self.get_keys(certs, KeyType::Primary, options)
            .map(|keys| keys.into_iter()
                 .map(|(_, signer)| signer)
                 .collect())
    }

    /// Returns a signer for the certificate's primary key.
    ///
    /// If the certificate doesn't have a suitable key, then this
    /// returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_primary_key<C>(&self, certs: C,
                              options: Option<&[GetKeysOptions]>)
        -> Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: std::borrow::Borrow<Cert>
    {
        let keys = self.get_primary_keys(&[certs], options)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_primary_keys()"
        );
        Ok(keys.into_iter().next().unwrap())
    }

    /// Returns a signer for a signing-capable key for each
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is signing capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_signing_keys<C>(&self, certs: &[C],
                               options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>>
    where C: Borrow<Cert>
    {
        self.get_keys(certs,
                      KeyType::KeyFlags(KeyFlags::empty().set_signing()),
                      options)
    }

    /// Returns a signer for a signing-capable key for the
    /// certificate.
    ///
    /// If a certificate doesn't have a suitable key, then this
    /// returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is signing capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_signing_key<C>(&self, cert: C,
                               options: Option<&[GetKeysOptions]>)
        -> Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: Borrow<Cert>
    {
        let keys = self.get_signing_keys(&[cert], options)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_signing_keys()"
        );
        Ok(keys.into_iter().next().unwrap().1)
    }

    /// Returns a signer for a certification-capable key for each
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is certification capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_certification_keys<C>(&self, certs: &[C],
                                     options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>>
    where C: std::borrow::Borrow<Cert>
    {
        self.get_keys(certs,
                      KeyType::KeyFlags(KeyFlags::empty().set_certification()),
                      options)
    }

    /// Returns a signer for a certification-capable key for the
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is certification capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_certification_key<C>(&self, cert: C,
                                    options: Option<&[GetKeysOptions]>)
        -> Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: std::borrow::Borrow<Cert>
    {
        let keys = self.get_certification_keys(&[cert], options)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_certification_keys()"
        );
        Ok(keys.into_iter().next().unwrap().1)
    }

    /// Prints additional information in verbose mode.
    pub fn info(&self, msg: fmt::Arguments) {
        if self.verbose() {
            weprintln!("{}", msg);
        }
    }

    /// Prints a hint for the user.
    pub fn hint(&self, msg: fmt::Arguments) -> Hint {
        Hint::new(! self.config().hints())
            .hint(msg)
    }

    /// Resolve cert designators to certificates.
    ///
    /// When matching on a user ID, a certificate is only returned if
    /// the matching user ID can be authenticated at the specified
    /// amount (`trust_amount`).  Note: when `trust_amount` is 0,
    /// matching user IDs do not have to be self signed.  If a
    /// designator matches multiple certificates, all of them are
    /// returned.
    ///
    /// When matching by key handle via `--cert`, or reading a
    /// certificate from a file, or from stdin, the certificate is not
    /// further authenticated.
    ///
    /// The returned certificates are deduped (duplicate certificates
    /// are merged).
    ///
    /// This function returns a vector of certificates and a vector of
    /// errors.  If processing a certificate results in an error, we
    /// add it to the list of errors.  If a designator does not match
    /// any certificates, an error is added to the error vector.  In
    /// general, designator-specific errors are returned as `Err`s in
    /// the `Vec`.  General errors, like the certificate store is
    /// disabled, are returned using the outer `Result`.
    pub fn resolve_certs<Arguments, Prefix, Options, Doc>(
        &self,
        designators: &CertDesignators<Arguments, Prefix, Options, Doc>,
        trust_amount: TrustThreshold,
    )
        -> Result<(Vec<Cert>, Vec<anyhow::Error>)>
    where
        Prefix: cert_designator::ArgumentPrefix,
    {
        self.resolve_certs_filter(designators, trust_amount, &mut |_, _| Ok(()))
    }


    /// Like [`Sq::resolve_certs`], but takes a filter option.
    ///
    /// The filter is applied in such a way that cert designators that
    /// can match more than one certificate (such as `--cert-domain`)
    /// only fail if they don't match any cert after filtering.
    ///
    /// Note: just because `filter` is called on a certificate, and it
    /// returns `Ok` doesn't mean that the certificate will
    /// necessarily be returned.
    pub fn resolve_certs_filter<Arguments, Prefix, Options, Doc>(
        &self,
        designators: &CertDesignators<Arguments, Prefix, Options, Doc>,
        trust_amount: TrustThreshold,
        filter: &mut dyn FnMut(&cert_designator::CertDesignator, &LazyCert)
                               -> Result<()>,
    )
        -> Result<(Vec<Cert>, Vec<anyhow::Error>)>
    where
        Prefix: cert_designator::ArgumentPrefix,
    {
        self.resolve_certs_filter_intern(
            &designators.designators, Prefix::prefix(), trust_amount, filter)
    }

    /// Like [`Sq::resolve_certs_filter`], but prevents
    /// monomorphization.
    fn resolve_certs_filter_intern(
        &self,
        designators: &[cert_designator::CertDesignator],
        prefix: &str,
        trust_amount: TrustThreshold,
        mut filter: &mut dyn FnMut(&cert_designator::CertDesignator, &LazyCert)
                                   -> Result<()>,
    )
        -> Result<(Vec<Cert>, Vec<anyhow::Error>)>
    {
        tracer!(TRACE, "Sq::resolve_certs_filter_intern");
        t!("{:?}", designators);

        // To report all errors, and not just the first one that we
        // encounter, we maintain a list of errors.
        let mut errors: Vec<anyhow::Error> = Vec::new();

        // We merge the certificates eagerly.  To do so, we maintain a
        // list of certificates that we've looked up.
        let mut results: Vec<Cert> = Vec::new();

        // Whether `ret` added something.  This needs to be a
        // `RefCell`. because the `ret` closure holds a `&mut` to
        // `results`.
        let matched: RefCell<bool> = RefCell::new(false);

        // Whether we've seen the given certificate.  The boolean is
        // if we merged in the certificate from the cert store.  The
        // index is the index of the certificate in `results`.
        let mut have: BTreeMap<Fingerprint, (bool, usize)>
            = BTreeMap::new();

        // The list of user ID queries.
        let mut userid_queries: Vec<(&cert_designator::CertDesignator, _, String)>
            = Vec::new();

        // Only open the cert store if we actually need it.
        let mut cert_store_ = None;
        let mut cert_store = || -> Result<_> {
            if let Some(cert_store) = cert_store_ {
                Ok(cert_store)
            } else {
                cert_store_ = Some(self.cert_store_or_else()?);
                Ok(cert_store_.expect("just set"))
            }
        };

        // Return a certificate or an error to the caller.
        //
        // `from_cert_store` is whether the certificate was read from
        // the certificate store or not.
        //
        // If `apply_filter` is true, `filter` is applied.  This
        // should be done for designators that precisely designate
        // certs (e.g. by fingerprint, or file), and false if the designator can
        // match more than one cert (e.g. by user ID match).
        let mut ret = |designator: &cert_designator::CertDesignator,
                       cert: Result<Arc<LazyCert>>,
                       from_cert_store: bool,
                       apply_filter: Option<
                               &mut dyn FnMut(&cert_designator::CertDesignator,
                                              &LazyCert)
                                              -> Result<()>>|
        {
            let cert = match cert {
                Ok(cert) => cert,
                Err(err) => {
                    errors.push(
                        err.context(format!(
                            "Failed to resolve {}",
                            designator.argument_with_prefix(prefix))));
                    return;
                }
            };

            if let Some(filter) = apply_filter {
                if let Err(err) = filter(designator, &cert) {
                    errors.push(
                        err.context(format!(
                            "Failed to resolve {}",
                            designator.argument_with_prefix(prefix))));
                    return;
                }
            }

            match have.entry(cert.fingerprint()) {
                Entry::Occupied(mut oe) => {
                    let (have_from_cert_store, have_cert) = oe.get_mut();
                    if from_cert_store {
                        if *have_from_cert_store {
                            // We read `cert` from the cert store, and
                            // we read the same cert from the cert
                            // store in the past.  There's nothing to
                            // merge; we're done.
                            *matched.borrow_mut() = true;
                            return;
                        }
                    }

                    let cert = match cert.to_cert() {
                        Ok(cert) => cert.clone(),
                        Err(err) => {
                            errors.push(
                                err.context(format!(
                                    "Failed to resolve {}",
                                    designator.argument_with_prefix(prefix))));
                            return;
                        }
                    };

                    assert!(*have_cert < results.len());
                    if let Some(have_cert) = results.get_mut(*have_cert) {
                        *have_cert = have_cert.clone()
                            .merge_public_and_secret(cert)
                            .expect("same cert");
                    }

                    *have_from_cert_store |= from_cert_store;

                    *matched.borrow_mut() = true;
                }
                Entry::Vacant(ve) => {
                    let cert = match cert.to_cert() {
                        Ok(cert) => cert.clone(),
                        Err(err) => {
                            errors.push(
                                err.context(format!(
                                    "Failed to resolve {}",
                                    designator.argument_with_prefix(prefix))));
                            return;
                        }
                    };

                    ve.insert((from_cert_store, results.len()));

                    results.push(cert);

                    *matched.borrow_mut() = true;
                }
            }
        };

        for designator in designators {
            *matched.borrow_mut() = false;

            match designator {
                cert_designator::CertDesignator::Cert(kh) => {
                    t!("Looking up certificate by handle {}", kh);

                    match cert_store()?.lookup_by_cert(kh) {
                        Ok(matches) => {
                            for cert in matches.into_iter() {
                                // We matched on the primary key.
                                ret(designator, Ok(cert), true, Some(&mut filter));
                            }
                        }
                        Err(err) => {
                            ret(designator, Err(err), true, Some(&mut filter));
                        }
                    }
                }

                cert_designator::CertDesignator::UserID(userid) => {
                    t!("Looking up certificate by userid {:?}", userid);

                    match designator.query_params() {
                        Ok(Some((q, pattern))) =>
                            userid_queries.push((designator, q, pattern)),

                        Ok(None) =>
                            unreachable!("designator matches on user IDs"),

                        Err(err) =>
                            ret(designator, Err(err), true, None),
                    }
                }

                cert_designator::CertDesignator::Email(email) => {
                    t!("Looking up certificate by email {:?}", email);

                    match designator.query_params() {
                        Ok(Some((q, pattern))) =>
                            userid_queries.push((designator, q, pattern)),

                        Ok(None) =>
                            unreachable!("designator matches on user IDs"),

                        Err(err) =>
                            ret(designator, Err(err), true, None),
                    }
                }

                cert_designator::CertDesignator::Domain(domain) => {
                    t!("Looking up certificate by domain {:?}", domain);

                    match designator.query_params() {
                        Ok(Some((q, pattern))) =>
                            userid_queries.push((designator, q, pattern)),

                        Ok(None) =>
                            unreachable!("designator matches on user IDs"),

                        Err(err) =>
                            ret(designator, Err(err), true, None),
                    }
                }

                cert_designator::CertDesignator::Grep(pattern) => {
                    t!("Looking up certificate by pattern {:?}", pattern);

                    match designator.query_params() {
                        Ok(Some((q, pattern))) =>
                            userid_queries.push((designator, q, pattern)),

                        Ok(None) =>
                            unreachable!("designator matches on user IDs"),

                        Err(err) =>
                            ret(designator, Err(err), true, None),
                    }
                }

                cert_designator::CertDesignator::File(filename) => {
                    t!("Reading certificates from the file {}",
                       filename.display());

                    match crate::load_certs(
                        std::iter::once(filename.as_path()))
                    {
                        Ok(found) => {
                            if found.is_empty() {
                                ret(designator,
                                    Err(anyhow::anyhow!(
                                        "File does not contain any \
                                         certificates")),
                                    false, Some(&mut filter));
                            } else {
                                for cert in found.into_iter() {
                                    ret(designator,
                                        Ok(Arc::new(cert.into())),
                                        false, Some(&mut filter));
                                }
                            }
                        },
                        Err(err) => {
                            ret(designator, Err(err), false, Some(&mut filter));
                        }
                    }
                }

                cert_designator::CertDesignator::Stdin => {
                    t!("Reading certificates from stdin");
                    let parser = CertParser::from_reader(StdinWarning::certs())
                        .with_context(|| {
                            format!("Failed to load certs from stdin")
                        })?;
                    for cert in parser {
                        match cert {
                            Ok(cert) => {
                                ret(
                                    designator,
                                    Ok(Arc::new(cert.into())),
                                    false, Some(&mut filter));
                            }
                            Err(err) => {
                                ret(designator,
                                    Err(err),
                                    false, Some(&mut filter));
                                continue;
                            }
                        }
                    }
                    if ! *matched.borrow() {
                        ret(
                            designator,
                            Err(anyhow::anyhow!(
                                "stdin did not contain any certificates")),
                            false, Some(&mut filter));
                    }
                }
                cert_designator::CertDesignator::Special(name) => {
                    let certd = match self.certd_or_else() {
                        Ok(certd) => certd,
                        Err(err) => {
                            ret(
                                designator,
                                Err(err),
                                true, Some(&mut filter));
                            continue;
                        }
                    };

                    let result = match name {
                        SpecialName::PublicDirectories => {
                            certd.public_directory_ca()
                        }
                        SpecialName::KeysOpenpgpOrg => {
                            certd.shadow_ca_keys_openpgp_org()
                        }
                        SpecialName::KeysMailvelopeCom => {
                            certd.shadow_ca_keys_mailvelope_com()
                        }
                        SpecialName::ProtonMe => {
                            certd.shadow_ca_proton_me()
                        }
                        SpecialName::WKD => {
                            certd.shadow_ca_wkd()
                        }
                        SpecialName::DANE => {
                            certd.shadow_ca_dane()
                        }
                        SpecialName::Autocrypt => {
                            certd.shadow_ca_autocrypt()
                        }
                        SpecialName::Web => {
                            certd.shadow_ca_web()
                        }
                    };

                    ret(
                        designator,
                        result
                            .map(|(cert, _created)| cert)
                            .with_context(|| {
                                format!("Looking up special certificate {}",
                                        name)
                            }),
                        true, Some(&mut filter));
                },

                cert_designator::CertDesignator::Self_ => {
                    let (certs, config): (Box<dyn Iterator<Item=&Fingerprint>>, _)
                        = match prefix
                    {
                        "for-" => (
                            Box::new(self.config().encrypt_for_self().iter()),
                            Config::encrypt_for_self_config_key(),
                        ),
                        "signer-" => (
                            Box::new(self.config().sign_signer_self().iter()),
                            Config::sign_signer_self_config_key(),
                        ),
                        "certifier-" => (
                            Box::new(self.config().pki_vouch_certifier_self().iter()),
                            Config::pki_vouch_certifier_self_config_key(),
                        ),
                        _ => return Err(anyhow::anyhow!(
                            "self designator used with unexpected prefix: {}", prefix)),
                    };

                    let mut one = false;
                    for fp in certs {
                        let cert = self.resolve_cert(
                            &openpgp::KeyHandle::from(
                                fp.clone()).into(), TrustThreshold::YOLO)?.0;
                        ret(designator,
                            Ok(Arc::new(cert.into())),
                            true, Some(&mut filter));
                        one = true;
                    }

                    if ! one {
                        return Err(anyhow::anyhow!(
                            "`--{}self` is given but no default \
                             is set in the configuration file under `{}`",
                            prefix,
                            config));
                    }
                },
            }
        }

        let n = if ! userid_queries.is_empty() {
            Some(self.wot_query()?.build())
        } else {
            None
        };

        for (designator, q, pattern) in userid_queries.iter() {
            t!("Executing query {:?} against {}", q, pattern);

            let n = n.as_ref().unwrap();

            *matched.borrow_mut() = false;

            let cert_store = cert_store()?;
            match cert_store.select_userid(q, pattern) {
                Ok(found) => {
                    t!("=> {} results", found.len());

                    // Apply the filter, if any.
                    let (found, error) = found.into_iter().fold(
                        (Vec::new(), None),
                        |(mut found, mut error), c|
                        {
                            match filter(designator, &c) {
                                Ok(()) => found.push(c),
                                Err(err) => {
                                    if error.is_none() {
                                        error = Some(err);
                                    }
                                }
                            }

                            (found, error)
                        });

                    if found.is_empty() {
                        ret(designator,
                            Err(error.unwrap_or_else(|| {
                                anyhow::anyhow!(
                                    "query did not match any certificates")
                            })),
                            true, None);
                        continue;
                    }

                    // If the designator doesn't match anything, we
                    // can sometimes provide a hint, e.g., weak
                    // crypto.
                    let mut hint = Vec::new();

                    for cert in found.into_iter() {
                        let mut authenticated = false;
                        if trust_amount == TrustThreshold::YOLO {
                            authenticated = true;
                        } else {
                            // Find the matching user ID and
                            // authenticate it.
                            for userid in cert.userids() {
                                if q.check(&userid, pattern) {
                                    let paths = n.authenticate(
                                        &userid, cert.fingerprint(),
                                        trust_amount.into());
                                    if paths.amount() < trust_amount.into() {
                                        hint.push(Err(anyhow::anyhow!(
                                            "{}, {} cannot be authenticated \
                                             at the required level ({} of {}). \
                                             After checking that {} really \
                                             controls {}, you could certify \
                                             their certificate by running \
                                             `sq pki link add --cert {} \
                                             --userid {:?}`.",
                                            cert.fingerprint(),
                                            ui::Safe(&userid),
                                            paths.amount(), trust_amount,
                                            ui::Safe(&userid),
                                            cert.fingerprint(),
                                            cert.fingerprint(),
                                            String::from_utf8_lossy(userid.value()))));
                                    } else {
                                        authenticated = true;
                                        break;
                                    }
                                }
                            }
                        }

                        if authenticated {
                            ret(designator, Ok(cert), true, None);
                        }
                    }

                    if ! *matched.borrow() {
                        // The designator didn't match any
                        // certificates.
                        if hint.is_empty() {
                            ret(designator,
                                Err(anyhow::anyhow!("Didn't match any certificates")),
                                true, None);
                        } else {
                            for hint in hint.into_iter() {
                                ret(designator,
                                    hint,
                                    true, None);
                            }
                        }
                    }
                }
                Err(err) => {
                    t!("=> {}", err);
                    ret(designator, Err(err), true, None);
                }
            }
        }

        Ok((results, errors))
    }

    /// Like `Sq::resolve_certs`, but bails if there is an error
    /// resolving a certificate.
    pub fn resolve_certs_or_fail<Arguments, Prefix, Options, Doc>(
        &self,
        designators: &CertDesignators<Arguments, Prefix, Options, Doc>,
        trust_amount: TrustThreshold,
    )
        -> Result<Vec<Cert>>
    where
        Prefix: cert_designator::ArgumentPrefix,
    {
        let (certs, errors) = self.resolve_certs(designators, trust_amount)?;

        for error in errors.iter() {
            print_error_chain(error);
        }
        if ! errors.is_empty() {
            return Err(anyhow::anyhow!("Failed to resolve certificates"));
        }

        Ok(certs)
    }

    /// Like `Sq::resolve_certs`, but bails if there is not exactly
    /// one designator, or the designator resolves to multiple
    /// certificates.
    ///
    /// Returns whether the certificate was read from a file.
    pub fn resolve_cert<Arguments, Prefix, Options, Doc>(
        &self,
        designators: &CertDesignators<Arguments, Prefix, Options, Doc>,
        trust_amount: TrustThreshold,
    )
        -> Result<(Cert, FileStdinOrKeyHandle)>
    where
        Prefix: cert_designator::ArgumentPrefix,
    {
        self.resolve_cert_intern(
            &designators.designators, Prefix::prefix(), trust_amount)
    }

    /// Like [`Sq::resolve_certs`], but prevents monomorphization.
    fn resolve_cert_intern(
        &self,
        designators: &[cert_designator::CertDesignator],
        prefix: &str,
        trust_amount: TrustThreshold,
    )
        -> Result<(Cert, FileStdinOrKeyHandle)>
    {
        // Assuming this is only called with OneValue, then the
        // following are not required.
        if designators.len() == 0 {
            panic!("clap failed to enforce that the {} argument is \
                    required.",
                   prefix);
        } else if designators.len() > 1 {
            panic!("clap failed to enforce that the {} argument is \
                    specified at most once.",
                   prefix);
        }

        let (certs, errors) =
            self.resolve_certs_filter_intern(designators, prefix, trust_amount,
                                             &mut |_, _| Ok(()))?;
        if certs.len() > 1 {
            weprintln!("{} is ambiguous.  It resolves to multiple certificates.",
                       designators[0].argument_with_prefix(prefix));
            for cert in certs.iter() {
                eprintln!("  - {} {}",
                          cert.fingerprint(),
                          self.best_userid(cert, true).display());
            }

            return Err(anyhow::anyhow!(
                "{} is ambiguous.  It resolves to multiple certificates.",
                designators[0].argument_with_prefix(prefix)))
        }

        if let Some(errors) = errors.into_iter().next() {
            return Err(errors);
        }

        let cert = certs.into_iter().next().unwrap();
        let handle = cert.key_handle();
        Ok((cert,
            match &designators[0] {
                cert_designator::CertDesignator::Stdin =>
                    FileStdinOrKeyHandle::FileOrStdin(Default::default()),
                cert_designator::CertDesignator::File(p) =>
                    FileStdinOrKeyHandle::FileOrStdin(p.as_path().into()),
                _ => handle.into()
            }))
    }

    /// Resolves keys.
    ///
    /// Keys are resolved to valid keys (according to the current
    /// policy) that are not hard revoked.
    ///
    /// `cert` and `cert_handle` are as returned by
    /// `sq::resolve_cert`.
    pub fn resolve_keys<'a, KOptions, KDoc>(
        &self,
        vc: &ValidCert<'a>, cert_handle: &FileStdinOrKeyHandle,
        keys: &KeyDesignators<KOptions, KDoc>,
        return_hard_revoked: bool)
        -> Result<Vec<ValidErasedKeyAmalgamation<'a, PublicParts>>>
    where
        KOptions: typenum::Unsigned,
    {
        assert!(keys.len() > 0);

        let options = KOptions::to_usize();
        let only_subkeys = (options & key_designator::OnlySubkeys::to_usize()) > 0;

        let khs = keys.iter()
            .map(|d| {
                match d {
                    key_designator::KeyDesignator::KeyHandle(kh) => kh,
                }
            })
            .collect::<Vec<_>>();

        // Don't stop at the first error.
        let mut bad = Vec::new();
        let mut missing = Vec::new();
        let mut kas = Vec::new();
        for kh in khs {
            if let Some(ka) = vc.keys().key_handle(kh.clone()).next() {
                // The key is bound to the certificate.

                if only_subkeys && ka.primary() {
                    let err = format!(
                        "Selected key {} is a primary key, not a subkey.",
                        ka.key().fingerprint());
                    weprintln!("{}", err);
                    bad.push(anyhow::anyhow!(err));
                    continue;
                }

                // Make sure it is not hard revoked.
                let mut hard_revoked = false;
                if ! return_hard_revoked {
                    if let RevocationStatus::Revoked(sigs)
                        = ka.revocation_status()
                    {
                        for sig in sigs {
                            let reason = sig.reason_for_revocation();
                            hard_revoked = if let Some((reason, _)) = reason {
                                reason.revocation_type() == RevocationType::Hard
                            } else {
                                true
                            };

                            if hard_revoked {
                                break;
                            }
                        }
                    }
                }

                if hard_revoked {
                    let err = anyhow::anyhow!(
                        "Can't use {}, it is hard revoked",
                        ka.key().fingerprint());
                    weprintln!("{}", err);
                    bad.push(err);
                } else {
                    // Looks good!
                    kas.push(ka);
                }
            } else if let Some(ka)
                = vc.cert().keys().key_handle(kh.clone()).next()
            {
                // See if the key is associated with the certificate
                // in some way.  This isn't enough to return it, but
                // we may be able to generate a better error message.

                let fingerprint = ka.key().fingerprint();

                let err = match ka.with_policy(vc.policy(), vc.time()) {
                    Ok(_) => unreachable!("key magically became usable"),
                    Err(err) => err,
                };

                weprintln!("Selected key {} is unusable: {}.",
                           fingerprint, err);

                bad.push(err);

                self.hint(format_args!(
                    "After checking the integrity of the certificate, you \
                     may be able to repair it using:"))
                    .sq().arg("cert").arg("lint").arg("--fix")
                    .arg_value(
                        match &cert_handle {
                            FileStdinOrKeyHandle::KeyHandle(_kh) => {
                                "--cert"
                            }
                            FileStdinOrKeyHandle::FileOrStdin(_file) => {
                                "--cert-file"
                            }
                        },
                        match &cert_handle {
                            FileStdinOrKeyHandle::KeyHandle(kh) => {
                                kh.to_string()
                            }
                            FileStdinOrKeyHandle::FileOrStdin(file) => {
                                file.path()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "".into())
                            }
                        })
                    .done();
            } else {
                // The key isn't bound to the certificate at all.
                weprintln!("Selected key {} is not part of the certificate.",
                           kh);
                missing.push(kh);
            }
        }

        assert_eq!(keys.len(), kas.len() + missing.len() + bad.len(),
                   "Didn't partition {} keys: {} valid, {} missing, {} bad",
                   keys.len(), kas.len(), missing.len(), bad.len());

        if ! missing.is_empty() {
            weprintln!();
            if only_subkeys {
                weprintln!("{} has the following subkeys:", vc.cert().fingerprint());
            } else {
                weprintln!("{} has the following keys:", vc.cert().fingerprint());
            }
            weprintln!();
            for ka in vc.keys().skip(if only_subkeys { 1 } else { 0 }) {
                weprintln!(" - {}", ka.key().fingerprint());
            }
        }

        if let Some(err) = bad.into_iter().next() {
            return Err(err);
        } else if ! missing.is_empty() {
            return Err(anyhow::anyhow!(
                "Some keys are not associated with the certificate"));
        }

        // Dedup.
        kas.sort_by_key(|ka| ka.key().fingerprint());
        kas.dedup_by_key(|ka| ka.key().fingerprint());

        assert!(kas.len() > 0);

        Ok(kas)
    }
}
