use std::borrow::Borrow;
use std::borrow::Cow;

use anyhow::Context as _;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::prelude::*;
use openpgp::crypto;
use openpgp::packet::Key;
use openpgp::packet::key::Encrypted;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::packet::key::Unencrypted;
use openpgp::packet::key;
use openpgp::policy::Policy;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;

use sequoia_keystore as keystore;
use keystore::Protection;

use crate::NULL_POLICY;
use crate::Result;
use crate::Sequoia;
use crate::cert::CertError;
use crate::cert;
use crate::prompt::Prompt;
use crate::prompt::check::CheckRemoteKey;
use crate::prompt;

use crate::TRACE;

/// Flags for [`Sequoia::get_signer`], [`Sequoia::get_primary_keys`]
/// and related functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetKeysOptions {
    /// Don't ignore keys that are not alive.
    AllowNotAlive,
    /// Don't ignore keys that are not revoke.
    AllowRevoked,
    /// Use the NULL Policy.
    NullPolicy,
}

/// Flags for [`Sequoia::get_signer`], [`Sequoia::get_primary_keys`]
/// and related functions.
pub enum KeyType {
    /// Only consider primary key.
    Primary,
    /// Only consider keys that have at least one of the specified
    /// capabilities.
    KeyFlags(KeyFlags),
}

// When the password is wrong, we often get an unexpected eof.  It
// doesn't make sense to propagate this to the user; suppress it.
fn flatten_eof(err: anyhow::Error) -> Option<anyhow::Error> {
    // For soft keys.
    match err.downcast::<std::io::Error>() {
        Ok(err) => {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                None
            } else {
                Some(err.into())
            }
        }
        Err(err) => {
            // For remote keys.
            match err.downcast::<sequoia_keystore::Error>() {
                Ok(err) => {
                    match err {
                        sequoia_keystore::Error::EOF => {
                            None
                        }
                        sequoia_keystore::Error::GenericError(Some(ref s)) => {
                            // At the RPC boundary, UnexpectedEof may
                            // be mapped to a string.  Use a sledgehammer.

                            // https://gitlab.com/sequoia-pgp/sequoia/-/blob/12d1d02e/buffered-reader/src/eof.rs#L69
                            static EOF_MSG: &'static str = "unexpected EOF";

                            if s == EOF_MSG {
                                None
                            } else {
                                Some(err.into())
                            }
                        }
                        _ => Some(err.into()),
                    }
                }
                Err(err) => Some(err),
            }
        }
    }
}

struct Check<'a, R>
where
    R: key::KeyRole + Clone,
{
    allow_skipping: bool,
    key: Key<key::SecretParts, R>,
    encrypted: &'a Encrypted,
    unencrypted: Option<Unencrypted>,
}

impl<R> prompt::Check<'_> for Check<'_, R>
where
    R: key::KeyRole + Clone,
{
    fn check(&mut self,
             _context: &mut prompt::Context,
             response: &prompt::Response)
        -> std::result::Result<(), prompt::CheckError>
    {
        match response {
            prompt::Response::Password(password) => {
                match self.encrypted.decrypt(&self.key, password) {
                    Ok(unencrypted) => {
                        self.unencrypted = Some(unencrypted);
                        Ok(())
                    }
                    Err(err) => {
                        Err(prompt::CheckError::IncorrectPassword(
                            flatten_eof(err)))
                    }
                }
            }
            prompt::Response::NoPassword => {
                if self.allow_skipping {
                    Ok(())
                } else {
                    Err(prompt::CheckError::PasswordRequired(None))
                }
            }
        }
    }
}

impl Sequoia {
    /// Decrypts a key, if possible.
    ///
    /// If the key is not decrypted, this just returns the key as is.
    /// Otherwise, the password cache is tried.  If the key can't be
    /// decrypted using those passwords, the user is prompted.  If a
    /// valid password is entered, it is added to the password cache.
    /// If you only want to probe the password cache and not prompt
    /// the user, use [`prompt::Cancel`] as the prompter.
    ///
    /// If `allow_skipping` is true, then the user is given the option
    /// to skip decrypting the key.  If the user skips decrypting the
    /// key, then an error is returned.
    pub fn decrypt_key<R, P>(&self, cert: Option<&Cert>,
                             key: Key<key::SecretParts, R>,
                             allow_skipping: bool,
                             prompt: P)
        -> Result<Key<key::SecretParts, R>>
    where R: key::KeyRole + Clone,
        P: prompt::Prompt,
    {
        tracer!(TRACE, "decrypt_key");
        t!("Decrypting {}/{}, allow skipping: {}",
           if let Some(cert) = cert {
               cert.fingerprint().to_string()
           } else {
               "unknown cert".into()
           },
           key.fingerprint(),
           allow_skipping);
        match key.secret() {
            SecretKeyMaterial::Unencrypted(_) => {
                t!("secret key material is unencrypted");
                Ok(key)
            }
            SecretKeyMaterial::Encrypted(e) => {
                t!("secret key material is encrypted");
                if ! e.s2k().is_supported() {
                    t!("s2k algorithm is not supported");
                    return Err(anyhow::anyhow!(
                        "Unsupported key protection mechanism"));
                }

                let password_cache = self.cached_passwords().collect::<Vec<_>>();
                t!("Trying password cache ({} entries)", password_cache.len());
                for p in password_cache.iter() {
                    if let Ok(unencrypted) = e.decrypt(&key, &p) {
                        let (key, _) = key.add_secret(unencrypted.into());
                        return Ok(key);
                    }
                }
                drop(password_cache);

                let mut context = prompt::ContextBuilder::password(
                    prompt::Reason::UnlockKey)
                    .sequoia(self)
                    .key(key.fingerprint());
                if let Some(cert) = cert {
                    context = context.cert(Cow::Borrowed(cert));
                }
                let mut context = context.build();

                let mut checker = Check {
                    allow_skipping,
                    key: key.clone(),
                    encrypted: e,
                    unencrypted: None,
                };

                match prompt.prompt(&mut context, &mut checker)
                    .context("Prompting for password")?
                {
                    prompt::Response::NoPassword => {
                        return Err(prompt::Error::Cancelled(Some(
                            "User canceled operation".into())).into());
                    }
                    prompt::Response::Password(password) => {
                        if let Some(unencrypted) = checker.unencrypted {
                            self.cache_password(password);
                            Ok(key.add_secret(unencrypted.into()).0)
                        } else {
                            panic!("Internal error: missing unencrypted key");
                        }
                    }
                }
            }
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
    pub fn get_signer<P1, R1, R2, P>(&self, ka: &KeyAmalgamation<P1, R1, R2>,
                                     prompt: P)
        -> Result<Box<dyn crypto::Signer + Send + Sync>, CertError>
    where P1: key::KeyParts + Clone,
          R1: key::KeyRole + Clone,
          P: Prompt,
    {
        let try_tsk = |cert: &Cert, key: &Key<_, _>|
            -> Result<_>
        {
            if let Ok(key) = key.parts_as_secret() {
                let key = self.decrypt_key(
                    Some(cert), key.clone(), false, &prompt)?;
                let keypair = Box::new(key.into_keypair()
                    .expect("decrypted secret key material"));
                Ok(keypair)
            } else {
                Err(anyhow::anyhow!("No secret key material."))
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

            Err(anyhow::anyhow!("No secret key material."))
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

                        let mut context
                            = prompt::ContextBuilder::password(
                                prompt::Reason::UnlockKey)
                            .sequoia(self)
                            .cert(Cow::Borrowed(ka.cert()))
                            .key(key.fingerprint())
                            .build();

                        let mut checker = CheckRemoteKey::optional(&mut key);

                        match prompt.prompt(&mut context, &mut checker) {
                            Ok(prompt::Response::Password(p)) => {
                                assert!(checker.unlocked());
                                self.cache_password(p.clone());
                                return Ok(Box::new(key));
                            },
                            Ok(prompt::Response::NoPassword)
                                | Err(prompt::Error::Cancelled(_)) =>
                            {
                                continue 'key;
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

            Err(anyhow::anyhow!("Key not managed by keystore."))
        };

        let key = ka.key().parts_as_public().role_as_unspecified();

        if let Ok(key) = try_tsk(ka.cert(), key) {
            Ok(key)
        } else if let Ok(key) = try_keyrings(ka.cert(), key) {
            Ok(key)
        } else if let Ok(key) = try_keystore(ka) {
            Ok(key)
        } else {
            Err(CertError {
                cert: ka.cert().clone(),
                problems: vec![
                    cert::CertProblem::MissingSecretKeyMaterial(
                        cert::problem::MissingSecretKeyMaterial {
                            cert: ka.cert().fingerprint(),
                            key: ka.key().fingerprint(),
                        })
                ]
            })
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
    fn get_keys<C, P>(&self, certs: &[C],
                      keytype: KeyType,
                      options: Option<&[GetKeysOptions]>,
                      prompt: P)
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>,
                  CertError>
    where C: Borrow<Cert>,
          P: Prompt,
    {
        let options = options.unwrap_or(&[][..]);
        let allow_not_alive = options.contains(&GetKeysOptions::AllowNotAlive);
        let allow_revoked = options.contains(&GetKeysOptions::AllowRevoked);
        let null_policy = options.contains(&GetKeysOptions::NullPolicy);

        let policy = if null_policy {
            NULL_POLICY as &dyn Policy
        } else {
            self.policy() as &dyn Policy
        };

        let mut keys = vec![];

        'next_cert: for cert in certs {
            let cert = cert.borrow();
            let vc = match cert.with_policy(policy, self.time()) {
                Ok(vc) => vc,
                Err(error) => {
                    return Err(CertError {
                        cert: cert.clone(),
                        problems: vec![
                            cert::CertProblem::CertInvalid(
                                cert::problem::CertInvalid {
                                    cert: cert.fingerprint(),
                                    error
                                })
                        ]
                    });
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

            let mut problems = Vec::new();

            let mut key_count = 0;
            for ka in keyiter {
                key_count += 1;

                let problem_count = problems.len();

                if ! allow_not_alive {
                    if let Err(err) = ka.alive() {
                        problems.push(cert::CertProblem::NotLive(
                            cert::problem::NotLive {
                                cert: cert.fingerprint(),
                                key: ka.key().fingerprint(),
                                creation_time: ka.key().creation_time(),
                                expiration_time: ka.key_expiration_time(),
                                reference_time: self.time(),
                                error: err,
                            }));
                    }
                }

                if ! allow_revoked {
                    if let RevocationStatus::Revoked(sigs)
                        = ka.revocation_status()
                    {
                        problems.push(cert::CertProblem::KeyRevoked(
                            cert::problem::KeyRevoked {
                                cert: cert.fingerprint(),
                                key: ka.key().fingerprint(),
                                revocations: sigs.into_iter()
                                    .map(|sig| sig.clone())
                                    .collect(),
                            }));
                    }
                }

                if ! ka.key().pk_algo().is_supported() {
                    problems.push(cert::CertProblem::UnsupportedAlgorithm(
                        cert::problem::UnsupportedAlgorithm {
                            cert: cert.fingerprint(),
                            key: ka.key().fingerprint(),
                            algo: ka.key().pk_algo(),
                        }));
                }

                if problems.len() > problem_count {
                    // This key has at least one problem.
                    continue;
                }

                match self.get_signer(ka.amalgamation(), &prompt) {
                    Ok(key) => {
                        keys.push((cert.clone(), key));
                        continue 'next_cert;
                    }
                    Err(err) => {
                        problems.extend(err.problems);
                        continue;
                    }
                }
            }

            // We didn't get a key.  Return an error.
            if problems.is_empty() {
                let key_flags = match keytype {
                    KeyType::Primary =>
                        unreachable!("All certificates have a primary key"),
                    KeyType::KeyFlags(flags) => flags.clone(),
                };

                return Err(CertError {
                    cert: cert.clone(),
                    problems: vec![
                        cert::CertProblem::NoUsableKeys(
                            cert::problem::NoUsableKeys {
                                cert: cert.fingerprint(),
                                capabilities: key_flags,
                                unusable: key_count,
                            })
                    ]
                });
            } else {
                return Err(CertError {
                    cert: cert.clone(),
                    problems,
                });
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
    pub fn get_primary_keys<C, P>(&self, certs: &[C],
                                  options: Option<&[GetKeysOptions]>,
                                  prompt: P)
        -> Result<Vec<Box<dyn crypto::Signer + Send + Sync>>, CertError>
    where
        C: std::borrow::Borrow<Cert>,
        P: Prompt,
    {
        self.get_keys(certs, KeyType::Primary, options, prompt)
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
    pub fn get_primary_key<C, P>(&self, certs: C,
                                 options: Option<&[GetKeysOptions]>,
                                 prompt: P)
        -> Result<Box<dyn crypto::Signer + Send + Sync>, CertError>
    where
        C: std::borrow::Borrow<Cert>,
        P: Prompt,
    {
        let keys = self.get_primary_keys(&[certs], options, prompt)?;
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
    pub fn get_signing_keys<C, P>(&self, certs: &[C],
                                  options: Option<&[GetKeysOptions]>,
                                  prompt: P)
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>,
                  CertError>
    where
        C: Borrow<Cert>,
        P: Prompt,
    {
        self.get_keys(certs,
                      KeyType::KeyFlags(KeyFlags::empty().set_signing()),
                      options, prompt)
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
    pub fn get_signing_key<C, P>(&self, cert: C,
                                 options: Option<&[GetKeysOptions]>,
                                 prompt: P)
        -> Result<Box<dyn crypto::Signer + Send + Sync>, CertError>
    where
        C: Borrow<Cert>,
        P: Prompt,
    {
        let keys = self.get_signing_keys(&[cert], options, prompt)?;
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
    pub fn get_certification_keys<C, P>(&self, certs: &[C],
                                        options: Option<&[GetKeysOptions]>,
                                        prompt: P)
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>,
                  CertError>
    where
        C: std::borrow::Borrow<Cert>,
        P: Prompt,
    {
        self.get_keys(certs,
                      KeyType::KeyFlags(KeyFlags::empty().set_certification()),
                      options, prompt)
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
    pub fn get_certification_key<C, P>(&self, cert: C,
                                       options: Option<&[GetKeysOptions]>,
                                       prompt: P)
        -> Result<Box<dyn crypto::Signer + Send + Sync>, CertError>
    where
        C: std::borrow::Borrow<Cert>,
        P: Prompt,
    {
        let keys = self.get_certification_keys(&[cert], options, prompt)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_certification_keys()"
        );
        Ok(keys.into_iter().next().unwrap().1)
    }
}
