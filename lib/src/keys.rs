use std::borrow::Cow;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::packet::Key;
use openpgp::packet::key::Encrypted;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::packet::key::Unencrypted;
use openpgp::packet::key;

use crate::Result;
use crate::Sequoia;
use crate::TRACE;
use crate::prompt;

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
}
