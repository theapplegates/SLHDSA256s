use std::borrow::Cow;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::packet::Key;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::packet::key;

use crate::Result;
use crate::Sequoia;
use crate::TRACE;
use crate::prompt;

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

                loop {
                    match prompt.prompt(&mut context)
                        .context("Prompting for password")?
                    {
                        prompt::Response::NoPassword => {
                            if allow_skipping {
                                return Err(prompt::Error::Cancelled(Some(
                                    "User canceled operation".into())).into());
                            } else {
                                weprintln!("You must enter a password \
                                            to continue.");
                            }
                        }
                        prompt::Response::Password(password) => {
                           if let Ok(unencrypted) = e.decrypt(&key, &password) {
                               let (key, _) = key.add_secret(unencrypted.into());
                               self.cache_password(password);
                               return Ok(key);
                           }

                           weprintln!("Incorrect password.");
                        }
                    }
                }
            }
        }
    }
}
