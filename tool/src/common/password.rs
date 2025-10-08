//! Common password-related functionality such as prompting.

use sequoia::openpgp as openpgp;
use openpgp::packet::Key;
use openpgp::packet::key;

use sequoia::key_store as keystore;

use sequoia::prompt;

use crate::Sq;

/// Prompt to repeat a password.
const REPEAT_PROMPT: &str = "Repeat the password";

pub struct Prompt<'a> {
    sq: &'a Sq,
    // Adds (password n of t) to the message.
    password: usize,
    password_count: usize,
    // Whether the user can skip this by entering the empty strip.  If
    // so, `prompt::Error::Cancelled` is returned instead of
    // `Response::NoPassword`.
    cancel: bool,
}

impl<'a> Prompt<'a> {
    /// Returns a new prompt.
    ///
    /// `cancel` means that if the user just hits enter, then we
    /// immediately return `prompt::Error::Cancel`.  Note: this is
    /// separate from allowing an empty password!
    pub fn new(sq: &'a Sq, cancel: bool) -> Self {
        Prompt {
            sq,
            password: 0,
            password_count: 0,
            cancel,
        }
    }

    /// Adds "(password n of t)".
    ///
    /// Cancel is disabled.
    pub fn npasswords(sq: &'a Sq, password: usize, count: usize) -> Self {
        Prompt {
            sq,
            password,
            password_count: count,
            cancel: false,
        }
    }
}

impl<'a> prompt::Prompt for Prompt<'a> {
    fn prompt<'c>(&self, context: &mut prompt::Context<'c>,
                  check: &mut dyn prompt::Check<'c>)
                  -> std::result::Result<prompt::Response, prompt::Error>
    {
        if self.sq.batch {
            return Err(prompt::Error::Disabled(Some(
                "Cannot prompt for password in batch mode".into())));
        }

        let mut prompt = context.prompt();

        if self.cancel {
            prompt.push_str(" (black to skip)");
        } else if context.reason().optional() {
            prompt.push_str(" (press enter to not use a password)");
        }

        // Add (password n of t), if appropriate.
        if self.password_count > 0 {
            assert_eq!(context.reason(), prompt::Reason::EncryptMessage);
            assert!(self.password > 0);
            assert!(self.password <= self.password_count);

            if self.password_count > 1 {
                prompt.push_str(&format!(
                    " (password {} of {})",
                    self.password, self.password_count));
            }
        } else {
            assert_eq!(self.password, 0);
            assert_eq!(self.password_count, 0);
        }

        let width = prompt.len().max(REPEAT_PROMPT.len());
        let p0 = format!("{:>1$}: ", prompt, width);
        let p1 = format!("{:>1$}: ", REPEAT_PROMPT, width);

        loop {
            let password = rpassword::prompt_password(&p0)?;

            if password.is_empty() {
                if self.cancel {
                    weprintln!("Skipping.");
                    return Err(prompt::Error::Cancelled(None));
                } else if ! context.reason().optional() {
                    eprintln!("You must enter a password.");
                    continue;
                }
            }

            if context.reason().confirm() {
                let password_repeat = rpassword::prompt_password(&p1)?;

                if password != password_repeat {
                    weprintln!("The passwords do not match.  Try again.");
                    weprintln!();
                    continue;
                }
            }

            let response = if password.is_empty() {
                prompt::Response::NoPassword
            } else {
                prompt::Response::Password(password.into())
            };

            if let Err(err) = check.check(context, &response) {
                eprintln!("{}", err);
            } else {
                return Ok(response);
            }
        }
    }
}

// When the password is wrong, we often get an unexpected eof.  This
// message is confusing for a user; suppress it.
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
            match err.downcast::<sequoia::key_store::Error>() {
                Ok(err) => {
                    match err {
                        sequoia::key_store::Error::EOF => {
                            None
                        }
                        sequoia::key_store::Error::GenericError(Some(ref s)) => {
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

/// Checks a new password.
///
/// Don't place any restrictions on passwords, and accept everything
/// including the empty password.
pub struct CheckNewPassword {
}

impl CheckNewPassword {
    pub fn new() -> Self
    {
        Self {
        }
    }
}

impl prompt::Check<'_> for CheckNewPassword {
    fn check(&mut self,
             _context: &mut prompt::Context,
             _response: &prompt::Response)
        -> std::result::Result<(), prompt::CheckError>
    {
        Ok(())
    }
}

/// Checks that a password can be used to unlock a remove key.
///
/// [`CheckRemoteKey::resolve`] returns whether the key was unlocked.
pub struct CheckRemoteKey<'a> {
    allow_skipping: bool,
    key: &'a mut keystore::Key,
    unlocked: bool,
}

impl<'a> CheckRemoteKey<'a> {
    /// Tries to unlock the remote key.
    ///
    /// The user may not skip this.
    pub fn required(key: &'a mut keystore::Key) -> Self {
        Self {
            allow_skipping: false,
            key,
            unlocked: false,
        }
    }

    /// Tries to unlock the remote key.
    ///
    /// The user may skip this.
    pub fn optional(key: &'a mut keystore::Key) -> Self {
        Self {
            allow_skipping: true,
            key,
            unlocked: false,
        }
    }

    /// Returns whether we unlocked the key.
    pub fn resolve(self) -> bool {
        self.unlocked
    }
}

impl prompt::Check<'_> for CheckRemoteKey<'_> {
    fn check(&mut self,
             _context: &mut prompt::Context,
             response: &prompt::Response)
        -> std::result::Result<(), prompt::CheckError>
    {
        match response {
            prompt::Response::Password(password) => {
                if let Err(err) = self.key.unlock(password.clone()) {
                    Err(prompt::CheckError::IncorrectPassword(
                        flatten_eof(err)))
                } else {
                    self.unlocked = true;
                    Ok(())
                }
            }
            prompt::Response::NoPassword => {
                if self.allow_skipping {
                    // Skip.
                    Ok(())
                } else {
                    Err(prompt::CheckError::PasswordRequired(None))
                }
            }
            r => {
                Err(anyhow::anyhow!("Unhandled response: {:?}", r).into())
            }
        }
    }
}

/// Tries to unlock a key.
pub struct CheckKeys<'a, R>
where
    R: key::KeyRole + Clone,
{
    allow_skipping: bool,
    keys: &'a mut [Key<key::SecretParts, R>],
    unlocked: Option<(usize, Key<key::SecretParts, R>)>,
}

impl<'a, R> CheckKeys<'a, R>
where
    R: key::KeyRole + Clone,
{
    /// Tries to unlock one of the remote keys.
    ///
    /// The user may not skip this.
    pub fn required(keys: &'a mut [Key<key::SecretParts, R>]) -> Self {
        Self {
            allow_skipping: false,
            keys,
            unlocked: None,
        }
    }

    /// Tries to unlock one of the remote keys.
    ///
    /// The user may skip this.
    #[allow(dead_code)]
    pub fn optional(keys: &'a mut [Key<key::SecretParts, R>]) -> Self {
        Self {
            allow_skipping: true,
            keys,
            unlocked: None,
        }
    }

    /// Returns the unlock key, if any.
    ///
    /// The number is the index of the unlocked key.
    pub fn resolve(self) -> Option<(usize, Key<key::SecretParts, R>)> {
        self.unlocked
    }
}

impl<'a, R> prompt::Check<'_> for CheckKeys<'a, R>
where
    R: key::KeyRole + Clone,
{
    fn check(&mut self,
             _context: &mut prompt::Context,
             response: &prompt::Response)
        -> std::result::Result<(), prompt::CheckError>
    {
        let p = match response {
            prompt::Response::Password(p) => {
                Some(p)
            }
            prompt::Response::NoPassword => {
                None
            }
            r => {
                return Err(anyhow::anyhow!("Unhandled response: {:?}", r).into());
            }
        };

        // Empty password given and a key without
        // encryption?  Pick it.
        if p.is_none() {
            if let Some((i, k)) = self.keys.iter().enumerate()
                .find(|(_, k)| ! k.secret().is_encrypted())
            {
                self.unlocked = Some((i, k.clone()));
                return Ok(());
            }
        }

        let mut err = None;
        if let Some(p) = p.as_ref() {
            for (i, k) in self.keys.iter().enumerate() {
                match k.secret().clone().decrypt(k, &p) {
                    Ok(decrypted) => {
                        // Keep the decrypted keypair.
                        self.unlocked = Some((
                            i, k.clone().add_secret(decrypted).0));
                        return Ok(());
                    },

                    Err(e) => err = flatten_eof(e),
                }
            }
        }

        if p.is_none() {
            if self.allow_skipping {
                // Skip.
                Ok(())
            } else {
                Err(prompt::CheckError::PasswordRequired(None))
            }
        } else {
            Err(prompt::CheckError::IncorrectPassword(err))
        }
    }
}
