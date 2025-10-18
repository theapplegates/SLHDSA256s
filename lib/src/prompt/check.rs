//! Various implementations of [`Check`][crate::prompt::Check].

use sequoia_openpgp as openpgp;
use openpgp::packet::SKESK;
use openpgp::types::SymmetricAlgorithm;
use openpgp::crypto;

use sequoia_keystore as keystore;

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
    /// The user may skip this.
    pub fn optional(key: &'a mut keystore::Key) -> Self {
        Self {
            allow_skipping: true,
            key,
            unlocked: false,
        }
    }

    /// Returns whether the key was unlocked.
    pub fn unlocked(self) -> bool {
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
                    Err(prompt::CheckError::IncorrectPassword(flatten_eof(err)))
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
        }
    }
}

pub(crate) struct CheckSkesks<'a> {
    skesks: &'a [SKESK],
    decrypt: &'a mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool,
    // The session key.  The usize is the index of the decrypted
    // SKESK.
    sk: Option<(usize, crypto::SessionKey)>,
}

impl<'a> CheckSkesks<'a> {
    pub fn new(skesks: &'a [SKESK],
               decrypt: &'a mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool)
        -> Self
    {
        Self {
            skesks,
            decrypt,
            sk: None,
        }
    }

    /// Returns the decrypted session key, if any.
    pub fn resolve(self) -> Option<(usize, crypto::SessionKey)> {
        self.sk
    }
}

impl prompt::Check<'_> for CheckSkesks<'_> {
    fn check(&mut self,
             _context: &mut prompt::Context,
             response: &prompt::Response)
        -> std::result::Result<(), prompt::CheckError>
    {
        match response {
            prompt::Response::Password(password) => {
                let mut err = None;
                for (i, skesk) in self.skesks.into_iter().enumerate() {
                    match skesk.decrypt(password) {
                        Ok((algo, sk)) => {
                            if (self.decrypt)(algo, &sk) {
                                self.sk = Some((i, sk));
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            if err.is_none() {
                                err = flatten_eof(e);
                            }
                        }
                    }
                }

                Err(prompt::CheckError::IncorrectPassword(err))
            }
            prompt::Response::NoPassword => {
                // Skip.
                Ok(())
            }
        }
    }
}

/// Checks a new password.
///
/// Don't place any restrictions on passwords, and accept everything
/// including the empty password.
pub(crate) struct CheckNewPassword {
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
