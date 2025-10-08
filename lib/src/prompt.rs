//! User prompting.

use std::borrow::Cow;
use std::time::SystemTime;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyID;
use openpgp::crypto::Password;
use openpgp::policy::Policy;

use crate::STANDARD_POLICY;
use crate::Sequoia;
use crate::types::Convert;

pub(crate) mod check;

/// Prompt-specific errors.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Password prompting has been disabled.
    ///
    /// The caller is allowed to interpret this return code to mean
    /// that it shouldn't prompt for passwords in other contexts as
    /// well.
    #[error("Password prompting is disabled")]
    Disabled(Option<String>),

    /// The user cancelled the prompt.
    ///
    /// The caller should not prompt for this password again.
    #[error("The user cancelled the operation")]
    Cancelled(Option<String>),

    /// The application closed the prompt asynchronously.
    ///
    /// An implementation of [`Prompt::prompt`] should return this in
    /// response to [`Prompt::close`].
    #[error("The application closed the prompt")]
    Closed(Option<String>),

    /// Another error.
    ///
    /// This allows the caller to return arbitrary errors.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// Returns whether this variant is `Error::Disabled`.
    pub fn is_disabled(&self) -> bool {
        matches!(self, Error::Disabled(_))
    }

    /// Returns whether this variant is `Error::Cancelled`.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Error::Cancelled(_))
    }

    /// Returns whether this variant is `Error::Closed`.
    pub fn is_closed(&self) -> bool {
        matches!(self, Error::Closed(_))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Other(anyhow::Error::from(err))
    }
}

/// The reason for the prompt.
///
/// If a caller doesn't understand a reason, they should use
/// [`Context::prompt`] to get a reasonable prompt.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// A password is needed to decrypt a symmetrically encrypted
    /// message.
    DecryptMessage,

    /// A password is needed to symmetrically encrypt a message.
    EncryptMessage,

    /// A password is needed to unlock a key.
    UnlockKey,

    /// A password is needed to encrypt all keys on a certificate.
    LockCert,

    /// A password is needed to encrypt all keys on a new certificate.
    LockNewCert,

    /// A password is needed to encrypt a single key on a certificate.
    LockKey,

    /// A password is needed to encrypt a single new key on a
    /// certificate.
    LockNewKey,
}

impl Reason {
    /// Whether the caller is trying to lock something.
    pub fn locking(&self) -> bool {
        matches!(self,
                 Reason::EncryptMessage
                 | Reason::LockCert
                 | Reason::LockNewCert
                 | Reason::LockKey
                 | Reason::LockNewKey)
    }

    /// Whether the caller is trying to unlock something.
    pub fn unlocking(&self) -> bool {
        ! self.locking()
    }

    /// Whether the password is optional.
    ///
    /// This is the case when prompting for a new password for a
    /// certificate or key.  In these cases, a password is optional.
    pub fn optional(&self) -> bool {
        matches!(self,
                 Reason::LockCert
                 | Reason::LockNewCert
                 | Reason::LockKey
                 | Reason::LockNewKey)
    }

    /// Whether the user should confirm the password.
    ///
    /// New passwords should be confirmed by, for example, having the
    /// user enter them twice.
    pub fn confirm(&self) -> bool {
        self.locking()
    }
}

/// The action.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Prompt for a password.
    Password,

    /// Prompt the user to attach a token.
    Attach,

    /// Prompt the user to touch a token.
    Touch,

    /// Prompt the user to enter a PIN directly on a token.
    ExternalPassword,
}

impl Action {
    /// Whether to prompt for a password.
    pub fn password(&self) -> bool {
        matches!(self, Action::Password)
    }

    /// Whether to wait for the user to ack the message.
    pub fn ack(&self) -> bool {
        ! self.password()
    }
}

/// The number of remaining tries before the object is locked.
///
/// This is normally only relevant when the object is stored on a
/// hardware security module.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemainingTries {
    /// The object will never be locked due to too many unlock
    /// attempts.
    Unlimited,

    /// The number of unlock attempts before the object is lock.
    ///
    /// This is normally only relevant when the object is stored on a
    /// hardware security module.
    Count(usize),

    /// The number of unlock attempts is unknown, but if the next
    /// unlock attempt fails it will not lock the object.
    ///
    /// This is normally only relevant when the object is stored on a
    /// hardware security module.
    AtLeastTwo,

    /// The number of unlock attempts is unknown, and if the next
    /// unlock attempt fails it may lock the object.
    ///
    /// This is normally only relevant when the object is stored on a
    /// hardware security module.
    Unknown,
}

/// Description of a token like a YubiKey.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    id: String,
}

/// The context for which the prompt is required.
///
/// The optional meta-parameter `T` allows you to attach
/// context-specific data directly to the context.
#[non_exhaustive]
#[derive(Clone)]
pub struct Context<'a, T=()> {
    reason: Reason,
    action: Action,
    sequoia: Option<&'a Sequoia>,
    cert: Option<Cow<'a, Cert>>,
    key: Option<Fingerprint>,
    token: Option<Token>,
    remaining_tries: RemainingTries,
    cookie: T,
}

impl<'a, T> Context<'a, T> {
    /// Returns a reasonable title for the given the context.
    ///
    /// The title should be relatively short (less than 40 characters)
    /// and can be used as the title for a window.
    pub fn title(&self) -> String {
        match self.action {
            Action::Password => "Enter a Password".into(),
            Action::Attach => "Attach a Token".into(),
            Action::Touch => "Touch Your Token".into(),
            Action::ExternalPassword => "Enter a Password".into(),
        }
    }

    /// Returns a reasonable prompt given the context.
    ///
    /// The prompt is a phrase that succinctly communicates what is
    /// needed and why.  Despite being succinct, the text may need to
    /// be line wrapped.  The returned string does not end in any
    /// punctuation.
    pub fn prompt(&self) -> String {
        let meta = |policy: &dyn Policy, time: Option<SystemTime>,
                    cert: &Cert, key: &Fingerprint|
        {
            let Ok(vc) = cert.with_policy(policy, time) else {
                return Cow::Borrowed("");
            };

            let Some(key) = vc.keys()
                .find(|k| &k.key().fingerprint() == key)
            else {
                return Cow::Borrowed("");
            };

            let creation_time = key.key().creation_time().convert();

            if let Some(flags) = key.key_flags() {
                let mut s = Vec::new();
                if flags.for_certification() {
                    s.push("certifying");
                }
                if flags.for_signing() {
                    s.push("signing");
                }
                if flags.for_storage_encryption()
                    && flags.for_transport_encryption()
                {
                    s.push("encryption");
                } else if flags.for_storage_encryption() {
                    s.push("storage encryption");
                } else if flags.for_transport_encryption() {
                    s.push("transport encryption");
                }
                if ! s.is_empty() {
                    Cow::Owned(format!(", created {} for {}",
                                       creation_time, s.join(", ")))
                } else {
                    Cow::Owned(format!(", created {}", creation_time))
                }
            } else {
                Cow::Owned(format!(", created {}", creation_time))
            }
        };

        let desc = |prefix: &str, fallback: &str| {
            match (self.sequoia, self.cert.as_ref(), self.key.as_ref()) {
                (Some(sq), Some(cert), Some(key))
                    if &cert.fingerprint() != key =>
                {
                    let uid = sq.best_userid(cert, true);
                    format!("{}{}/{} {}{}",
                            prefix, cert.fingerprint(), KeyID::from(key),
                            uid.display(),
                            meta(sq.policy(), Some(sq.time()),
                                 cert, key))
                }
                (None, Some(cert), Some(key))
                    if &cert.fingerprint() != key =>
                {
                    let uid = Sequoia::self_userid(
                        STANDARD_POLICY, None, cert);
                    format!("{}{}/{} {}{}",
                            prefix, cert.fingerprint(), KeyID::from(key),
                            uid.display(),
                            meta(STANDARD_POLICY, None, cert, key))
                }
                (Some(sq), Some(cert), _) => {
                    let uid = sq.best_userid(cert, true);
                    format!("{}{} {}, created {}",
                            prefix, cert.fingerprint(),
                            uid.display(),
                            cert.primary_key().key().creation_time().convert())
                }
                (None, Some(cert), _) => {
                    let uid = Sequoia::self_userid(
                        STANDARD_POLICY, None, cert);
                    format!("{}{} {}, created {}",
                            prefix, cert.fingerprint(),
                            uid.display(),
                            cert.primary_key().key().creation_time().convert())
                }
                (_, None, Some(key)) => {
                    format!("{}{}", prefix, KeyID::from(key))
                }
                _ => fallback.into(),
            }
        };

        match self.reason {
            Reason::DecryptMessage =>
                "Enter a password used to encrypt the message".into(),
            Reason::EncryptMessage =>
                "Enter a password to encrypt the message".into(),
            Reason::LockCert => {
                format!(
                    "Enter a password to protect the certificate{}",
                    desc(" ", ""))
            }
            Reason::LockNewCert => {
                "Enter a password to protect the new certificate".into()
            }
            Reason::LockKey => {
                format!(
                    "Enter a password to protect the key{}",
                    desc(" ", ""))
            }
            Reason::LockNewKey => {
                "Enter a password to protect the new key".into()
            }
            Reason::UnlockKey => {
                let the_key = desc("", "the key");
                let the_token = self.token()
                    .map(|token| {
                        Cow::Owned(format!("the token {}", token.id))
                    })
                    .unwrap_or_else(|| Cow::Borrowed("the token"));

                match self.action {
                    Action::Password => {
                        if self.token().is_some() {
                            format!("Enter the password to unlock {} on {}",
                                    the_key, the_token)
                        } else {
                            format!("Enter the password to unlock {}",
                                    the_key)
                        }
                    }
                    Action::Attach =>
                        format!("Attach {} with {}",
                                the_token, the_key),
                    Action::Touch =>
                        format!("Touch {} with {}",
                                the_token, the_key),
                    Action::ExternalPassword =>
                        format!("Enter the PIN on {} with {}",
                                the_token, the_key),
                }
            }
        }
    }

    /// Returns a longer explanation of the context.
    ///
    /// This includes details about the context, and may be multiple
    /// lines.  The caller may need to wrap the text.  Newlines should
    /// be treated as new paragraphs.  The user should not need this
    /// to understand the password prompt.
    pub fn about(&self) -> Option<&str> {
        None
    }

    /// Returns the reason.
    pub fn reason(&self) -> Reason {
        self.reason.clone()
    }

    /// Returns the action.
    pub fn action(&self) -> Action {
        self.action.clone()
    }

    /// Returns the certificate, if any.
    pub fn cert(&'a self) -> Option<&'a Cert> {
        match self.cert {
            Some(Cow::Owned(ref c)) => Some(c),
            Some(Cow::Borrowed(c)) => Some(c),
            None => None
        }
    }

    /// Returns the key, if any.
    pub fn key(&self) -> Option<&Fingerprint> {
        self.key.as_ref()
    }

    /// Returns the associated token, if any.
    pub fn token(&self) -> Option<&Token> {
        self.token.as_ref()
    }

    /// Returns the number of remaining tries until the object is
    /// locked.
    pub fn remaining_tries(&self) -> &RemainingTries {
        &self.remaining_tries
    }

    /// Sets the number of remaining tries until the object is locked.
    pub fn set_remaining_tries(&mut self, remaining_tries: RemainingTries) {
        self.remaining_tries = remaining_tries
    }

    /// Returns a reference to the cookie.
    pub fn cookie(&self) -> &T {
        &self.cookie
    }

    /// Returns a mutable reference to the cookie.
    pub fn cookie_mut(&mut self) -> &mut T {
        &mut self.cookie
    }
}

/// The context in which a password is prompted.
pub struct ContextBuilder<'a, T=()> {
    context: Context<'a, T>,
}

impl<'a> ContextBuilder<'a, ()> {
    /// Returns a new prompt context builder.
    pub fn new(action: Action, reason: Reason) -> Self {
        ContextBuilder::with_cookie(action, reason, ())
    }

    /// Returns a new prompt context builder that will prompt for a
    /// password.
    pub fn password(reason: Reason) -> Self {
        ContextBuilder::with_cookie(Action::Password, reason, ())
    }
}

impl<'a, T> ContextBuilder<'a, T> {
    /// Returns a new prompt context builder with a caller-specified
    /// cookie.
    pub fn with_cookie(action: Action, reason: Reason, cookie: T) -> Self {
        ContextBuilder {
            context: Context {
                action,
                reason,
                sequoia: None,
                cert: None,
                key: None,
                token: None,
                remaining_tries: RemainingTries::Unknown,
                cookie,
            }
        }
    }

    /// Sets the Sequoia instance.
    ///
    /// This is optional: it only used for decorative purposes when
    /// generating the prompt.
    pub fn sequoia(mut self, sequoia: &'a Sequoia) -> Self {
        self.context.sequoia = Some(sequoia);

        self
    }

    /// Sets the certificate as the certificate relevant to the
    /// password prompt.
    ///
    /// Normally, this is only set when unlocking a key on a
    /// certificate.
    pub fn cert(mut self, cert: Cow<'a, Cert>) -> Self {
        self.context.cert = Some(cert);

        self
    }

    /// Sets the key as the key relevant to the password prompt.
    ///
    /// Normally, this is only set when unlocking a key.
    pub fn key(mut self, key: Fingerprint) -> Self {
        self.context.key = Some(key);

        self
    }

    /// Sets the associated token.
    pub fn token(mut self, token: Token) -> Self {
        self.context.token = Some(token);

        self
    }

    /// Returns a password prompt context.
    pub fn build(self) -> Context<'a, T> {
        self.context
    }
}

/// The response to a prompt.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Response {
    /// A password.
    ///
    /// This can be returned when the action is [`Action::Password`].
    Password(Password),

    /// No password.
    ///
    /// This can be returned when the action is [`Action::Password`].
    /// This should only be returned when password protecting a
    /// certificate or key; it doesn't make sense when unlocking a
    /// password-protected object.
    ///
    /// This can also be returned when the action is
    /// [`Action::Attach`], [`Action::Touch`], or
    /// [`Action::ExternalPassword`] to indicate that the user
    /// acknowledged the prompt.
    NoPassword,
}

/// Errors returned by `Check`.
///
/// The errors that need to be returned by an implementation of
/// [`Check`].
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum CheckError {
    /// The password is incorrect.
    #[error("Incorrect password{}.",
            if let Some(err) = .0.as_ref() {
                Cow::Owned(format!(": {}", err))
            } else {
                Cow::Borrowed("")
            })]
    IncorrectPassword(Option<anyhow::Error>),

    /// A password was not provided, but one is required.
    #[error("You must enter a password to continue{}.",
            if let Some(err) = .0.as_ref() {
                Cow::Owned(format!(": {}", err))
            } else {
                Cow::Borrowed("")
            })]
    PasswordRequired(Option<anyhow::Error>),

    /// The password is invalid.
    ///
    /// This indicates that the password doesn't conform to the
    /// password policy.
    #[error("Invalid password{}.",
            if let Some(err) = .0.as_ref() {
                Cow::Owned(format!(": {}", err))
            } else {
                Cow::Borrowed("")
            })]
    InvalidPassword(Option<anyhow::Error>),

    /// Another error.
    ///
    /// This allows the caller to return arbitrary errors.  This
    /// causes the prompt to immediately abort, and propagate the
    /// error to the caller.  As such, this needs to be used with
    /// care.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Checks that a password is acceptable or correct.
///
/// When prompting for a new password, this checks that the password
/// has the desired properties (e.g., length).  If it doesn't, then
/// the implementation should return [`CheckError::InvalidPassword`].
///
/// When unlocking something, this attempts to unlock the object.  If
/// it fails, it should return [`CheckError::IncorrectPassword`].
/// Since you've unlocked the thing, you should probably also store it
/// so you don't have to unlock it a second time.  A convenient place
/// to put it is in your `Check` struct.  If the user does not enter a
/// password, but a password is required, return
/// [`CheckError::PasswordRequired`].
///
/// Note: The `Check` implementation is not responsible for the
/// presentation; all presentation logic should be in the `Prompt`
/// implementation.
pub trait Check<'a, T=()> {
    /// Returns whether the response is acceptable for the given
    /// context.
    fn check(&mut self, context: &mut Context<'a, T>, response: &Response)
        -> std::result::Result<(), CheckError>;
}

/// An implementation of `Check` that accepts all passwords as well as
/// no password.
pub struct AcceptAll {
}

impl AcceptAll {
    /// Returns a new instance of `AcceptAll`.
    pub fn new() -> Self {
        Self {
        }
    }
}

impl<'a, T> Check<'a, T> for AcceptAll {
    fn check(&mut self, _context: &mut Context<'a, T>, _response: &Response)
        -> std::result::Result<(), CheckError>
    {
        Ok(())
    }
}

/// The prompting interface.
pub trait Prompt<T=()> {
    /// Returns a password for the specified context.
    ///
    /// Normally the password is obtained by prompting the user.  If
    /// prompting is disabled, this should return [`Error::Disabled`].
    ///
    /// If `context.reason().confirm()` is true, then the user should
    /// confirm that the password is correct.  This is usually done by
    /// prompting for the same password a second time.
    ///
    /// Before returning, the function must call `check.check`.  If
    /// the function returns `Ok`, it should return the response.  If
    /// it returns a [`CheckError`] error, it should display error and
    /// loop, or propagate the error to the caller, as appropriate.
    /// When a password requires confirmation, `check.check` should
    /// only be called after the password has been confirmed.
    fn prompt<'a>(&self, context: &mut Context<'a, T>,
                  check: &mut dyn Check<'a, T>)
        -> std::result::Result<Response, Error>;

    /// Returns a password for one of the the specified contexts.
    ///
    /// Sometimes there are multiple ways to access an object.  For
    /// instance, when decrypting a message, the session key may be
    /// encrypted with a password, and a password protected public
    /// key.  This interface allows the user to choose which one to
    /// try.
    ///
    /// The default implementation iterates over the contexts and
    /// calls [`Prompt::prompt`] on each.  It returns the context and
    /// the password for the first prompt to which the user provides a
    /// password.  If `Prompt::prompt` returns [`Error::Cancelled`],
    /// `Prompt::prompt` is called on the next context.  If
    /// `Prompt::prompt` returns [`Error::Disabled`], that result is
    /// propagated immediately.  If `Prompt::prompt` another error via
    /// [`Error::Other`], that error is returned immediately.
    ///
    /// A more sophisticated implementation would show a single dialog
    /// that allows the user to select the context they want to
    /// provide the password for.
    ///
    /// See [`Prompt::prompt`] for more details.
    fn multiprompt<'a, 'c>(&self, contexts: &'c mut [Context<'a, T>],
                           check: &mut dyn Check<'a, T>)
        -> std::result::Result<(&'c Context<'a, T>, Response), Error>
    {
        for context in contexts.iter_mut() {
            match self.prompt(context, check) {
                Ok(password) => {
                    return Ok((context, password));
                }
                Err(Error::Cancelled(_)) => {
                    continue;
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        Err(Error::Cancelled(None))
    }

    /// Indicates that the prompt should abort.
    ///
    /// The implementation should close the prompt dialog, and
    /// [`Prompt::prompt`] should return [`Error::Closed`].
    ///
    /// This can be called when the application needs a token.  It
    /// first calls [`Prompt::prompt`] to prompt the user to insert
    /// the token.  If the application detects that the token has
    /// become available, it can call this to close the prompt thereby
    /// saving the user a click.
    ///
    /// The default implementation ignores this.
    ///
    /// # Examples
    ///
    /// Use an [`mpsc::channel`] to send the close message to the
    /// prompt:
    ///
    /// [`mpsc::channel`]: https://doc.rust-lang.org/stable/std/sync/mpsc/index.html
    ///
    /// ```
    /// use std::sync::mpsc;
    /// use std::sync::Mutex;
    ///
    /// use sequoia::prompt;
    /// use sequoia::prompt::Prompt as _;
    ///
    /// struct MyPrompt {
    ///     sender: mpsc::Sender<()>,
    ///     receiver: Mutex<mpsc::Receiver<()>>,
    /// }
    ///
    /// impl prompt::Prompt for MyPrompt {
    ///     fn prompt(&self, _context: &mut prompt::Context,
    ///               _check: &mut dyn prompt::Check)
    ///         -> std::result::Result<prompt::Response, prompt::Error>
    ///     {
    ///         let timeout = std::time::Duration::new(10, 0);
    ///         match self.receiver.lock().unwrap().recv_timeout(timeout) {
    ///             Err(_) => {
    ///                 // Timeout.
    ///                 Err(prompt::Error::Cancelled(None))
    ///             }
    ///             Ok(()) => {
    ///                 Err(prompt::Error::Closed(None))
    ///             }
    ///         }
    ///     }
    ///
    ///     fn close(&self) {
    ///         self.sender.send(()).unwrap();
    ///     }
    /// }
    ///
    /// let (sender, receiver) = mpsc::channel();
    /// let prompt = MyPrompt {
    ///     sender,
    ///     receiver: Mutex::new(receiver),
    /// };
    ///
    /// std::thread::scope(|s| {
    ///     // Don't move prompt into the thread.
    ///     let prompt_ref = &prompt;
    ///     let th = s.spawn(|| {
    ///         let mut context = prompt::ContextBuilder::new(
    ///             prompt::Action::Attach, prompt::Reason::UnlockKey)
    ///             .build();
    ///
    ///         let mut checker = prompt::AcceptAll::new();
    ///
    ///         prompt_ref.prompt(&mut context, &mut checker)
    ///     });
    ///
    ///     prompt.close();
    ///
    ///     let result = th.join().unwrap();
    ///     assert!(matches!(result, Err(prompt::Error::Closed(_))));
    /// })
    /// ```
    fn close(&self) {
    }
}

impl<'b, T> Prompt<T> for Box<dyn Prompt<T> + 'b> {
    fn prompt<'a>(&self, context: &mut Context<'a, T>, check: &mut dyn Check<'a, T>)
        -> std::result::Result<Response, Error>
    {
        self.as_ref().prompt(context, check)
    }

    fn multiprompt<'a, 'c>(&self, contexts: &'c mut [Context<'a, T>],
                           check: &mut dyn Check<'a, T>)
        -> std::result::Result<(&'c Context<'a, T>, Response), Error>
    {
        self.as_ref().multiprompt(contexts, check)
    }

    fn close(&self) {
        self.as_ref().close()
    }
}

impl<'b, T, P> Prompt<T> for &P
where
    P: Prompt<T> + 'b
{
    fn prompt<'a>(&self, context: &mut Context<'a, T>, check: &mut dyn Check<'a, T>)
        -> std::result::Result<Response, Error>
    {
        (*self).prompt(context, check)
    }

    fn multiprompt<'a, 'c>(&self, contexts: &'c mut [Context<'a, T>],
                           check: &mut dyn Check<'a, T>)
        -> std::result::Result<(&'c Context<'a, T>, Response), Error>
    {
        (*self).multiprompt(contexts, check)
    }

    fn close(&self) {
        (*self).close()
    }
}

/// An implementation of `Prompt` that always cancels.
///
/// This is useful when the program is operating in batch mode.
pub struct Cancel {
}

impl Cancel {
    /// Returns a new instance of `Cancel`.
    pub fn new() -> Self {
        Cancel {
        }
    }
}

impl<T> Prompt<T> for Cancel {
    fn prompt(&self, _context: &mut Context<T>, _check: &mut dyn Check<T>)
        -> std::result::Result<Response, Error>
    {
        Err(Error::Cancelled(None))
    }
}
