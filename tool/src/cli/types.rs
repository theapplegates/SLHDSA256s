//! Types used in the command-line parser.

use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Read;
use std::io::stdin;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::Result;

/// Common types for arguments of sq.
use clap::ValueEnum;

use sequoia::openpgp;
use openpgp::packet::UserID;

use sequoia::types::FileOrStdin;

pub mod cert_designator;
pub use cert_designator::CertDesignators;
pub mod key_designator;
pub use key_designator::KeyDesignators;
pub mod paths;
pub mod userid_designator;
pub use userid_designator::UserIDDesignators;
pub mod expiration;
pub use expiration::Expiration;
pub use expiration::ExpirationArg;
pub mod signature_notations;
pub use signature_notations::SignatureNotationsArg;
pub mod special_names;
pub use special_names::SpecialName;
pub mod version;
pub use version::Version;

// A local copy of the standard library's AsRef trait.
//
// We need a local copy of AsRef, as we need to implement AsRef for
// UserID, but due to the orphan rule, we can't.  Instead we have to
// make a local copy of AsRef or UserID.  Copying AsRef is less
// invasive.
pub trait MyAsRef<T>
where
    T: ?Sized,
{
    fn as_ref(&self) -> &T;
}

impl MyAsRef<UserID> for UserID {
    fn as_ref(&self) -> &UserID {
        self
    }
}

impl MyAsRef<UserID> for &UserID {
    fn as_ref(&self) -> &UserID {
        self
    }
}

/// A trait to provide const &str for clap annotations for custom structs
pub trait ClapData {
    /// The clap value name.
    const VALUE_NAME: &'static str;

    /// The clap help text for required arguments.
    ///
    /// Use this as the default help text if the value must be given.
    const HELP_REQUIRED: &'static str;

    /// The clap help text for optional arguments.
    ///
    /// Use this as the default help text if the value must not be
    /// given, because either:
    ///
    ///   - there is a default value, or
    ///   - the type is an `Option<T>`.
    const HELP_OPTIONAL: &'static str;
}

/// Reads from stdin, and prints a warning to stderr if no input is
/// read within a certain amount of time.
pub struct StdinWarning {
    do_warn: bool,
    /// The thing that is being waited for.  See `StdinWarning::emit`.
    thing: &'static str,
}

/// Print a warning if we don't get any input after this amount of
/// time.
const STDIN_TIMEOUT: Duration = std::time::Duration::new(2, 0);

impl StdinWarning {
    /// Emit a custom warning if no input is received.
    pub fn new(thing: &'static str) -> Self {
        Self {
            do_warn: true,
            thing,
        }
    }

    /// Emit a warning that a certificate is expected if no input is
    /// received.
    pub fn openpgp() -> Self {
        Self::new("OpenPGP data")
    }

    /// Emit a warning that certificates are expected if no input is
    /// received.
    pub fn certs() -> Self {
        Self::new("OpenPGP certificates")
    }

    pub fn emit(&self) {
        eprintln!("Waiting for {} on stdin...", self.thing);
    }
}

impl Read for StdinWarning {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if self.do_warn {
            if buf.len() == 0 {
                return Ok(0);
            }

            // We may warn the user.  We don't want to print the
            // warning if we read anything.  If we try to read two
            // bytes, we might read one byte, block, print the
            // warning, and then later read a second byte.  That's not
            // great.  Thus, we don't read more than a single byte.
            buf = &mut buf[..1];

            // Don't warn again.
            self.do_warn = false;

            thread::scope(|s| {
                let (sender, receiver) = mpsc::channel::<()>();

                s.spawn(move || {
                    if let Err(mpsc::RecvTimeoutError::Timeout)
                        = receiver.recv_timeout(STDIN_TIMEOUT)
                    {
                        self.emit();
                    }
                });

                let result = stdin().read(buf);
                // Force the thread to exit now.
                drop(sender);
                result
            })
        } else {
            stdin().read(buf)
        }
    }
}

impl ClapData for FileOrStdin {
    const VALUE_NAME: &'static str = "FILE";
    const HELP_OPTIONAL: &'static str =
        "Read from FILE or stdin if FILE is '-'";
    const HELP_REQUIRED: &'static str =
        "Read from FILE or stdin if omitted";
}

/// A type providing const strings for output to certstore by default
///
/// This struct is empty and solely used to provide strings to clap.
/// Use this in combination with a [`FileOrStdout`] if a CLI should allow output
/// to a file and if unset output to a cert store.
///
/// ## Examples
/// ```
/// use clap::Args;
///
/// #[derive(Debug, Args)]
/// #[clap(name = "example", about = "an example")]
/// pub struct Example {
///     #[clap(
///         help = FileOrCertStore::HELP_OPTIONAL,
///         long,
///         value_name = FileOrCertStore::VALUE_NAME,
///     )]
///     pub output: Option<FileOrStdout>,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrCertStore{}

impl ClapData for FileOrCertStore {
    const VALUE_NAME: &'static str = "FILE";
    const HELP_REQUIRED: &'static str
        = "Write to FILE (or stdout if FILE is '-') instead of \
          importing into the certificate store";
    const HELP_OPTIONAL: &'static str
        = "Write to FILE (or stdout when omitted) instead of \
          importing into the certificate store";
}

/// A type wrapping an optional PathBuf to use as stdout or file output
///
/// When creating `FileOrStdout` from `&str`, providing a `"-"` is interpreted
/// as `None`, i.e. output to stdout. Providing other strings is interpreted as
/// `Some(PathBuf)`, i.e. output to file.
/// Use this if a CLI should allow output to a file and if unset output to
/// stdout.
///
/// ## Examples
/// ```
/// use clap::Args;
///
/// #[derive(Debug, Args)]
/// #[clap(name = "example", about = "an example")]
/// pub struct Example {
///     #[clap(
///         default_value_t = FileOrStdout::default(),
///         help = FileOrStdout::HELP_OPTIONAL,
///         long,
///         value_name = FileOrStdout::VALUE_NAME,
///     )]
///     pub output: FileOrStdout,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrStdout {
    path: Option<PathBuf>,

    /// If set, secret keys may be written to this sink.
    for_secrets: bool,
}

impl ClapData for FileOrStdout {
    const VALUE_NAME: &'static str = "FILE";
    const HELP_REQUIRED: &'static str =
        "Write to FILE or stdout if FILE is '-'";
    const HELP_OPTIONAL: &'static str =
        "Write to FILE or stdout if omitted";
}

impl FileOrStdout {
    pub fn new(path: Option<PathBuf>) -> Self {
        FileOrStdout {
            path,
            ..Default::default()
        }
    }

    /// Indicates that we will emit secrets.
    ///
    /// Use this to mark outputs where we intend to emit secret keys.
    pub fn for_secrets(mut self) -> Self {
        self.for_secrets = true;
        self
    }

    /// Queries whether we are configured to emit secrets.
    pub fn is_for_secrets(&self) -> bool {
        self.for_secrets
    }

    /// Return a reference to the optional PathBuf
    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

}

impl Default for FileOrStdout {
    fn default() -> Self {
        FileOrStdout {
            path: None,
            for_secrets: false,
        }
    }
}

impl From<PathBuf> for FileOrStdout {
    fn from(value: PathBuf) -> Self {
        if value == PathBuf::from("-") {
            FileOrStdout::default()
        } else {
            FileOrStdout::new(Some(value))
        }
    }
}

impl From<Option<PathBuf>> for FileOrStdout {
    fn from(value: Option<PathBuf>) -> Self {
        if let Some(path) = value {
            FileOrStdout::from(path)
        } else {
            FileOrStdout::default()
        }
    }
}

impl FromStr for FileOrStdout {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if "-" == s {
            Ok(FileOrStdout::default())
        } else {
            Ok(FileOrStdout::new(Some(PathBuf::from(s))))
        }
    }
}

impl Display for FileOrStdout {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{}", path.display()),
            None => write!(f, "-"),
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum ArmorKind {
    Auto,
    Message,
    #[clap(name = "cert")]
    PublicKey,
    #[clap(name = "key")]
    SecretKey,
    #[clap(name = "sig")]
    Signature,
    File,
}

impl From<ArmorKind> for Option<openpgp::armor::Kind> {
    fn from(c: ArmorKind) -> Self {
        match c {
            ArmorKind::Auto => None,
            ArmorKind::Message => Some(openpgp::armor::Kind::Message),
            ArmorKind::PublicKey => Some(openpgp::armor::Kind::PublicKey),
            ArmorKind::SecretKey => Some(openpgp::armor::Kind::SecretKey),
            ArmorKind::Signature => Some(openpgp::armor::Kind::Signature),
            ArmorKind::File => Some(openpgp::armor::Kind::File),
        }
    }
}
