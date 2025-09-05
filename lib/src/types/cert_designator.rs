//! Types used in the command-line parser.

use std::fmt::Display;
use std::fmt::Formatter;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use anyhow::Result;

use sequoia_openpgp::parse::buffered_reader::BufferedReader;
use sequoia_openpgp::parse::buffered_reader::File;
use sequoia_openpgp::parse::buffered_reader::Generic;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::parse::Cookie;

use crate::transitional::stdin::StdinWarning;

/// A type wrapping an optional PathBuf to use as stdin or file input
///
/// When creating `FileOrStdin` from `&str`, providing a `"-"` is interpreted
/// as `None`, i.e. read from stdin. Providing other strings is interpreted as
/// `Some(PathBuf)`, i.e. read from file.
/// Use this if a CLI should allow input from a file and if unset from stdin.
///
/// ## Examples
/// ```no_compile
/// use clap::Args;
/// use sequoia::types::FileOrStdin;
///
/// #[derive(Debug, Args)]
/// #[clap(name = "example", about = "an example")]
/// pub struct Example {
///     #[clap(
///         default_value_t = FileOrStdin::default(),
///         help = "Read from FILE or stdin if FILE is '-'",
///         value_name = "FILE",
///     )]
///     pub input: FileOrStdin,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrStdin(Option<PathBuf>);

impl FileOrStdin {
    pub fn new(path: Option<PathBuf>) -> Self {
        FileOrStdin(path)
    }

    /// Return a reference to the inner type
    pub fn inner(&self) -> Option<&PathBuf> {
        self.0.as_ref()
    }

    /// Returns `None` if `self.0` is `None`, otherwise calls f with the wrapped
    /// value and returns the result
    pub fn and_then<U, F>(self, f: F) -> Option<U>
    where
        F: FnOnce(PathBuf) -> Option<U>,
    {
        self.0.and_then(|x| f(x))
    }

    /// Get a boxed BufferedReader for the FileOrStdin
    ///
    /// Opens a file if there is Some(PathBuf), else opens stdin.
    ///
    /// `thing` is the thing that we expect to read, e.g., "OpenPGP
    /// certificates" or "a signed message".
    pub fn open<'a>(&self, thing: &'static str)
        -> Result<Box<dyn BufferedReader<Cookie> + 'a>>
    {
        if let Some(path) = self.inner() {
            Ok(Box::new(
                File::with_cookie(path, Default::default())
                .with_context(|| format!("Failed to open {}", self))?))
        } else {
            Ok(Box::new(
                Generic::with_cookie(
                    StdinWarning::new(thing), None, Default::default())))
        }
    }

    /// Return a reference to the optional PathBuf.
    pub fn path(&self) -> Option<&PathBuf> {
        self.0.as_ref()
    }
}

impl Default for FileOrStdin {
    fn default() -> Self {
        FileOrStdin(None)
    }
}

impl From<PathBuf> for FileOrStdin {
    fn from(value: PathBuf) -> Self {
        if value == PathBuf::from("-") {
            FileOrStdin::default()
        } else {
            FileOrStdin::new(Some(value))
        }
    }
}

impl From<Option<PathBuf>> for FileOrStdin {
    fn from(value: Option<PathBuf>) -> Self {
        if let Some(path) = value {
            FileOrStdin::from(path)
        } else {
            FileOrStdin::default()
        }
    }
}

impl From<&Path> for FileOrStdin {
    fn from(value: &Path) -> Self {
        if Path::new("-") == value {
            FileOrStdin::default()
        } else {
            FileOrStdin::from(value.to_owned())
        }
    }
}

impl From<Option<&Path>> for FileOrStdin {
    fn from(value: Option<&Path>) -> Self {
        if let Some(path) = value {
            FileOrStdin::from(path)
        } else {
            FileOrStdin::default()
        }
    }
}

impl FromStr for FileOrStdin {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if "-" == s {
            Ok(FileOrStdin(None))
        } else {
            Ok(FileOrStdin(Some(PathBuf::from(s))))
        }
    }
}

impl Display for FileOrStdin {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match &self.0 {
            None => write!(f, "-"),
            Some(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Designates a certificate by path, by stdin, or by key handle.
///
/// Use [`Sequoia::lookup_one`](crate::Sequoia::lookup_one) to read
/// the certificate.
#[derive(Clone, Debug)]
pub enum FileStdinOrKeyHandle {
    FileOrStdin(FileOrStdin),
    KeyHandle(KeyHandle),
}

impl From<FileOrStdin> for FileStdinOrKeyHandle {
    fn from(file: FileOrStdin) -> Self {
        FileStdinOrKeyHandle::FileOrStdin(file)
    }
}

impl From<&str> for FileStdinOrKeyHandle {
    fn from(path: &str) -> Self {
        PathBuf::from(path).into()
    }
}

impl From<&Path> for FileStdinOrKeyHandle {
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

impl From<PathBuf> for FileStdinOrKeyHandle {
    fn from(path: PathBuf) -> Self {
        FileStdinOrKeyHandle::FileOrStdin(path.into())
    }
}

impl From<&KeyHandle> for FileStdinOrKeyHandle {
    fn from(kh: &KeyHandle) -> Self {
        FileStdinOrKeyHandle::KeyHandle(kh.clone())
    }
}

impl From<KeyHandle> for FileStdinOrKeyHandle {
    fn from(kh: KeyHandle) -> Self {
        FileStdinOrKeyHandle::KeyHandle(kh)
    }
}

impl FileStdinOrKeyHandle {
    /// Returns whether this contains a `FileOrStdin`.
    pub fn is_file(&self) -> bool {
        match self {
            FileStdinOrKeyHandle::FileOrStdin(_) => true,
            FileStdinOrKeyHandle::KeyHandle(_) => false,
        }
    }

    /// Returns whether this contains a `KeyHandle`.
    pub fn is_key_handle(&self) -> bool {
        match self {
            FileStdinOrKeyHandle::FileOrStdin(_) => false,
            FileStdinOrKeyHandle::KeyHandle(_) => true,
        }
    }
}
