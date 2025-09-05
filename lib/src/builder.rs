use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::Clock;
use crate::Result;
use crate::Sequoia;
use crate::StateDirectory;
use crate::config::ConfigFile;
use crate::openpgp;

enum Home {
    /// Use the default home directory.
    Default,
    /// Use the specified home directory.
    Home(Cow<'static, sequoia_directories::Home>),
    /// Operate in stateless mode.
    Stateless,
}

/// A builder to configure a `Sequoia` context.
///
///
/// # Examples
///
/// Create a [`Sequoia`] context using the default home directory:
///
/// ```rust
/// use sequoia::SequoiaBuilder;
///
/// # fn main() -> anyhow::Result<()> {
///
/// let sequoia = SequoiaBuilder::new()
///     .build()?;
/// # Ok(()) }
/// ```
pub struct SequoiaBuilder {
    /// The home directory.
    home: Home,

    /// The OpenPGP policy's reference time.
    ///
    /// See [`StandardPolicy::at`] for details.
    ///
    /// [`StandardPolicy::at`]: https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/policy/struct.StandardPolicy.html#method.at
    policy_as_of: Option<SystemTime>,

    /// The current time.
    time: Clock,

    /// Overrides the path to the cert store.
    cert_store_path: Option<crate::types::StateDirectory>,

    /// Additional keyrings to read.
    keyrings: Vec<PathBuf>,

    /// Overrides the path to the key store.
    key_store_path: Option<crate::types::StateDirectory>,

    /// Additional trust roots.
    trust_roots: Vec<openpgp::Fingerprint>,

    /// Path to our IPC servers.
    ipc_server_path: PathBuf,
}

impl SequoiaBuilder {
    /// Returns a new `SequoiaBuilder`.
    pub fn new() -> Self {
        SequoiaBuilder {
            home: Home::Default,
            policy_as_of: None,
            time: Default::default(),
            cert_store_path: Default::default(),
            keyrings: Default::default(),
            key_store_path: Default::default(),
            trust_roots: Default::default(),
            ipc_server_path:
            PathBuf::from(option_env!("PREFIX").unwrap_or("/usr/local"))
                .join("libexec").join("sequoia"),
        }
    }

    /// Override the home directory.
    ///
    /// # Examples
    ///
    /// Create a [`Sequoia`] context that uses an ephemeral home
    /// directory:
    ///
    /// ```rust
    /// use sequoia::SequoiaBuilder;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// # let tempdir = tempfile::tempdir()?;
    /// # let alt_home = tempdir.path();
    ///
    /// let sequoia = SequoiaBuilder::new()
    ///     .home_directory(alt_home)?
    ///     .build()?;
    /// assert!(sequoia.home().is_some());
    /// # Ok(()) }
    /// ```
    pub fn home_directory<P>(&mut self, directory: P) -> Result<&mut Self>
    where P: AsRef<Path>
    {
        let directory = directory.as_ref();

        let home = sequoia_directories::Home::new(
            Some(directory.to_path_buf()))?;

        self.home = Home::Home(Cow::Owned(home));

        Ok(self)
    }

    /// Override the home directory.
    pub fn home(&mut self, home: sequoia_directories::Home) -> &mut Self {
        self.home = Home::Home(Cow::Owned(home));

        self
    }

    /// Uses an ephemeral home directory.
    ///
    /// Configure the [`Sequoia`] context to use an ephemeral home
    /// directory.  When the context is destroyed, the ephemeral home
    /// directory is removed.
    pub fn ephemeral(&mut self) -> Result<&mut Self> {
        self.home = Home::Home(Cow::Owned(
            sequoia_directories::Home::ephemeral()?));

        Ok(self)
    }

    /// Enables stateless mode.
    ///
    /// This disables the home directory, which causes the `Sequoia`
    /// instance to operate in stateless mode.
    ///
    /// # Examples
    ///
    /// Create a [`Sequoia`] context that operates in stateless mode
    /// (i.e., without a home directory):
    ///
    /// ```rust
    /// use sequoia::SequoiaBuilder;
    ///
    /// # fn main() -> anyhow::Result<()> {
    ///
    /// let sequoia = SequoiaBuilder::new()
    ///     .stateless()
    ///     .build()?;
    /// assert!(sequoia.home().is_none());
    /// # Ok(()) }
    /// ```
    pub fn stateless(&mut self) -> &mut Self {
        self.home = Home::Stateless;

        self
    }

    /// Overrides the cert store location.
    pub fn cert_store_path(&mut self, p: StateDirectory) -> &mut Self {
        self.cert_store_path = Some(p);
        self
    }

    /// Overrides the key store location.
    pub fn key_store_path(&mut self, p: StateDirectory) -> &mut Self {
        self.key_store_path = Some(p);
        self
    }

    /// Adds the given keyring to Sequoia's virtual cert store.
    pub fn add_keyring<P>(&mut self, p: P) -> &mut Self
    where
        P: AsRef<Path>,
    {
        self.keyrings.push(p.as_ref().to_path_buf());
        self
    }

    /// Adds the given fingerprint as trust root.
    pub fn add_trust_root(&mut self, fp: openpgp::Fingerprint) -> &mut Self {
        self.trust_roots.push(fp);
        self
    }

    /// Sets the policy's reference time accordingly.
    ///
    /// `at` is a meta-parameter that selects a security profile that
    /// is appropriate for the given point in time.
    ///
    /// See [`StandardPolicy::at`] for more details.
    ///
    ///   [`StandardPolicy::at`]: https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/policy/struct.StandardPolicy.html#method.at
    pub fn policy_as_of<T>(&mut self, at: T) -> &mut Self
    where
        T: Into<SystemTime>
    {
        self.policy_as_of = Some(at.into());

        self
    }

    /// Fixes the time at the current time.
    pub fn fix_time(&mut self) -> &mut Self {
        self.time = Clock::Frozen(SystemTime::now());
        self
    }

    /// Fixes the time at the given time.
    pub fn fix_time_at(&mut self, t: SystemTime) -> &mut Self {
        self.time = Clock::Fix(t);
        self
    }

    /// Sets the path to the IPC servers.
    pub fn ipc_server_path<P>(&mut self, p: P) -> &mut Self
    where
        P: AsRef<Path>,
    {
        self.ipc_server_path = p.as_ref().into();
        self
    }

    /// Instantiate a new context based on the builder's
    /// configuration.
    pub fn build(&self) -> Result<Sequoia> {
        let home = match &self.home {
            Home::Default => {
                let home = sequoia_directories::Home::default()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Platform does not have any known \
                                         default directories.")
                    })?;
                Some(Cow::Borrowed(home))
            }
            Home::Home(home) => Some(home.clone()),
            Home::Stateless => None,
        };

        let config_file = if let Some(home) = home.as_deref() {
            ConfigFile::parse_home(home)?
        } else {
            ConfigFile::default()
        };
        let config = if let Some(at) = self.policy_as_of {
            config_file.config_policy_as_of(at)?
        } else {
            config_file.config()?
        };

        Ok(Sequoia {
            home,
            config_file,
            config,
            time: self.time.clone(),
            cert_store_path: self.cert_store_path.clone(),
            cert_store: Default::default(),
            keyrings: self.keyrings.clone(),
            keyring_tsks: Default::default(),
            key_store_path: self.key_store_path.clone(),
            key_store: Default::default(),
            trust_roots: self.trust_roots.clone(),
            trust_root_local: Default::default(),
            ipc_server_path: self.ipc_server_path.clone(),
            password_cache: Default::default(),
        })
    }
}
