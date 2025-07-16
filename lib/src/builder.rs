use std::borrow::Cow;
use std::path::Path;

use crate::Result;
use crate::Sequoia;

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
}

impl SequoiaBuilder {
    /// Returns a new `SequoiaBuilder`.
    pub fn new() -> Self {
        SequoiaBuilder {
            home: Home::Default,
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

        Ok(Sequoia {
            home,
        })
    }
}
