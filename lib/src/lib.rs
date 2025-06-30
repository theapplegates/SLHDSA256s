//! A high-level API for Sequoia.

use std::borrow::Cow;

#[macro_use] mod log;

use anyhow::Result;

/// Re-export.
pub use sequoia_directories;

mod builder;
pub use builder::SequoiaBuilder;

pub struct Sequoia {
    // The home directory.
    //
    // If `None`, then the `Sequoia` instance should operate in
    // stateless mode.
    home: Option<Cow<'static, sequoia_directories::Home>>,
}

impl Sequoia {
    /// Returns a new builder.
    pub fn builder() -> SequoiaBuilder {
        SequoiaBuilder::new()
    }

    /// Returns a new `Sequoia` instance using all the defaults.
    pub fn new() -> Result<Sequoia> {
        Sequoia::builder().build()
    }

    /// Returns the home directory.
    ///
    /// This returns `None` if this `Sequoia` instance is configured to
    /// operate in stateless mode.
    pub fn home(&self) -> Option<&sequoia_directories::Home> {
        self.home.as_deref()
    }

    /// Returns whether this `Sequoia` instance is operating in
    /// stateless mode.
    pub fn stateless(&self) -> bool {
        self.home.is_none()
    }
}
