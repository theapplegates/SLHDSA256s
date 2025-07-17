//! A high-level API for Sequoia.

use std::borrow::Cow;
use std::time::SystemTime;

#[macro_use] mod log;

use anyhow::Result;

/// Re-export.
pub use sequoia_directories;
pub use sequoia_openpgp as openpgp;

mod builder;
pub use builder::SequoiaBuilder;

pub struct Sequoia {
    /// The home directory.
    ///
    /// If `None`, then the `Sequoia` instance should operate in
    /// stateless mode.
    home: Option<Cow<'static, sequoia_directories::Home>>,

    /// The OpenPGP policy.
    policy: openpgp::policy::StandardPolicy<'static>,

    /// The current time.
    time: Time,
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

    /// Returns the OpenPGP policy.
    pub fn policy(&self) -> &openpgp::policy::StandardPolicy<'static> {
        &self.policy
    }

    /// Returns the configured time.
    pub fn time(&self) -> SystemTime {
        self.time.get()
    }

    /// Returns whether the configured time approximates the current
    /// time.
    pub fn time_is_now(&self) -> bool {
        self.time.is_now()
    }
}

#[derive(Clone, Default)]
enum Time {
    /// Always use the current time.
    ///
    /// This is the default, and good for long-running programs.
    #[default]
    Realtime,

    /// Freeze the time the Sequoia context is built.
    Frozen(SystemTime),

    /// Use the given time.
    Fix(SystemTime),
}

impl Time {
    /// Returns the configured time.
    fn get(&self) -> SystemTime {
        match self {
            Time::Realtime => SystemTime::now(),
            Time::Frozen(t) => *t,
            Time::Fix(t) => *t,
        }
    }

    /// Returns whether the configured time approximates the current
    /// time.
    fn is_now(&self) -> bool {
        ! matches!(self, Time::Fix(_))
    }
}
