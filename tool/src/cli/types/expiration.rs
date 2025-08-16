use std::ops::Deref;

use typenum::Unsigned;

pub use sequoia::config::Expiration;
use sequoia::config::Config;
use sequoia::config::DEFAULT_KEY_ROTATE_RETIRE_IN_DURATION;
use sequoia::config::DEFAULT_THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION;

use crate::cli::config;

// Argument parser options.

/// Expiration argument kind specialization.
pub enum ExpirationKind {
    Default,
    Certification,
    RetireIn,
}

impl From<usize> for ExpirationKind {
    fn from(v: usize) -> ExpirationKind {
        match v {
            0 => {
                debug_assert_eq!(0, DefaultKind::to_usize());
                ExpirationKind::Default
            },

            1 => {
                debug_assert_eq!(1, CertificationKind::to_usize());
                ExpirationKind::Certification
            },

            2 => {
                debug_assert_eq!(2, RetireInKind::to_usize());
                ExpirationKind::RetireIn
            },

            _ => unreachable!(),
        }
    }
}

impl ExpirationKind {
    fn name(&self) -> &'static str {
        match self {
            ExpirationKind::Default => "expiration",
            ExpirationKind::Certification => "expiration",
            ExpirationKind::RetireIn => "retire-in",
        }
    }
}

/// Default expiration parameter.
pub type DefaultKind = typenum::U0;

/// Specialization for third-party certifications.
pub type CertificationKind = typenum::U1;

/// Specialization for `sq key rotate --retire-in`.
pub type RetireInKind = typenum::U2;

#[derive(Debug)]
pub struct ExpirationArg<Kind = DefaultKind> {
    expiration: Expiration,

    /// Argument parser specializations.
    arguments: std::marker::PhantomData<Kind>,
}

impl<Kind> Deref for ExpirationArg<Kind> {
    type Target = Expiration;

    fn deref(&self) -> &Self::Target {
        &self.expiration
    }
}

impl<Kind> ExpirationArg<Kind> {
    /// Returns the expiration time.
    pub fn value(&self) -> Expiration {
        self.expiration.clone()
    }
}

impl<Kind> clap::Args for ExpirationArg<Kind>
where
    Kind: typenum::Unsigned,
{
    fn augment_args(cmd: clap::Command) -> clap::Command {
        let kind: ExpirationKind = Kind::to_usize().into();

        const EXPIRATION_LONG_HELP: &str = "\
Sets the expiration time

EXPIRATION is either an ISO 8601 formatted date with an optional time \
or a custom duration.  A duration takes the form `N[ymwds]`, where the \
letters stand for years, months, weeks, days, and seconds, respectively. \
Alternatively, the keyword `never` does not set an expiration time.";

        const RETIRE_IN_LONG_HELP: &str = "\
Sets the time at which the certificate should be retired

TIME is either an ISO 8601 formatted date with an optional time \
or a custom duration.  A duration takes the form `N[ymwds]`, where the \
letters stand for years, months, weeks, days, and seconds, respectively. \
Alternatively, the keyword `never` skips the certification of a \
revocation certificate.";

        let name = kind.name();

        cmd.arg(
            clap::Arg::new(name)
                .long(name)
                .allow_hyphen_values(true)
                .value_name(match kind {
                    ExpirationKind::Default => "EXPIRATION",
                    ExpirationKind::Certification => "EXPIRATION",
                    ExpirationKind::RetireIn => "TIME",
                })
                .value_parser(Expiration::new)
                .default_value(match kind {
                    ExpirationKind::Default => Expiration::Never,
                    ExpirationKind::Certification =>
                        Expiration::from_duration(
                            DEFAULT_THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION),
                    ExpirationKind::RetireIn =>
                        Expiration::from_duration(
                            DEFAULT_KEY_ROTATE_RETIRE_IN_DURATION),
                })
                .help(match kind {
                    ExpirationKind::Default | ExpirationKind::Certification =>
                        "Sets the expiration time",
                    ExpirationKind::RetireIn =>
                        "Sets the time at which the certificate should be retired",
                })
                .long_help(match kind {
                    ExpirationKind::Default => EXPIRATION_LONG_HELP.into(),
                    ExpirationKind::Certification =>
                        config::augment_help(Config::pki_vouch_expiration_config_key(),
                                             EXPIRATION_LONG_HELP),
                    ExpirationKind::RetireIn => RETIRE_IN_LONG_HELP.into(),
                })
        )
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

impl<Kind> clap::FromArgMatches for ExpirationArg<Kind>
where
    Kind: typenum::Unsigned
{
    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches)
                               -> clap::error::Result<()>
    {
        let kind: ExpirationKind = Kind::to_usize().into();

        if let Some(v) = matches.get_one::<Expiration>(kind.name()) {
            self.expiration = v.clone();
        }

        Ok(())
    }

    fn from_arg_matches(matches: &clap::ArgMatches)
                        -> clap::error::Result<Self>
    {
        let mut expiration = ExpirationArg {
            expiration: Expiration::Never,
            arguments: Default::default(),
        };

        expiration.update_from_arg_matches(matches)?;
        Ok(expiration)
    }
}
