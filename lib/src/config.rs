//! Configuration model and file parsing.

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashSet},
    fs,
    io,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime},
};

#[cfg(feature = "clap")]
/// Re-export.
pub use clap;
#[cfg(feature = "clap")]
use clap::parser::ValueSource;

use aho_corasick::AhoCorasick;
use anyhow::Context;

/// Re-export.
pub use toml_edit;
use toml_edit::{
    DocumentMut,
    Item,
    Table,
    Value,
};

use crate::openpgp;
use openpgp::{
    Fingerprint,
    policy::StandardPolicy,
};
use sequoia_ipc as ipc;
use sequoia_net::reqwest::Url;
use sequoia_directories::{Component, Home};
use sequoia_policy_config::ConfiguredStandardPolicy;

use crate::Result;
use crate::consts::SECONDS_IN_DAY;
use crate::consts::SECONDS_IN_YEAR;

mod cipher_suite;
pub use cipher_suite::CipherSuite;
mod expiration;
pub use expiration::Expiration;
mod profile;
pub use profile::Profile;
pub mod toml_edit_tree;
mod verbosity;
pub use verbosity::Verbosity;

/// The default validity (in years) for keys and subkeys
pub const DEFAULT_KEY_VALIDITY_IN_YEARS: u64 = 3;
/// The default validity period (as Duration) for keys and subkeys
pub const DEFAULT_KEY_VALIDITY_DURATION: Duration =
    Duration::new(SECONDS_IN_YEAR * DEFAULT_KEY_VALIDITY_IN_YEARS, 0);
/// The default validity (in years) for third party certifications
pub const DEFAULT_THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS: u64 = 10;
/// The default validity period (as Duration) for third party certifications
pub const DEFAULT_THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION: Duration =
    Duration::new(
        SECONDS_IN_YEAR * DEFAULT_THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS,
        0);

/// The default key servers to query.
pub const DEFAULT_KEYSERVERS: &[&'static str] = &[
    "hkps://keys.openpgp.org",
    "hkps://mail-api.proton.me",
    "hkps://keys.mailvelope.com",
    "hkps://keyserver.ubuntu.com",
    "hkps://sks.pod01.fleetstreetops.com",
];
/// The number of times to iterate when doing a network search.
pub const DEFAULT_NETWORK_SEARCH_ITERATIONS: u8 = 3;
/// Whether to use WKD when doing a network search.
pub const DEFAULT_NETWORK_SEARCH_USE_WKD: bool = true;
/// Whether to use DANE when doing a network search.
pub const DEFAULT_NETWORK_SEARCH_USE_DANE: bool = true;

/// The default time (in days) to retire a certificate after rotation.
pub const DEFAULT_KEY_ROTATE_RETIRE_IN_IN_DAYS: u64 = 182;
/// The default time to retire a certificate after rotation.
pub const DEFAULT_KEY_ROTATE_RETIRE_IN_DURATION: Duration =
    Duration::new(SECONDS_IN_DAY * DEFAULT_KEY_ROTATE_RETIRE_IN_IN_DAYS, 0);

/// Where a configuration setting got its value from.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub enum Source {
    /// Unset (the default value).
    #[default]
    Default,
    /// Set in the configuration file.
    ConfigFile,
    /// Set using `init_verbose`, etc.
    CommandLine,
    /// Set using a setter.
    Programmatically,
}

/// Holds the runtime configuration.
///
/// [`Config::default`] returns the default configuration.  To read
/// the configuration from a file, use [`ConfigFile::parse_home`]:
///
/// ```rust,norun
/// use sequoia::config::ConfigFile;
///
/// # fn main() -> anyhow::Result<()> {
/// let config_file = ConfigFile::parse_default_home()?;
/// let config = config_file.into_config();
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// How verbose the UI should be.
    verbosity: Verbosity,
    verbosity_source: Source,

    /// Whether to show hints.
    hints: Option<bool>,

    /// The set of encryption certs selected using `--for-self`.
    encrypt_for_self: BTreeSet<Fingerprint>,
    encrypt_for_self_source: Source,

    /// The default profile for encryption containers.
    encrypt_profile: Profile,
    encrypt_profile_source: Source,

    /// The set of signing keys selected using `--signer-self`.
    sign_signer_self: BTreeSet<Fingerprint>,
    sign_signer_self_source: Source,

    /// The default certification key selected using
    /// `--certifier-self`.
    pki_vouch_certifier_self: Option<Fingerprint>,
    pki_vouch_certifier_self_source: Source,

    /// The default validity period for third-party certifications.
    pki_vouch_expiration: Expiration,
    pki_vouch_expiration_source: Source,

    policy_path: Option<PathBuf>,
    policy_inline: Option<Vec<u8>>,

    /// The default cipher suite for newly generated keys.
    cipher_suite: CipherSuite,
    cipher_suite_source: Source,

    /// The default profile for newly generated keys.
    key_generate_profile: Profile,
    key_generate_profile_source: Source,

    /// The set of keyservers to use.
    key_servers: Vec<String>,
    key_servers_source: Source,

    /// Iterations for network search.
    network_search_iterations: u8,
    network_search_iterations_source: Source,

    /// Whether network search should use WKD.
    network_search_use_wkd: bool,
    network_search_use_wkd_source: Source,

    /// Whether network search should use DANE.
    network_search_use_dane: bool,
    network_search_use_dane_source: Source,

    /// The location of the backend server executables.
    servers_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            verbosity: Default::default(),
            verbosity_source: Default::default(),
            hints: None,
            encrypt_for_self: Default::default(),
            encrypt_for_self_source: Default::default(),
            encrypt_profile: Default::default(),
            encrypt_profile_source: Default::default(),
            sign_signer_self: Default::default(),
            sign_signer_self_source: Default::default(),
            pki_vouch_certifier_self: None,
            pki_vouch_certifier_self_source: Default::default(),
            pki_vouch_expiration: Expiration::from_duration(
                DEFAULT_THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION),
            pki_vouch_expiration_source: Default::default(),
            policy_path: None,
            policy_inline: None,
            cipher_suite: Default::default(),
            cipher_suite_source: Default::default(),
            key_generate_profile: Default::default(),
            key_generate_profile_source: Default::default(),
            key_servers: DEFAULT_KEYSERVERS.iter()
                .map(|s| s.to_string())
                .collect(),
            key_servers_source: Default::default(),
            network_search_iterations: DEFAULT_NETWORK_SEARCH_ITERATIONS,
            network_search_iterations_source: Default::default(),
            network_search_use_wkd: DEFAULT_NETWORK_SEARCH_USE_WKD,
            network_search_use_wkd_source: Default::default(),
            network_search_use_dane: DEFAULT_NETWORK_SEARCH_USE_DANE,
            network_search_use_dane_source: Default::default(),
            servers_path: Default::default(),
        }
    }
}

impl Config {
    /// Returns the verbosity setting.
    pub fn verbosity(&self) -> Verbosity {
        self.verbosity.clone()
    }

    /// Returns where the setting was set.
    pub fn verbosity_source(&self) -> Source {
        self.verbosity_source.clone()
    }

    /// Returns the configuration key for the verbosity setting.
    pub const fn verbosity_config_key() -> &'static str {
        "ui.verbosity"
    }

    /// Returns the configuration value for the verbosity setting.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn verbosity_config_value(&self) -> String {
        format!("{:?}", self.verbosity)
    }

    /// Sets the verbose setting.
    ///
    /// Handles the precedence of the various sources, but since this
    /// is a global flag and accessed very often, this is a setter and
    /// we do this once, when initializing the configuration object:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn init_verbose(&mut self, cli: bool, source: Option<ValueSource>)
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue => {
                // Use the value from the configuration file.
            },
            _ => {
                self.verbosity_source = Source::CommandLine;
                if cli {
                    self.verbosity = Verbosity::Verbose;
                } else {
                    self.verbosity = Verbosity::Default;
                }
            }
        }
    }

    /// Returns the verbose setting.
    pub fn verbose(&self) -> bool {
        self.verbosity == Verbosity::Verbose
    }

    /// Sets the quiet setting.
    ///
    /// Handles the precedence of the various sources, but since this
    /// is a global flag and accessed very often, this is a setter and
    /// we do this once, when initializing the configuration object:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn init_quiet(&mut self, cli: bool,
                      source: Option<ValueSource>)
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue => {
                // Use the value from the configuration file.
            },
            _ => {
                self.verbosity_source = Source::CommandLine;
                if cli {
                    self.verbosity = Verbosity::Quiet;
                } else {
                    self.verbosity = Verbosity::Default;
                }
            }
        }
    }

    /// Returns the quiet setting.
    pub fn quiet(&self) -> bool {
        self.verbosity == Verbosity::Quiet
    }

    /// Returns whether to show hints.
    pub fn hints(&self) -> bool {
        self.hints.unwrap_or(! self.quiet())
    }

    /// Returns the certificates that should be added to the list of
    /// recipients if `encrypt --for-self` is given.
    pub fn encrypt_for_self(&self) -> &BTreeSet<Fingerprint> {
        &self.encrypt_for_self
    }

    /// Returns where the setting was set.
    pub fn encrypt_for_self_source(&self) -> Source {
        self.encrypt_for_self_source.clone()
    }

    /// Returns the configuration key for the encrypt for self
    /// setting.
    pub const fn encrypt_for_self_config_key() -> &'static str {
        "encrypt.for-self"
    }

    /// Returns the configuration value for the encrypt for self
    /// setting.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn encrypt_for_self_config_value(&self) -> String {
        format!(
            "[ \"{}\" ]",
            self.encrypt_for_self
                .iter()
                .map(|fpr| fpr.to_string())
                .collect::<Vec<String>>()
                .join("\", \""))
    }

    /// Returns the profile for encryption containers.
    pub fn encrypt_profile(&self) -> Profile {
        self.encrypt_profile.clone()
    }

    /// Returns where the setting was set.
    pub fn encrypt_profile_source(&self) -> Source {
        self.encrypt_profile_source.clone()
    }

    /// Returns the profile for encryption containers.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn resolve_encrypt_profile(
        &self, cli: &Profile, source: Option<ValueSource>)
        -> Profile
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                &self.encrypt_profile,
            _ => cli,
        }.clone()
    }

    /// Returns the configuration key for the encrypt profile
    /// setting.
    pub const fn encrypt_profile_config_key() -> &'static str {
        "encrypt.profile"
    }

    /// Returns the configuration value for the encrypt profile
    /// setting.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn encrypt_profile_config_value(&self) -> String {
        format!("{:?}", self.encrypt_profile)
    }

    /// Returns the keys that should be added to the list of
    /// signers if `--signer-self` is given.
    pub fn sign_signer_self(&self) -> &BTreeSet<Fingerprint> {
        &self.sign_signer_self
    }

    /// Returns where the setting was set.
    pub fn sign_signer_self_source(&self) -> Source {
        self.sign_signer_self_source.clone()
    }

    /// Returns the configuration key for the sign signer self
    /// setting.
    pub const fn sign_signer_self_config_key() -> &'static str {
        "sign.signer-self"
    }

    /// Returns the configuration value for the sign signer self
    /// setting.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn sign_signer_self_config_value(&self) -> String {
        format!(
            "[ \"{}\" ]",
            self.sign_signer_self
                .iter()
                .map(|fpr| fpr.to_string())
                .collect::<Vec<String>>()
                .join("\", \""))
    }

    /// Returns the key that should be used as certifier if
    /// `--certifier-self` is given.
    pub fn pki_vouch_certifier_self(&self) -> &Option<Fingerprint> {
        &self.pki_vouch_certifier_self
    }

    /// Returns where the setting was set.
    pub fn pki_vouch_certifier_self_source(&self) -> Source {
        self.pki_vouch_certifier_self_source.clone()
    }

    /// Returns the configuration key for the pki vouch certifier self
    /// key setting.
    pub const fn pki_vouch_certifier_self_config_key() -> &'static str {
        "pki.vouch.certifier-self"
    }

    /// Returns the configuration value for the pki vouch certifier
    /// self key setting.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn pki_vouch_certifier_self_config_value(&self) -> String {
        if let Some(fpr) = self.pki_vouch_certifier_self.as_ref() {
            format!("\"{}\"", fpr)
        } else {
            "\"\"".into()
        }
    }

    /// Returns the value of the pki vouch expiration setting.
    pub fn pki_vouch_expiration(&self) -> Expiration {
        self.pki_vouch_expiration.clone()
    }

    /// Returns where the setting was set.
    pub fn pki_vouch_expiration_source(&self) -> Source {
        self.pki_vouch_expiration_source.clone()
    }

    /// Returns the expiration for third-party certifications.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn resolve_pki_vouch_expiration(
        &self, cli: &Expiration,
        source: Option<ValueSource>)
        -> Expiration
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                &self.pki_vouch_expiration,
            _ => cli,
        }.clone()
    }

    /// Returns the configuration key for the pki vouch expiration
    /// setting.
    pub const fn pki_vouch_expiration_config_key() -> &'static str {
        "pki.vouch.expiration"
    }

    /// Returns the configuration value for the pki vouch certifier
    /// self key setting.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn pki_vouch_expiration_config_value(&self) -> String {
        format!("\"{}\"", self.pki_vouch_expiration)
    }

    /// Returns the path to the referenced cryptographic policy, if
    /// any.
    pub fn policy_path(&self) -> Option<&Path> {
        self.policy_path.as_deref()
    }

    /// Returns the cryptographic policy.
    ///
    /// We read in the default policy configuration, the configuration
    /// referenced in the configuration file, and the inline policy.
    pub fn policy(&self, at: SystemTime)
                  -> Result<StandardPolicy<'static>>
    {
        let mut policy = ConfiguredStandardPolicy::at(at);

        policy.parse_default_config()?;

        if let Some(p) = &self.policy_path {
            if ! policy.parse_config_file(p)? {
                return Err(anyhow::anyhow!(
                    "referenced policy file {:?} does not exist", p));
            }
        }

        if let Some(p) = &self.policy_inline {
            policy.parse_bytes(p)?;
        }

        Ok(policy.build())
    }

    /// Returns the cipher suite setting.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite.clone()
    }

    /// Returns where the setting was set.
    pub fn cipher_suite_source(&self) -> Source {
        self.cipher_suite_source.clone()
    }

    /// Returns the cipher suite for generating new keys.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn resolve_cipher_suite(&self, cli: &CipherSuite,
                                source: Option<ValueSource>)
        -> CipherSuite
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue => &self.cipher_suite,
            _ => cli,
        }.clone()
    }

    /// Returns the configuration key for the cipher suite setting.
    pub const fn cipher_suite_config_key() -> &'static str {
        "key.generate.cipher-suite"
    }

    /// Returns the configuration value for the cipher suite setting.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn cipher_suite_config_value(&self) -> String {
        format!("\"{}\"", self.cipher_suite)
    }

    /// Returns the key generate profile setting.
    pub fn key_generate_profile(&self) -> Profile {
        self.key_generate_profile.clone()
    }

    /// Returns where the setting was set.
    pub fn key_generate_profile_source(&self) -> Source {
        self.key_generate_profile_source.clone()
    }

    /// Returns the profile for generating new keys.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn resolve_key_generate_profile(
        &self, cli: &Profile,
        source: Option<ValueSource>)
        -> Profile
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue => {
                &self.key_generate_profile
            }
            _ => cli,
        }.clone()
    }

    /// Returns the configuration key for the key generate profile
    /// setting.
    pub const fn key_generate_profile_config_key() -> &'static str {
        "key.generate.profile"
    }

    /// Returns the configuration value for the key generate profile
    /// setting.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn key_generate_profile_config_value(&self) -> String {
        format!("{:?}", self.key_generate_profile)
    }

    /// Returns the key servers to query or publish.
    pub fn key_servers(&self) -> &[ String ] {
        &self.key_servers
    }

    /// Returns where the setting was set.
    pub fn key_servers_source(&self) -> Source {
        self.key_servers_source.clone()
    }

    /// Returns the key servers to query or publish.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn resolve_key_servers<'s, S>(&'s self, cli: &'s [S],
                                      source: Option<ValueSource>)
        -> impl Iterator<Item = &'s str> + 's
    where
        S: AsRef<str> + 's,
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                Box::new(self.key_servers.iter().map(|s| s.as_str()))
                    as Box<dyn Iterator<Item = &str>>,
            _ => Box::new(cli.iter().map(|s| s.as_ref()))
                    as Box<dyn Iterator<Item = &str>>,
        }
    }

    /// Returns the configuration key for the keyservers setting.
    pub const fn key_servers_config_key() -> &'static str {
        "network.keyservers"
    }

    /// Returns the configuration value for the key servers setting.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn key_servers_config_value(&self) -> String {
        format!(
            "[ {} ]",
            self.key_servers
                .iter()
                .map(|ks| format!("{:?}", ks))
                .collect::<Vec<String>>()
                .join(", "))
    }

    /// Returns the iteration count for network search.
    pub fn network_search_iterations(&self) -> u8 {
        self.network_search_iterations
    }

    /// Returns where the setting was set.
    pub fn network_search_iterations_source(&self) -> Source {
        self.network_search_iterations_source.clone()
    }

    /// Returns the iteration count for network search.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn resolve_network_search_iterations(
        &self, cli: u8, source: Option<ValueSource>)
        -> u8
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.network_search_iterations,
            _ => cli,
        }
    }

    /// Returns the configuration key for the network search
    /// iterations setting.
    pub const fn network_search_iterations_config_key() -> &'static str {
        "network.search.iterations"
    }

    /// Returns the configuration value for the network search
    /// iterations.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn network_search_iterations_config_value(&self) -> String {
        self.network_search_iterations.to_string()
    }

    /// Returns whether network search should use WKD.
    pub fn network_search_use_wkd(&self) -> bool {
        self.network_search_use_wkd
    }

    /// Returns where the setting was set.
    pub fn network_search_use_wkd_source(&self) -> Source {
        self.network_search_use_wkd_source.clone()
    }

    /// Returns whether network search should use WKD.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn resolve_network_search_use_wkd(
        &self, cli: Option<bool>, source: Option<ValueSource>)
        -> bool
    {
        let cli = cli.expect("has a default");
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.network_search_use_wkd,
            _ => cli,
        }
    }

    /// Returns the configuration key for the network search
    /// use wkd setting.
    pub const fn network_search_use_wkd_config_key() -> &'static str {
        "network.search.use-wkd"
    }

    /// Returns the configuration value whether the network search
    /// should use WKD.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn network_search_use_wkd_config_value(&self) -> String {
        self.network_search_use_wkd.to_string()
    }

    /// Returns whether network search should use DANE.
    pub fn network_search_use_dane(&self) -> bool {
        self.network_search_use_dane
    }

    /// Returns where the setting was set.
    pub fn network_search_use_dane_source(&self) -> Source {
        self.network_search_use_dane_source.clone()
    }

    /// Returns whether network search should use DANE.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    #[cfg(feature = "clap")]
    pub fn resolve_network_search_use_dane(
        &self, cli: Option<bool>, source: Option<ValueSource>)
        -> bool
    {
        let cli = cli.expect("has a default");
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.network_search_use_dane,
            _ => cli,
        }
    }

    /// Returns the configuration key for the network search
    /// use dane setting.
    pub const fn network_search_use_dane_config_key() -> &'static str {
        "network.search.use-dane"
    }

    /// Returns the configuration value whether the network search
    /// should use DANE.
    ///
    /// The returned value can be written directly to the
    /// configuration file; additional quoting is not required.
    pub fn network_search_use_dane_config_value(&self) -> String {
        self.network_search_use_dane.to_string()
    }

    /// Returns the path to the backend servers.
    pub fn servers_path(&self) -> Option<&Path> {
        self.servers_path.as_ref().map(|p| p.as_path())
    }
}

/// Holds the document tree of the configuration file.
///
/// Most applications just need to use [`ConfigFile::parse_home`] to
/// parse and validate the configuration file.  Then, given a
/// configuration file, you can get the configuration using
/// [`ConfigFile::config`] or [`ConfigFile::into_config`].
///
/// To modify a configuration file, you can use
/// [`ConfigFile::into_doc`] to convert a `ConfigFile` into a
/// `toml_edit::DocumentMut`.  You can then modify the document tree.
/// When you are done, you can convert it back to a `ConfigFile` using
/// [`ConfigFile::from_doc`], which also validates the new
/// configuration.  Note that if you use `doc.remove` to remove a key,
/// it may leave comments behind, which can make the resulting file
/// misleading.
#[derive(Debug, Default, Clone)]
pub struct ConfigFile {
    doc: DocumentMut,
    config: Config,
}

impl ConfigFile {
    /// A template for the configuration containing the default
    /// values.
    ///
    /// Not all of the comment out values are valid.  Those that are
    /// not valid are prefixed with "example".
    const TEMPLATE: &'static str = "\
# Configuration template for sequoia <SEQUOIA-VERSION>
<SQ-CONFIG-PATH-HINT>

[ui]
#verbosity = \"default\" # or \"verbose\" or \"quiet\"
#hints = true

[encrypt]
example#for-self = [\"fingerprint of your key\"]
#profile = <DEFAULT-ENCRYPT-PROFILE>

[sign]
example#signer-self = [\"fingerprint of your key\"]

[pki.vouch]
example#certifier-self = \"fingerprint of your key\"
#expiration = \"<DEFAULT-PKI-VOUCH-EXPIRATION>y\"

[key.generate]
#cipher-suite = <DEFAULT-CIPHER-SUITE>
#profile = <DEFAULT-KEY-GENERATE-PROFILE>

[network]
#keyservers = <DEFAULT-KEY-SERVERS>

[network.search]
#iterations = <DEFAULT-NETWORK-SEARCH-ITERATIONS>
#use-wkd = <DEFAULT-NETWORK-SEARCH-USE-WKD>
#use-dane = <DEFAULT-NETWORK-SEARCH-USE-DANE>

[servers]
#path = <DEFAULT-SERVERS-PATH>

[policy]
#path = <DEFAULT-POLICY-FILE>

# The policy can be inlined, either alternatively, or additionally,
# like so:

<DEFAULT-POLICY-INLINE>
";

    /// Patterns to match on in `Self::DEFAULT` to be replaced with
    /// the default values.
    const TEMPLATE_PATTERNS: &'static [&'static str] = &[
        "<SEQUOIA-VERSION>",
        "<SQ-CONFIG-PATH-HINT>",
        "<DEFAULT-ENCRYPT-PROFILE>",
        "<DEFAULT-PKI-VOUCH-EXPIRATION>",
        "<DEFAULT-CIPHER-SUITE>",
        "<DEFAULT-KEY-GENERATE-PROFILE>",
        "<DEFAULT-KEY-SERVERS>",
        "<DEFAULT-SERVERS-PATH>",
        "<DEFAULT-POLICY-FILE>",
        "<DEFAULT-POLICY-INLINE>",
        "<DEFAULT-NETWORK-SEARCH-ITERATIONS>",
        "<DEFAULT-NETWORK-SEARCH-USE-WKD>",
        "<DEFAULT-NETWORK-SEARCH-USE-DANE>",
    ];

    /// Returns a configuration template with the defaults.
    fn config_template(path: Option<&Path>,
                       inline_policy: bool,
                       uncomment_defaults: bool)
        -> Result<String>
    {
        let ac = AhoCorasick::new(Self::TEMPLATE_PATTERNS)?;

        let mut p = ConfiguredStandardPolicy::new();
        p.parse_default_config()?;

        let mut default_policy_inline;
        let default_policy_inline = if inline_policy {
            default_policy_inline = Vec::new();
            p.dump(&mut default_policy_inline,
                   sequoia_policy_config::DumpDefault::Template)?;
            regex::Regex::new(r"(?m)^\[")?.replace_all(
                std::str::from_utf8(&default_policy_inline)?, "[policy.")
        } else {
            "".into()
        };

        let template = if uncomment_defaults {
            // Enable all defaults by commenting-in.
            let r = regex::Regex::new(r"(?m)^#([^ ])")?;
            r.replace_all(Self::TEMPLATE, "$1")
        } else {
            Cow::Borrowed(Self::TEMPLATE)
        };

        // Remove the example tag.
        let r = regex::Regex::new(r"(?m)^example(#[^ ])")?;
        let template = r.replace_all(&template, "$1");

        Ok(ac.replace_all(&template, &[
            &env!("CARGO_PKG_VERSION").to_string(),
            &if let Some(path) = path {
                format!(
                    "\n\
                     # To use it, edit it to your liking and write it to\n\
                     # {}",
                    &path.display())
            } else {
                "".into()
            },
            &format!("{:?}", Profile::default()),
            &DEFAULT_THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS.to_string(),
            &format!("{:?}", CipherSuite::default()),
            &format!("{:?}", Profile::default()),
            &format!("{:?}", DEFAULT_KEYSERVERS),
            &format!("{:?}", {
                ipc::Context::configure().build()
                    .map(|c| c.lib().display().to_string())
                    .unwrap_or_else(|_| "<unknown>".into())
            }),
            &format!("{:?}", Self::global_crypto_policy_file()),
            &default_policy_inline.to_string(),
            &format!("{}", DEFAULT_NETWORK_SEARCH_ITERATIONS),
            &format!("{}", DEFAULT_NETWORK_SEARCH_USE_WKD),
            &format!("{}", DEFAULT_NETWORK_SEARCH_USE_DANE),
        ]))
    }

    /// Returns the default configuration in template form.
    ///
    /// All the configuration options with their defaults are
    /// commented out.
    pub fn default_template(home: Option<&Home>) -> Result<Self> {
        let template = Self::config_template(
            home.map(Self::file_name).as_deref(), true, false)?;

        let doc: DocumentMut = template.parse()
            .context("Parsing default configuration failed")?;
        Ok(Self::from_doc(doc).expect("Default configuration is valid"))
    }

    /// Returns the default configuration.
    ///
    /// Unlike [`ConfigFile::default_template`], the default
    /// configuration options are explicitly set.
    pub fn default_config(home: Option<&Home>) -> Result<Self> {
        let template = Self::config_template(
            home.map(Self::file_name).as_deref(), true, true)?;

        let doc: DocumentMut = template.parse()
            .context("Parsing default configuration failed")?;

        Ok(Self::from_doc(doc).expect("Default configuration is valid"))
    }

    /// Returns the absolute path of the configuration file for the
    /// specified home directory.
    pub fn file_name(home: &Home) -> PathBuf {
        home.config_dir(Component::Sq).join("config.toml")
    }

    /// Reads and validates the configuration file from the default
    /// home directory.
    ///
    /// If the configuration file does not exist, the default
    /// configuration file is returned.  Any other error that occurs
    /// while reading the configuration is propagated to the caller.
    pub fn parse_default_home() -> Result<Self> {
        if let Some(home) = sequoia_directories::Home::default() {
            Self::parse_home(home)
        } else {
            Err(anyhow::anyhow!("Platform does not have a default home directory"))
        }
    }

    /// Reads and validates the configuration file from the specified
    /// home directory.
    ///
    /// If the configuration file does not exist, the default
    /// configuration file is returned.  Any other error that occurs
    /// while reading the configuration is propagated to the caller.
    pub fn parse_home(home: &Home) -> Result<Self> {
        Self::parse_file(&Self::file_name(home))
    }

    /// Reads and validates the specified configuration file.
    ///
    /// The file must contain a valid toml document, which is
    /// consistent with the schema.
    ///
    /// If the file does not exist, the default configuration file is
    /// used.  Any other error that occurs while reading the
    /// configuration is propagated to the caller.
    pub fn parse_file(path: &Path) -> Result<Self> {
        let config = match fs::read_to_string(&path) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound =>
                Self::config_template(Some(&path), true, false)?,
            Err(e) => return Err(anyhow::Error::from(e).context(
                format!("Reading configuration file {} failed",
                        path.display()))),
        };

        Self::parse(&config)
            .with_context(|| {
                format!("Reading configuration file {}", path.display())
            })
    }

    /// Parses and validates the configuration.
    fn parse(doc: &str) -> Result<Self>
    {
        let doc: DocumentMut = doc.parse()?;

        Self::from_doc(doc)
    }

    /// Uses and validates the document tree.
    ///
    /// This returns an error if the document tree does not contain a
    /// valid configuration.
    pub fn from_doc(doc: DocumentMut) -> Result<Self> {
        let mut config = Config::default();
        apply_schema(&mut Some(&mut config), None, doc.iter(),
                     TOP_LEVEL_SCHEMA)?;

        Ok(Self {
            doc,
            config,
        })
    }

    /// Returns the parsed `Config`.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the parsed `Config`.
    pub fn into_config(self) -> Config {
        self.config
    }

    /// Writes the configuration to the disk.
    pub fn persist(&self, home: &Home) -> Result<()> {
        let path = Self::file_name(home);
        let dir = path.parent().unwrap();

        fs::create_dir_all(dir)?;

        let mut t =
            tempfile::NamedTempFile::new_in(dir)?;
        self.dump(&mut t)?;
        t.persist(path)?;

        Ok(())
    }

    /// Writes the configuration to the given writer.
    pub fn dump(&self, sink: &mut dyn io::Write) -> Result<()> {
        write!(sink, "{}", self.doc.to_string())?;
        Ok(())
    }

    /// Augments the configuration with the effective configuration
    /// and policy.
    ///
    /// XXX: Due to the way doc.remove works, it will leave misleading
    /// comments behind.  Therefore, the resulting configuration is
    /// not suitable for dumping, but may only be used for
    /// commands::config::get.
    pub fn effective_configuration(&self, policy: &StandardPolicy,
                                   hints: bool)
            -> Result<Self>
    {
        use std::io::Write;
        let mut raw = Vec::new();

        // First, start with our configuration, and drop most of the
        // policy with the exception of the path.
        let p = ConfiguredStandardPolicy::from_policy(policy.clone());
        let mut doc = self.doc.clone();
        doc.remove("policy");

        use toml_edit_tree::Node;
        let policy_path: toml_edit_tree::Path
            = "policy.path".parse().unwrap();
        if let Ok(p) = self.as_item().traverse(&policy_path) {
            let p =
                p.as_atomic_value().unwrap().as_str().unwrap().to_string();
            doc.as_table_mut().insert("policy", Item::Table(
                [("path", Value::from(p))]
                    .into_iter().collect()));
        }

        write!(&mut raw, "{}", doc.to_string())?;

        // Then, augment the configuration with the effective policy.
        let mut default_policy_inline = Vec::new();
        p.dump(&mut default_policy_inline,
               sequoia_policy_config::DumpDefault::Template)?;
        let default_policy_inline =
            regex::Regex::new(r"(?m)^\[")?.replace_all(
                std::str::from_utf8(&default_policy_inline)?, "[policy.");

        write!(&mut raw, "{}", default_policy_inline)?;

        // Now, parse the resulting configuration.
        let mut doc: DocumentMut = std::str::from_utf8(&raw)?.parse()?;

        // Tweak a few settings.
        if doc.get("ui").is_none() {
            doc.as_table_mut().insert("ui".into(),
                                      Item::Table(Default::default()));
        }
        doc.get_mut("ui").expect("just created on demand")
            .set(&"hints".into(), hints.into())?;

        // Double check that it is well-formed.
        let mut config = Config::default();
        apply_schema(&mut Some(&mut config), None, doc.iter(),
                     TOP_LEVEL_SCHEMA)?;

        Ok(Self {
            doc,
            config,
        })
    }

    /// Returns the path to the global cryptographic policy
    /// configuration file.
    pub fn global_crypto_policy_file() -> String {
        std::env::var(ConfiguredStandardPolicy::ENV_VAR)
            .unwrap_or_else(
                |_| ConfiguredStandardPolicy::CONFIG_FILE.into())
    }

    /// Returns the document tree.
    pub fn as_item(&self) -> &Item {
        self.doc.as_item()
    }

    /// Returns the mutable document tree.
    ///
    /// You can use this to get a mutable reference to the underlying
    /// document.  After editing it, you can convert it back to a
    /// `ConfigFile` using [`ConfigFile::from_doc`].
    pub fn into_doc(self) -> DocumentMut {
        self.doc
    }
}

/// Validates a configuration section using a schema, and optionally
/// applies changes to the configuration.
///
/// Returns an error if a key is unknown.
///
/// known_keys better be lowercase.
fn apply_schema<'toml>(config: &mut Option<&mut Config>,
                       path: Option<&str>,
                       section: toml_edit::Iter<'toml>,
                       schema: Schema) -> Result<()> {
    let section = section.collect::<Vec<_>>();
    let known_keys: Vec<_> =
        schema.iter().map(|(key, _)| *key).collect();

    // Schema keys better be lowercase.
    debug_assert!(known_keys.iter().all(|&s| &s.to_lowercase() == s),
                  "keys in schema must be lowercase");

    // Schema keys better be sorted.
    debug_assert!(known_keys.windows(2).all(|v| v[0] <= v[1]),
                  "keys in schema must be sorted");
    // XXX: once [].is_sorted is stabilized:
    // debug_assert!(known_keys.is_sorted(), "keys in schema must be sorted");

    let prefix = if let Some(path) = path {
        format!("{}.", path)
    } else {
        "".to_string()
    };

    let keys: HashSet<&str> = section
        .iter().map(|(key, _value)| *key)
        .collect();

    // The set of allowed keys are the known keys, plus
    // "ignore_invalid", and the value of "ignore_invalid".
    let mut allowed_keys: Vec<&str> = known_keys.to_vec();
    if let Some(ignore) = section.iter()
        .find_map(|(k, v)| (*k == "ignore_invalid").then_some(*v))
    {
        allowed_keys.push("ignore_invalid");
        match ignore {
            Item::Value(Value::String(k)) =>
                allowed_keys.push(k.value().as_str()),
            Item::Value(Value::Array(ks)) => {
                for k in ks {
                    if let Value::String(k) = k {
                        allowed_keys.push(k.value().as_str());
                    } else {
                        Err(Error::ParseError(format!(
                            "'{}ignore_invalid' takes a string \
                             or an array of strings",
                            prefix)))?
                    }
                }
            }
            _ => {
                return Err(Error::ParseError(format!(
                    "Invalid value for '{}ignore_invalid': {}, \
                     expected a string or an array of strings",
                    prefix, ignore)).into());
            }
        }
    }

    // Now check if there are any unknown sections.
    let unknown_keys = keys
        .difference(&allowed_keys.into_iter().collect())
        .map(|s| *s)
        .collect::<Vec<_>>();
    if ! unknown_keys.is_empty() {
        return Err(Error::ParseError(format!(
            "{} has unknown keys: {}, valid keys are: {}",
            if let Some(path) = path {
                path
            } else {
                "top-level section"
            },
            unknown_keys.join(", "),
            // We don't include the keys listed in ignore_invalid.
            known_keys.join(", "))).into());
    }

    // Now validate the values.
    for (key, value) in &section {
        if let Ok(i) = schema.binary_search_by_key(key, |(k, _)| k) {
            let apply = schema[i].1;
            (apply)(config, &format!("{}{}", prefix, key), value)
                .with_context(|| format!("Error validating {:?}", key))?;
        }
    }

    Ok(())
}

/// Errors used in this module.
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),

    /// A Relative Path was provided where an absolute path was expected.
    #[error("Relative path not allowed: {0}")]
    RelativePathError(PathBuf),

    /// An algorithm is not known to this crate.
    #[error("Unknown algorithm: {0}")]
    UnknownAlgorithm(String),

    #[error("Configuration item {0:?} is not a {1} but a {2}")]
    BadType(String, &'static str, &'static str),
}

impl Error {
    /// Returns an `Error::BadType` given an item.
    fn bad_item_type(path: &str, i: &Item, want_type: &'static str)
                     -> anyhow::Error
    {
        Error::BadType(path.into(), want_type, i.type_name()).into()
    }

    /// Returns an `Error::BadType` given a value.
    fn bad_value_type(path: &str, v: &Value, want_type: &'static str)
                      -> anyhow::Error
    {
        Error::BadType(path.into(), want_type, v.type_name()).into()
    }
}

/// A function that validates a node in the configuration tree with
/// the given path.
type Applicator = fn(&mut Option<&mut Config>, &str, &Item) -> Result<()>;

/// Ignores a node.
fn apply_nop(_: &mut Option<&mut Config>, _: &str, _: &Item) -> Result<()> {
    Ok(())
}

/// A [`Schema`] maps keys to [`Applicator`]s.
type Schema = &'static [(&'static str, Applicator)];

/// Schema for the toplevel.
const TOP_LEVEL_SCHEMA: Schema = &[
    ("encrypt", apply_encrypt),
    ("key", apply_key),
    ("network", apply_network),
    ("pki", apply_pki),
    ("policy", apply_policy),
    ("servers", apply_servers),
    ("sign", apply_sign),
    ("ui", apply_ui),
];

/// Schema for the `ui` section.
const UI_SCHEMA: Schema = &[
    ("hints", apply_ui_hints),
    ("verbosity", apply_ui_verbosity),
];

/// Validates the `ui` section.
fn apply_ui(config: &mut Option<&mut Config>, path: &str, item: &Item)
            -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), UI_SCHEMA)?;
    Ok(())
}

/// Validates the `ui.hints` value.
fn apply_ui_hints(config: &mut Option<&mut Config>, path: &str, item: &Item)
                  -> Result<()>
{
    let s = item.as_bool()
        .ok_or_else(|| Error::bad_item_type(path, item, "bool"))?;

    if let Some(config) = config {
        config.hints = Some(s);
    }

    Ok(())
}

/// Validates the `ui.verbosity` value.
fn apply_ui_verbosity(config: &mut Option<&mut Config>,
                      path: &str, item: &Item)
    -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    let verbosity = match s {
        "default" => Verbosity::Default,
        "verbose" => Verbosity::Verbose,
        "quiet" => Verbosity::Quiet,
        _ => return Err(anyhow::anyhow!("verbosity must be either \
                                         \"default\", \
                                         \"verbose\", \
                                         or \"quiet\"")),
    };

    if let Some(config) = config {
        config.verbosity = verbosity;
        config.verbosity_source = Source::ConfigFile;
    }

    Ok(())
}

/// Schema for the `encrypt` section.
const ENCRYPT_SCHEMA: Schema = &[
    ("for-self", apply_encrypt_for_self),
    ("profile", apply_encrypt_profile),
];

/// Validates the `encrypt` section.
fn apply_encrypt(config: &mut Option<&mut Config>,
                 path: &str, item: &Item)
    -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), ENCRYPT_SCHEMA)?;
    Ok(())
}

/// Validates the `encrypt.for-self` value.
fn apply_encrypt_for_self(config: &mut Option<&mut Config>,
                          path: &str, item: &Item)
                          -> Result<()>
{
    let list = item.as_array()
        .ok_or_else(|| Error::bad_item_type(path, item, "array"))?;

    let mut strs = Vec::new();
    let mut values = BTreeSet::default();
    for (i, server) in list.iter().enumerate() {
        let s = server.as_str()
            .ok_or_else(|| Error::bad_value_type(&format!("{}.{}", path, i),
                                                 server, "string"))?;

        strs.push(s);
        values.insert(s.parse::<Fingerprint>()?);
    }

    if let Some(config) = config {
        config.encrypt_for_self = values;
        config.encrypt_for_self_source = Source::ConfigFile;
    }

    Ok(())
}

/// Validates the `encrypt.profile` value.
fn apply_encrypt_profile(config: &mut Option<&mut Config>,
                         path: &str, item: &Item)
                         -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;
    let v = Profile::from_str(s)?;

    if let Some(config) = config {
        config.encrypt_profile = v.clone();
        config.encrypt_profile_source = Source::ConfigFile;
    }

    Ok(())
}

/// Schema for the `sign` section.
const SIGN_SCHEMA: Schema = &[
    ("signer-self", apply_sign_signer_self),
];

/// Validates the `sign` section.
fn apply_sign(config: &mut Option<&mut Config>,
              path: &str, item: &Item)
              -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), SIGN_SCHEMA)?;
    Ok(())
}

/// Validates the `sign.signer-self` value.
fn apply_sign_signer_self(config: &mut Option<&mut Config>,
                          path: &str, item: &Item)
                          -> Result<()>
{
    let list = item.as_array()
        .ok_or_else(|| Error::bad_item_type(path, item, "array"))?;

    let mut strs = Vec::new();
    let mut values = BTreeSet::default();
    for (i, server) in list.iter().enumerate() {
        let s = server.as_str()
            .ok_or_else(|| Error::bad_value_type(&format!("{}.{}", path, i),
                                                 server, "string"))?;

        strs.push(s);
        values.insert(s.parse::<Fingerprint>()?);
    }

    if let Some(config) = config {
        config.sign_signer_self = values;
        config.sign_signer_self_source = Source::ConfigFile;
    }

    Ok(())
}

/// Schema for the `pki` section.
const PKI_SCHEMA: Schema = &[
    ("vouch", apply_pki_vouch),
];

/// Validates the `pki` section.
fn apply_pki(config: &mut Option<&mut Config>,
             path: &str, item: &Item)
    -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), PKI_SCHEMA)?;
    Ok(())
}

/// Schema for the `pki.vouch` section.
const PKI_VOUCH_SCHEMA: Schema = &[
    ("certifier-self", apply_pki_vouch_certifier_self),
    ("expiration", apply_pki_vouch_expiration),
];

/// Validates the `pki.vouch` section.
fn apply_pki_vouch(config: &mut Option<&mut Config>,
                   path: &str, item: &Item)
    -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), PKI_VOUCH_SCHEMA)?;
    Ok(())
}

/// Validates the `pki.vouch.certifier-self` value.
fn apply_pki_vouch_certifier_self(config: &mut Option<&mut Config>,
                                  path: &str, item: &Item)
    -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    let fp = if s.is_empty() {
        None
    } else {
        Some(s.parse::<Fingerprint>()
             .with_context(|| format!("{:?} is not a valid fingerprint", s))?)
    };

    if let Some(config) = config {
        config.pki_vouch_certifier_self = fp;
        config.pki_vouch_certifier_self_source = Source::ConfigFile;
    }

    Ok(())
}

/// Validates the `pki.vouch.expiration` value.
fn apply_pki_vouch_expiration(config: &mut Option<&mut Config>,
                              path: &str, item: &Item)
    -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    let v = s.parse::<Expiration>()?;

    if let Some(config) = config {
        config.pki_vouch_expiration = v;
        config.pki_vouch_expiration_source = Source::ConfigFile;
    }

    Ok(())
}

/// Schema for the `key` section.
const KEY_SCHEMA: Schema = &[
    ("generate", apply_key_generate),
];

/// Validates the `key` section.
fn apply_key(config: &mut Option<&mut Config>,
             path: &str, item: &Item)
    -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), KEY_SCHEMA)?;
    Ok(())
}

/// Schema for the `key.generate` section.
const KEY_GENERATE_SCHEMA: Schema = &[
    ("cipher-suite", apply_key_generate_cipher_suite),
    ("profile", apply_key_generate_profile),
];

/// Validates the `key.generate` section.
fn apply_key_generate(config: &mut Option<&mut Config>,
                      path: &str, item: &Item)
    -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), KEY_GENERATE_SCHEMA)?;
    Ok(())
}

/// Validates the `key.generate.cipher-suite` value.
fn apply_key_generate_cipher_suite(config: &mut Option<&mut Config>,
                                   path: &str, item: &Item)
    -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;
    let v = CipherSuite::from_str(s)?;

    if let Some(config) = config {
        config.cipher_suite = v.clone();
        config.cipher_suite_source = Source::ConfigFile;
    }

    Ok(())
}

/// Validates the `key.generate.profile` value.
fn apply_key_generate_profile(config: &mut Option<&mut Config>,
                              path: &str, item: &Item)
    -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;
    let v = Profile::from_str(s)?;

    if let Some(config) = config {
        config.key_generate_profile = v.clone();
        config.key_generate_profile_source = Source::ConfigFile;
    }

    Ok(())
}

/// Schema for the `network` section.
const NETWORK_SCHEMA: Schema = &[
    ("keyservers", apply_network_keyservers),
    ("search", apply_network_search),
];

/// Validates the `network` section.
fn apply_network(config: &mut Option<&mut Config>,
                 path: &str, item: &Item)
    -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), NETWORK_SCHEMA)?;
    Ok(())
}

/// Validates the `network.keyservers` value.
fn apply_network_keyservers(config: &mut Option<&mut Config>,
                            path: &str, item: &Item)
    -> Result<()>
{
    let list = item.as_array()
        .ok_or_else(|| Error::bad_item_type(path, item, "array"))?;

    let mut servers_str = Vec::new();
    for (i, server) in list.iter().enumerate() {
        let server_str = server.as_str()
            .ok_or_else(|| Error::bad_value_type(&format!("{}.{}", path, i),
                                                 server, "string"))?;

        let url = Url::parse(server_str)?;
        let s = url.scheme();
        match s {
            "hkp" => (),
            "hkps" => (),
            _ => return Err(anyhow::anyhow!(
                "must be a hkp:// or hkps:// URL: {}", url)),
        }

        servers_str.push(server_str.to_string());
    }

    if let Some(config) = config {
        config.key_servers = servers_str;
        config.key_servers_source = Source::ConfigFile;
    }

    Ok(())
}

/// Schema for the `network.search` section.
const NETWORK_SEARCH_SCHEMA: Schema = &[
    ("iterations", apply_network_search_iterations),
    ("use-dane", apply_network_search_use_dane),
    ("use-wkd", apply_network_search_use_wkd),
];

/// Validates the `network.search` section.
fn apply_network_search(config: &mut Option<&mut Config>,
                        path: &str, item: &Item)
    -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(),
                 NETWORK_SEARCH_SCHEMA)?;
    Ok(())
}

/// Validates the `network.search.iterations` value.
fn apply_network_search_iterations(config: &mut Option<&mut Config>,
                                   path: &str, item: &Item)
    -> Result<()>
{
    let s = item.as_integer()
        .ok_or_else(|| Error::bad_item_type(path, item, "integer"))?;

    if let Some(config) = config {
        if s == 0 {
            return Err(anyhow::anyhow!("value must be at least 1"));
        }

        config.network_search_iterations = s.try_into()
            .map_err(|_| anyhow::anyhow!("value must not exceed 255"))?;
        config.network_search_iterations_source = Source::ConfigFile;
    }

    Ok(())
}

/// Validates the `network.search.use-dane` value.
fn apply_network_search_use_dane(config: &mut Option<&mut Config>,
                                 path: &str, item: &Item)
    -> Result<()>
{
    let s = item.as_bool()
        .ok_or_else(|| Error::bad_item_type(path, item, "bool"))?;

    if let Some(config) = config {
        config.network_search_use_dane = s;
        config.network_search_use_dane_source = Source::ConfigFile;
    }

    Ok(())
}

/// Validates the `network.search.use-wkd` value.
fn apply_network_search_use_wkd(config: &mut Option<&mut Config>,
                                path: &str, item: &Item)
    -> Result<()>
{
    let s = item.as_bool()
        .ok_or_else(|| Error::bad_item_type(path, item, "bool"))?;

    if let Some(config) = config {
        config.network_search_use_wkd = s;
        config.network_search_use_wkd_source = Source::ConfigFile;
    }

    Ok(())
}

/// Schema for the `policy` section.
const POLICY_SCHEMA: Schema = &[
    ("aead_algorithms", apply_nop),
    ("asymmetric_algorithms", apply_nop),
    ("hash_algorithms", apply_nop),
    ("packets", apply_nop),
    ("path", apply_policy_path),
    ("symmetric_algorithms", apply_nop),
];

/// Validates the `policy` section.
fn apply_policy(config: &mut Option<&mut Config>,
                path: &str, item: &Item)
    -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), POLICY_SCHEMA)?;

    if let Some(config) = config {
        // Extract the inline policy.

        // XXX: This doesn't work because toml_edit bug
        // https://github.com/toml-rs/toml/issues/785
        //
        //let table = section.iter().collect::<Table>();
        //
        // Instead, we have to use a workaround:
        let mut table = Table::new();
        section.iter().for_each(|(k, v)| { table.insert(k, v.clone()); });

        let mut inline = DocumentMut::from(table);
        inline.remove("path");
        if inline.is_empty() {
            config.policy_inline = None;
        } else {
            config.policy_inline = Some(inline.to_string().into_bytes());
        }
    }

    Ok(())
}

/// Validates the `policy.path` value.
fn apply_policy_path(config: &mut Option<&mut Config>,
                     path: &str, item: &Item)
    -> Result<()>
{
    let path = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    if let Some(config) = config {
        config.policy_path = Some(path.into());
    }

    Ok(())
}

/// Schema for the `servers` section.
const SERVERS_SCHEMA: Schema = &[
    ("path", apply_servers_path),
];

/// Validates the `servers` section.
fn apply_servers(config: &mut Option<&mut Config>,
                 path: &str, item: &Item)
    -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, Some(path), section.iter(), SERVERS_SCHEMA)?;
    Ok(())
}

/// Validates the `servers.path` value.
fn apply_servers_path(config: &mut Option<&mut Config>,
                      path: &str, item: &Item)
    -> Result<()>
{
    let path = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    if let Some(config) = config {
        config.servers_path = Some(path.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Check that we can parse the configuration template when it only
    // contains defaults.
    #[test]
    fn check_config_template() {
        let template = ConfigFile::config_template(None, false, false)
            .expect("can create a configuration template");

        let config_file = ConfigFile::parse(&template)
            .expect("can parse the default configuration template");

        assert_eq!(config_file.into_config(), Config::default());
    }

    #[test]
    fn round_trip() {
        macro_rules! check {
            // Value is already quoted!!!
            ($key:ident, $value:expr, $value_str:expr,
             $value_getter:ident, $conf_getter:ident,
             $source:ident) => {{
                 let value_str: &str = &$value_str;

                 let config = Config::default();
                 assert_eq!(config.$source, Source::Default);

                 // Write the value to the config file, read the
                 // config file, and make sure we get the same value
                 // back.
                 let doc = format!("{} = {}", Config::$key(), value_str);
                 let config = ConfigFile::parse(&doc).unwrap().into_config();
                 assert_eq!(config.$value_getter, $value);
                 assert_eq!(config.$source, Source::ConfigFile);

                 // Get the value from the configuration file, and
                 // make sure we can round trip it.
                 let doc = format!("{} = {}", Config::$key(), config.$conf_getter());
                 let config = ConfigFile::parse(&doc).unwrap().into_config();
                 assert_eq!(config.$value_getter, $value);
                 assert_eq!(config.$source, Source::ConfigFile);
            }};
        }

        let fpr: Fingerprint
            = "F7173B3C7C685CD9ECC4191B74E445BA0E15C957".parse().expect("valid");

        // verbosity.
        for v in Verbosity::variants() {
            check!(
                verbosity_config_key,
                // Value.
                v,
                // Value as string for configuration file.
                format!("{:?}", v),
                verbosity,
                verbosity_config_value,
                verbosity_source);
        }

        // encrypt for self
        check!(
            encrypt_for_self_config_key,
            // Value.
            BTreeSet::from_iter(std::iter::once(fpr.clone())),
            // Value as string for configuration file.
            format!("[ \"{}\" ]", fpr),
            encrypt_for_self,
            encrypt_for_self_config_value,
            encrypt_for_self_source);

        // encrypt profile
        for v in Profile::variants() {
            check!(
                encrypt_profile_config_key,
                // Value.
                v,
                // Value as string for configuration file.
                format!("{:?}", v),
                encrypt_profile,
                encrypt_profile_config_value,
                encrypt_profile_source);
        }

        // signer self sign
        check!(
            sign_signer_self_config_key,
            // Value.
            BTreeSet::from_iter(std::iter::once(fpr.clone())),
            // Value as string for configuration file.
            format!("[ \"{}\" ]", fpr),
            sign_signer_self,
            sign_signer_self_config_value,
            sign_signer_self_source);

        // pki vouch certifier self
        check!(
            pki_vouch_certifier_self_config_key,
            // Value.
            Some(fpr.clone()),
            // Value as string for configuration file.
            format!("\"{}\"", fpr),
            pki_vouch_certifier_self,
            pki_vouch_certifier_self_config_value,
            pki_vouch_certifier_self_source);
        check!(
            pki_vouch_certifier_self_config_key,
            // Value.
            None,
            // Value as string for configuration file.
            format!("\"\""),
            pki_vouch_certifier_self,
            pki_vouch_certifier_self_config_value,
            pki_vouch_certifier_self_source);

        // pki vouch expiration.
        check!(
            pki_vouch_expiration_config_key,
            // Value.
            Expiration::new("1d").unwrap(),
            // Value as string for configuration file.
            "\"1d\"",
            pki_vouch_expiration,
            pki_vouch_expiration_config_value,
            pki_vouch_expiration_source);

        // key generate cipher suite.
        check!(
            cipher_suite_config_key,
            // Value.
            CipherSuite::Rsa2k,
            // Value as string for configuration file.
            "\"rsa2k\"",
            cipher_suite,
            cipher_suite_config_value,
            cipher_suite_source);

        // key generate profile
        check!(
            key_generate_profile_config_key,
            // Value.
            Profile::RFC9580,
            // Value as string for configuration file.
            "\"rfc9580\"",
            key_generate_profile,
            key_generate_profile_config_value,
            key_generate_profile_source);

        // keyservers.
        check!(
            key_servers_config_key,
            // Value.
            &[ "hkps://some.example", "hkp://other.example" ],
            // Value as string for configuration file.
            "[ \"hkps://some.example\", \"hkp://other.example\" ]",
            key_servers,
            key_servers_config_value,
            key_servers_source);

        // network search iterations.
        check!(
            network_search_iterations_config_key,
            // Value.
            2,
            // Value as string for configuration file.
            "2",
            network_search_iterations,
            network_search_iterations_config_value,
            network_search_iterations_source);

        // network search use dane.
        check!(
            network_search_use_dane_config_key,
            // Value.
            false,
            // Value as string for configuration file.
            "false",
            network_search_use_dane,
            network_search_use_dane_config_value,
            network_search_use_dane_source);

        // network search use wkd.
        check!(
            network_search_use_wkd_config_key,
            // Value.
            false,
            // Value as string for configuration file.
            "false",
            network_search_use_wkd,
            network_search_use_wkd_config_value,
            network_search_use_wkd_source);
    }
}
