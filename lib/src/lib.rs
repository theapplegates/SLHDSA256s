//! A high-level API for Sequoia.

use std::{
    borrow::Cow,
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::SystemTime,
};

#[macro_use] mod log;
#[macro_use] mod macros;

use anyhow::Context;

// Re-exports.
pub use anyhow;
pub use sequoia_cert_store as cert_store;
pub use sequoia_directories as directories;
pub use sequoia_keystore as key_store;
pub use sequoia_ipc as ipc;
pub use sequoia_net as net;
pub use sequoia_openpgp as openpgp;
pub use sequoia_policy_config as policy_config;
pub use sequoia_wot as wot;

use openpgp::Fingerprint;
use openpgp::cert::raw::RawCertParser;
use openpgp::crypto::Password;
use openpgp::packet::Key;
use openpgp::packet::key;
use openpgp::parse::Parse;
use openpgp::policy::NullPolicy;
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;

use cert_store::{
    LazyCert,
    StoreUpdate,
};

#[macro_use] pub mod transitional;

pub mod cert;
pub mod consts;
pub mod decrypt;
pub mod encrypt;
pub mod inspect;
pub mod list;
pub mod sign;
pub mod types;
use types::StateDirectory;

mod best_userid;
mod builder;
pub use builder::SequoiaBuilder;
mod compat;
pub mod config;
use config::Config;
use config::ConfigFile;
mod errors;
pub use errors::Error;
mod keys;
pub use keys::GetKeysOptions;
pub use keys::KeyType;
mod lookup;
pub mod packet;
pub mod prompt;
mod password_cache;
mod time;
pub use time::Time;
pub mod verify;

// XXX transitional: Switch to our own Error type.
pub type Result<T, E=anyhow::Error> = anyhow::Result<T, E>;

static STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();
static NULL_POLICY: &NullPolicy = unsafe { &NullPolicy::new() };
const TRACE: bool = false;

pub struct Sequoia {
    /// The home directory.
    ///
    /// If `None`, then the `Sequoia` instance should operate in
    /// stateless mode.
    home: Option<Cow<'static, sequoia_directories::Home>>,

    /// The configuration.
    config_file: ConfigFile,
    config: Config,

    /// The current time.
    time: Clock,

    /// Overrides the path to the cert store.
    cert_store_path: Option<types::StateDirectory>,

    /// This will be set if the cert store has not been disabled, OR
    /// --keyring is passed.
    cert_store: OnceLock<WotStore>,

    /// Additional keyrings to read.
    keyrings: Vec<PathBuf>,

    /// Map from key fingerprint to cert fingerprint and the key.
    keyring_tsks: OnceLock<BTreeMap<
            Fingerprint,
        (Fingerprint, Key<key::PublicParts, key::UnspecifiedRole>)>>,

    /// The local trust root, as set in the cert store.
    trust_root_local: OnceLock<Option<Fingerprint>>,

    /// Additional trust roots.
    trust_roots: Vec<Fingerprint>,

    /// The key store.
    key_store_path: Option<StateDirectory>,
    key_store: once_cell::sync::OnceCell<Mutex<key_store::Keystore>>,

    /// Path to our IPC servers.
    ipc_server_path: PathBuf,

    /// A password cache.  When encountering a locked key, we first
    /// consult the password cache.  The passwords are only tried if
    /// it is safe.  That is, the passwords are only tried if we are
    /// sure that the key is not protected by a retry counter.  If the
    /// password cache doesn't contain the correct password, or the
    /// key is protected by a retry counter, the user is prompted to
    /// unlock the key.  The correct password is added to the cache.
    pub password_cache: Mutex<Vec<Password>>,
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

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Returns a reference to the configuration file.
    pub fn config_file(&self) -> &ConfigFile {
        &self.config_file
    }

    /// Returns the OpenPGP policy.
    pub fn policy(&self) -> &openpgp::policy::StandardPolicy<'static> {
        self.config.policy()
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

    /// Returns whether the cert store is disabled.
    fn no_rw_cert_store(&self) -> bool {
        self.cert_store_path.as_ref()
            .map(|s| s.is_none())
            .unwrap_or(self.stateless())
    }

    /// Returns the cert store's base directory, if it is enabled.
    pub fn cert_store_base(&self) -> Option<PathBuf> {
        let default = || if let Ok(path) = std::env::var("PGP_CERT_D") {
            Some(PathBuf::from(path))
        } else {
            self.home()
                .map(|h| h.data_dir(sequoia_directories::Component::CertD))
        };

        if let Some(state) = self.cert_store_path.as_ref() {
            match state {
                StateDirectory::Absolute(p) => Some(p.clone()),
                StateDirectory::Default => default(),
                StateDirectory::None => None,
            }
        } else {
            default()
        }
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn cert_store(&self) -> Result<Option<&WotStore>> {
        if self.no_rw_cert_store()
            && self.keyrings.is_empty()
        {
            // The cert store is disabled.
            return Ok(None);
        }

        if let Some(cert_store) = self.cert_store.get() {
            // The cert store is already initialized, return it.
            return Ok(Some(cert_store));
        }

        let create_dirs = |path: &Path| -> Result<()> {
            use std::fs::DirBuilder;

            let mut b = DirBuilder::new();
            b.recursive(true);

            // Create the parent with the normal umask.
            if let Some(parent) = path.parent() {
                // Note: since recursive is turned on, it is not an
                // error if the directory exists, which is exactly
                // what we want.
                b.create(parent)
                    .with_context(|| {
                        format!("Creating the directory {:?}", parent)
                    })?;
            }

            // Create path with more restrictive permissions.
            platform!{
                unix => {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                },
                windows => {
                },
            }

            b.create(path)
                .with_context(|| {
                    format!("Creating the directory {:?}", path)
                })?;

            Ok(())
        };

        // We need to initialize the cert store.
        let mut cert_store = if ! self.no_rw_cert_store() {
            // Open the cert-d.

            let path = self.cert_store_base()
                .expect("just checked that it is configured");

            create_dirs(&path)
                .and_then(|_| cert_store::CertStore::open(&path))
                .with_context(|| {
                    format!("While opening the certificate store at {:?}",
                            &path)
                })?
        } else {
            cert_store::CertStore::empty()
        };

        let keyring = cert_store::store::Certs::empty();
        let mut tsks = BTreeMap::new();
        let mut error = None;
        for filename in self.keyrings.iter() {
            let f = std::fs::File::open(filename)
                .with_context(|| format!("Open {:?}", filename))?;
            let parser = RawCertParser::from_reader(f)
                .with_context(|| format!("Parsing {:?}", filename))?;

            for cert in parser {
                match cert {
                    Ok(cert) => {
                        for key in cert.keys() {
                            if key.has_secret() {
                                tsks.insert(
                                    key.fingerprint(),
                                    (cert.fingerprint(), key.clone()));
                            }
                        }

                        keyring.update(Arc::new(cert.into()))
                            .expect("implementation doesn't fail");
                    }
                    Err(err) => {
                        eprint!("Parsing certificate in {:?}: {}",
                                filename, err);
                        error = Some(err);
                    }
                }
            }
        }

        self.keyring_tsks.set(tsks).expect("uninitialized");

        if let Some(err) = error {
            return Err(err).context("Parsing keyrings");
        }

        cert_store.add_backend(
            Box::new(keyring),
            cert_store::AccessMode::Always);

        // Sync certs from GnuPG's state if we are using the user's
        // default home directory.
        if self.home().map(|h| h.is_default_location())
            .unwrap_or(false)
            && std::env::var("GNUPGHOME").is_err()
        {
            if let Err(e) = crate::compat::sync_from_gnupg(self, &cert_store) {
                self.warn(format_args!(
                    "Syncing state from GnuPG failed: {}", e));
            }
        }

        let cert_store = WotStore::from_store(
            cert_store, Box::new(self.policy().clone()) as Box::<dyn Policy>,
            self.time());

        let _ = self.cert_store.set(cert_store);

        Ok(Some(self.cert_store.get().expect("just configured")))
    }

    fn no_cert_store_err() -> errors::Error {
        errors::Error::state_disabled("certificate store")
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns an error.
    pub fn cert_store_or_else<'s>(&'s self) -> Result<&'s WotStore> {
        self.cert_store().and_then(|cert_store| cert_store.ok_or_else(|| {
            Self::no_cert_store_err().into()
        }))
    }

    /// Returns a reference to the underlying certificate directory,
    /// if it is configured.
    ///
    /// If the cert direcgory is disabled, returns an error.
    pub fn certd_or_else(&self)
        -> Result<&cert_store::store::certd::CertD<'static>>
    {
        const NO_CERTD_ERR: &str =
            "A local trust root and other special certificates are \
             only available when using an OpenPGP certificate \
             directory";

        let cert_store = self.cert_store_or_else()
            .with_context(|| NO_CERTD_ERR.to_string())?;

        cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))
    }


    /// Returns a web-of-trust query builder.
    ///
    /// The trust roots are already set appropriately.
    pub fn wot_query(&self)
        -> Result<wot::NetworkBuilder<&WotStore>>
    {
        let cert_store = self.cert_store_or_else()?;
        let network = wot::NetworkBuilder::rooted(cert_store,
                                                  &*self.trust_roots());
        Ok(network)
    }

    /// Returns the local trust root, creating it if necessary.
    pub fn local_trust_root(&self) -> Result<Arc<LazyCert<'static>>> {
        self.certd_or_else()?.trust_root().map(|(cert, _created)| {
            cert
        })
    }

    /// Returns the trust roots, including the cert store's trust
    /// root, if any.
    pub fn trust_roots(&self) -> Vec<Fingerprint> {
        let trust_root_local = self.trust_root_local.get_or_init(|| {
            self.cert_store_or_else()
                .ok()
                .and_then(|cert_store| cert_store.certd())
                .and_then(|certd| {
                    match certd.certd().get(cert_store::store::openpgp_cert_d::TRUST_ROOT) {
                        Ok(Some((_tag, cert_bytes))) => Some(cert_bytes),
                        // Not found.
                        Ok(None) => None,
                        Err(err) => {
                            self.warn(format_args!(
                                "Error looking up local trust root: {}", err));
                            None
                        }
                    }
                })
                .and_then(|cert_bytes| {
                    match RawCertParser::from_bytes(&cert_bytes[..]) {
                        Ok(mut parser) => {
                            match parser.next() {
                                Some(Ok(cert)) => Some(cert.fingerprint()),
                                Some(Err(err)) => {
                                    self.warn(format_args!(
                                        "Local trust root is corrupted: {}",
                                        err));
                                    None
                                }
                                None =>  {
                                    self.warn(format_args!(
                                        "Local trust root is corrupted: \
                                         no data"));
                                    None
                                }
                            }
                        }
                        Err(err) => {
                            self.warn(format_args!(
                                "Error parsing local trust root: {}", err));
                            None
                        }
                    }
                })
        });

        if let Some(trust_root_local) = trust_root_local {
            self.trust_roots.iter().cloned()
                .chain(std::iter::once(trust_root_local.clone()))
                .collect()
        } else {
            self.trust_roots.clone()
        }
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns `Ok(None)`.
    pub fn key_store_path(&self) -> Result<Option<PathBuf>> {
        let default = || {
            Ok(self.home()
               .map(|h| h.data_dir(directories::Component::Keystore)))
        };

        if let Some(dir) = self.key_store_path.as_ref() {
            match dir {
                StateDirectory::Absolute(p) => Ok(Some(p.clone())),
                StateDirectory::Default => default(),
                StateDirectory::None => Ok(None),
            }
        } else {
            default()
        }
    }

    /// Returns whether the key store is disabled.
    fn no_key_store(&self) -> bool {
        self.key_store_path.as_ref()
            .map(|s| s.is_none())
            .unwrap_or(self.stateless())
    }

    fn no_key_store_err() -> errors::Error {
        errors::Error::state_disabled("key store")
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_path_or_else(&self) -> Result<PathBuf> {
        if self.no_key_store() {
            Err(Self::no_key_store_err().into())
        } else {
            self.key_store_path()?
                .ok_or_else(|| {
                    Self::no_key_store_err().into()
                })
        }
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn key_store(&self) -> Result<Option<&Mutex<key_store::Keystore>>> {
        if self.no_key_store() {
            return Ok(None);
        }

        self.key_store
            .get_or_try_init(|| {
                let c = key_store::Context::configure()
                    .home(self.key_store_path_or_else()?)
                    .lib(self.ipc_server_path())
                    .build()?;

                let ks = key_store::Keystore::connect(&c)
                    .context("Connecting to key store")?;

                Ok(Mutex::new(ks))
            })
            .map(Some)
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_or_else(&self) -> Result<&Mutex<key_store::Keystore>> {
        self.key_store().and_then(|key_store| key_store.ok_or_else(|| {
            Self::no_key_store_err().into()
        }))
    }

    /// Returns the secret keys found in any specified keyrings.
    pub fn keyring_tsks(&self)
        -> Result<&BTreeMap<Fingerprint,
                            (Fingerprint, Key<key::PublicParts, key::UnspecifiedRole>)>>
    {
        if let Some(keyring_tsks) = self.keyring_tsks.get() {
            Ok(keyring_tsks)
        } else {
            // This also initializes keyring_tsks.
            self.cert_store()?;

            // If something went wrong, we just set it to an empty
            // map.
            Ok(self.keyring_tsks.get_or_init(|| BTreeMap::new()))
        }
    }

    /// Returns the path to the IPC servers.
    pub fn ipc_server_path(&self) -> &Path {
        &self.ipc_server_path
    }

    /// Emits a warning.
    pub(crate) fn warn(&self, msg: std::fmt::Arguments) {
        let _ = msg; // XXX
    }

    /// Emits a warning showing an error message.
    pub(crate) fn warn_err(&self, err: &anyhow::Error) {
        let _ = err; // XXX
    }
}

#[derive(Clone, Default)]
enum Clock {
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

impl Clock {
    /// Returns the configured time.
    fn get(&self) -> SystemTime {
        match self {
            Clock::Realtime => SystemTime::now(),
            Clock::Frozen(t) => *t,
            Clock::Fix(t) => *t,
        }
    }

    /// Returns whether the configured time approximates the current
    /// time.
    fn is_now(&self) -> bool {
        ! matches!(self, Clock::Fix(_))
    }
}

/// A shorthand for our store type.
type WotStore
    = wot::store::CertStore<'static, 'static, cert_store::CertStore<'static>>;

/// The creation time for the trust root and intermediate CAs.
///
/// We use a creation time in the past (Feb 2002) so that it is still
/// possible to use the CA when the reference time is in the past.
// XXX: This is copied from sequoia-cert-store.  It would be nice to
// import it, but it is private.
pub fn ca_creation_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::new(1014235320, 0)
}
