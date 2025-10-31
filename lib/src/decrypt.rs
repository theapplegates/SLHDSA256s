//! Decryption.

use anyhow::Context as _;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::types::SymmetricAlgorithm;
use openpgp::KeyHandle;
use openpgp::crypto;
use openpgp::{Fingerprint, Cert, KeyID, Result};
use openpgp::packet;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;
use openpgp::parse::PacketParser;
use openpgp::parse::PacketParserResult;
use openpgp::parse::stream::DecryptionHelper;
use openpgp::parse::stream::DecryptorBuilder;
use openpgp::parse::stream::MessageStructure;
use openpgp::parse::stream;
use openpgp::types::KeyFlags;

use sequoia_keystore as keystore;

use crate::Sequoia;
use crate::prompt::Prompt as _;
use crate::prompt::check::CheckRemoteKey;
use crate::prompt::check::CheckSkesks;
use crate::prompt;
use crate::types::PreferredUserID;
use crate::types::SessionKey;
use crate::verify::VerificationHelper;
use crate::verify;

const TRACE: bool = false;

/// The trait for collecting output.
pub trait Stream {
    /// Output from [`decrypt`](Builder::decrypt) and
    /// [`decrypt_unwrap`](Builder::decrypt_unwrap).
    fn output(&mut self, params: &Params, output: Output) -> Result<()>;
}

impl<T> Stream for Box<T>
where
    T: Stream + ?Sized
{
    fn output(&mut self, params: &Params, output: Output) -> Result<()> {
        self.as_mut().output(params, output)
    }
}

/// Collects the output in the specified vector.
impl Stream for &mut Vec<Output> {
    fn output(&mut self, _params: &Params, output: Output) -> Result<()> {
        self.push(output);
        Ok(())
    }
}

/// Discards the output.
impl Stream for () {
    fn output(&mut self, _params: &Params, _output: Output) -> Result<()> {
        Ok(())
    }
}

/// The decryption parameters.
///
/// These parameters are used by [`decrypt`](Builder::decrypt) and
/// [`decrypt_unwrap`](Builder::decrypt_unwrap).
#[derive(Clone)]
pub struct Params<'sequoia> {
    vparams: verify::Params<'sequoia>,
    secret_keys: Vec<Cert>,
    session_keys: Vec<SessionKey>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        self.vparams.sequoia()
    }

    /// Returns the number of signatures that have to be authenticated
    /// for the verification to succeed.
    ///
    /// See [`Builder::signatures`].
    pub fn signatures(&self) -> usize {
        self.vparams.signatures()
    }

    /// Returns the set of designated signers.
    ///
    /// See [`Builder::designated_signers`].
    pub fn designated_signers(&self) -> Option<&[Cert]> {
        self.vparams.designated_signers()
    }

    /// Returns the verification parameters.
    pub fn verify_params(&self) -> &verify::Params<'sequoia> {
        &self.vparams
    }

    /// Returns the pre-loaded secret keys.
    ///
    /// See [`Builder::secret_keys`].
    pub fn secret_keys(&self) -> &[Cert] {
        &self.secret_keys[..]
    }

    /// Returns the pre-loaded session keys.
    pub fn session_keys(&self) -> &[SessionKey] {
        &self.session_keys[..]
    }
}

/// Decrypt messages.
///
/// This command builder is used to decrypt messages.
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia> {
    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Sets the number of required authenticated signatures.
    ///
    /// The default depends on the designated signers setting (see
    /// [`Builder::designated_signers`]).  If set, one authenticated
    /// signature is required.  Otherwise, no authenticated signatures
    /// are required.
    ///
    /// Note: [`decrypt_unwrap`](Builder::decrypt_unwrap) does not
    /// apply a signing policy and silently ignores this parameter.
    pub fn signatures(&mut self, signatures: usize) -> &mut Self {
        self.params.vparams.signatures = signatures;

        self
    }

    /// Sets the designated signers.
    ///
    /// The specified certificates (and no other certificates) are
    /// considered authenticated.
    ///
    /// By default, signer certificates are authenticated using the
    /// web of trust using certificates from the certificate store
    /// (unless disabled with [`SequoiaBuilder::stateless`]) and any
    /// configured keyrings (see [`SequoiaBuiler::add_keyring`]).
    /// This disables the use of the web of trust and only considers
    /// signatures by the specified certificates.
    ///
    /// Note: [`decrypt_unwrap`](Builder::decrypt_unwrap) does not
    /// apply a signing policy and silently ignores this parameter.
    ///
    ///   [`SequoiaBuilder::stateless`]: crate::SequoiaBuilder::stateless
    ///   [`SequoiaBuiler::add_keyring`]: crate::SequoiaBuilder::add_keyring
    pub fn designated_signers(&mut self, certs: Vec<Cert>) -> &mut Self {
        self.params.vparams.designated_signers = Some(certs);

        self
    }

    /// Sets the secret keys to try.
    ///
    /// The secret keys are tried in addition to the key store, if it
    /// hasn't been disabled.
    pub fn secret_keys(&mut self, secret_keys: Vec<Cert>) -> &mut Self {
        self.params.secret_keys = secret_keys;

        self
    }

    /// Sets session keys to try.
    ///
    /// The session keys are tried in addition to the key store, if
    /// it hasn't been disabled.
    pub fn session_keys(&mut self, session_keys: Vec<SessionKey>) -> &mut Self {
        self.params.session_keys = session_keys;

        self
    }

    /// Decrypts the specified message with the configured parameters.
    ///
    /// Returns `Ok` if the message could be verified.  See
    /// [`verify::Builder`] for details.  Note: as documented in
    /// [`Builder::designated_signers`], the signing policy is
    /// slightly different when decrypting a message vs. verifying a
    /// signed message: when decrypting a message, if no designated
    /// signers have been set, no authenticated signatures are
    /// required by default.
    ///
    /// If you don't want to implement [`Stream`], you can pass `&mut
    /// Vec<Output>` to collect the status messages, or `()` to ignore
    /// them.
    pub fn decrypt<'a, I, O, S, P>(&self, input: I, mut output: O,
                                   prompt: P, stream: S) -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream + verify::Stream + 'a,
        P: prompt::Prompt,
    {
        let &Builder {
            params: Params {
                vparams: verify::Params {
                    sequoia,
                    detached_sig_arg: _,
                    detached_sig_value: _,
                    signatures,
                    ref designated_signers,
                },
                ref secret_keys,
                ref session_keys,
            },
        } = self;

        let proxy: Rc<RefCell<Box<dyn verify::VerifyDecryptStream>>>
            = Rc::new(RefCell::new(Box::new(StreamProxy {
                stream: Box::new(stream),
                params: &self.params,
            })));

        let mut helper = Helper::new(
            sequoia, signatures, designated_signers.clone(),
            secret_keys.clone(), session_keys.clone(), prompt);

        helper.stream
            = Some((Rc::clone(&proxy),
                    &self.params));
        helper.vhelper.stream
            = Some((proxy,
                    Cow::Borrowed(&self.params.vparams)));

        let mut decryptor = DecryptorBuilder::from_reader(input)?
            .with_policy(sequoia.policy(), None, helper)
            .context("Decryption failed")?;

        io::copy(&mut decryptor, &mut output).context("Decryption failed")?;

        Ok(())
    }

    /// Decrypts the outer most encryption container with the
    /// configured parameters.
    ///
    /// Unlike [`Sequoia::decrypt`], this does not process the
    /// contents of the encryption container; it returns the content
    /// as is, which is often a signed message.
    ///
    /// Since this function does not process the content of the
    /// encryption container, it also does not verify the signatures.
    /// Thus, the signing policy parameters ([`Builder::signatures`]
    /// and [`Builder::designated_signers`]) are ignored.
    ///
    /// If you don't want to implement [`Stream`], you can pass `&mut
    /// Vec<Output>` to collect the status messages, or `()` to ignore
    /// them.
    pub fn decrypt_unwrap<I, O, S, P>(&self,
                                      input: I, mut output: O,
                                      prompt: P, stream: S)
        -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream + verify::Stream,
        P: prompt::Prompt,
    {
        let &Builder {
            params: Params {
                vparams: verify::Params {
                    sequoia,
                    detached_sig_arg: _,
                    detached_sig_value: _,
                    signatures: _,
                    designated_signers: _,
                },
                ref secret_keys,
                ref session_keys,
            },
        } = self;

        let proxy: Rc<RefCell<Box<dyn verify::VerifyDecryptStream>>>
            = Rc::new(RefCell::new(Box::new(StreamProxy {
                stream: Box::new(stream),
                params: &self.params,
            })));

        let mut helper = Helper::new(
            sequoia, 0, None,
            secret_keys.clone(), session_keys.clone(), prompt);

        helper.stream
            = Some((Rc::clone(&proxy),
                    &self.params));
        helper.vhelper.stream
            = Some((proxy,
                    Cow::Borrowed(&self.params.vparams)));

        let mut ppr = PacketParser::from_reader(input)?;

        let mut pkesks: Vec<packet::PKESK> = Vec::new();
        let mut skesks: Vec<packet::SKESK> = Vec::new();
        while let PacketParserResult::Some(mut pp) = ppr {
            let sym_algo_hint = match &pp.packet {
                Packet::SEIP(SEIP::V2(seip)) => Some(seip.symmetric_algo()),
                _ => None,
            };

            match pp.packet {
                Packet::SEIP(_) => {
                    {
                        let mut decrypt = |algo, secret: &crypto::SessionKey| {
                            pp.decrypt(algo, secret).is_ok()
                        };
                        helper.decrypt(&pkesks[..], &skesks[..], sym_algo_hint,
                                       &mut decrypt)?;
                    }
                    if ! pp.processed() {
                        return Err(
                            openpgp::Error::MissingSessionKey(
                                "No session key".into()).into());
                    }

                    io::copy(&mut pp, &mut output)?;
                    return Ok(());
                },
                #[allow(deprecated)]
                Packet::MDC(ref mdc) => if ! mdc.valid() {
                    return Err(openpgp::Error::ManipulatedMessage.into());
                },
                _ => (),
            }

            let (p, ppr_tmp) = pp.recurse()?;
            match p {
                Packet::PKESK(pkesk) => pkesks.push(pkesk),
                Packet::SKESK(skesk) => skesks.push(skesk),
                _ => (),
            }
            ppr = ppr_tmp;
        }

        Ok(())
    }
}

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// A key is locked, but not trying cached passwords, because the
    /// key may be protected by a retry counter.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct NotTryingCachedPasswords {
        pub key_handle: KeyHandle,
        pub userid: PreferredUserID,
        pub cert: Option<Cert>,
    }

    /// We decrypted a PKESK, but the session key was not able to
    /// decrypt the message.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct BadSessionKey {
        pub key_handle: KeyHandle,
        pub userid: PreferredUserID,
        pub cert: Option<Cert>,
    }

    #[non_exhaustive]
    #[derive(Debug)]
    pub struct KeyStoreUnreachable {
        pub error: anyhow::Error,
    }

    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    pub enum Info {
        /// A key is locked, but not trying cached passwords, because
        /// the key may be protected by a retry counter.
        #[error("{}, {} is locked, but not trying cached passwords, \
                 because the key may be protected by a retry counter.",
                .0.key_handle, .0.userid.display())]
        NotTryingCachedPasswords(NotTryingCachedPasswords),

        /// Decrypted a session key, but the session key was not able
        /// to decrypt the message.
        #[error("Unlocked {}, {}, but it failed to decrypt the message",
                .0.key_handle, .0.userid.display())]
        BadSessionKey(BadSessionKey),

        /// The key store is enabled, but we were unable to the
        /// connect to it.
        #[error("Warning: unable to connect to keystore: {}",
                .0.error)]
        KeyStoreUnreachable(KeyStoreUnreachable),
    }

    /// The certificate, SKESK, or session key that was used to decrypt
    /// the SEIPD packet.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub enum Decryptor {
        /// The certificate was used to decrypt the SEIPD packet.
        Cert(Cert, Key<key::PublicParts, key::UnspecifiedRole>),

        /// The key was used to decrypt the SEIPD packet.
        ///
        /// If the certificate is available, [`Decryptor::Cert`] will be
        /// returned.  However, it may happen that a key on the key store,
        /// but the certificate is not in the certificate store.  In cases
        /// like this, this variant is returned.
        Key(Key<key::PublicParts, key::UnspecifiedRole>),

        /// The SKESK was used to decrypt the SEIPD packet.
        SKESK(SKESK),

        /// The preloaded-session key was used to decrypt the SEIPD
        /// packet.
        SessionKey(SessionKey),
    }

    /// The message was decrypted using the specified decryptor.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Decrypted {
        pub decryptor: Decryptor,
        pub session_key: crypto::SessionKey,
    }

    /// The message could not be decrypted.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct DecryptionFailed {
        pub pkesks: Vec<PKESK>,
        pub skesks: Vec<SKESK>,
    }

    /// Information about the operation.
    ///
    /// This includes summary statistics.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Report {
        pub verification: verify::output::Report,
    }
}

/// The variants of this enum are the different types of output that
/// [`decrypt`](Builder::decrypt) and
/// [`decrypt_unwrap`](Builder::decrypt_unwrap) emit.
#[non_exhaustive]
#[derive(Debug)]
pub enum Output {
    Info(output::Info),
    Decrypted(output::Decrypted),
    DecryptionFailed(output::DecryptionFailed),
    MessageStructure(verify::output::MessageStructure),
    Report(output::Report),
}

impl Sequoia {
    /// Returns a builder for decrypting and verifying messages.
    ///
    /// See [`Builder`] for details.
    pub fn decrypt<'sequoia>(&'sequoia self) -> Builder<'sequoia> {
        Builder {
            params: Params {
                vparams: verify::Params {
                    sequoia: self,
                    detached_sig_arg: None,
                    detached_sig_value: None,
                    signatures: 10,
                    designated_signers: None,
                },
                secret_keys: Vec::new(),
                session_keys: Vec::new(),
            },
        }
    }
}

struct StreamProxy<'a> {
    stream: Box<dyn verify::VerifyDecryptStream + 'a>,
    params: &'a Params<'a>,
}

impl verify::Stream for StreamProxy<'_>
{
    fn output(&mut self, _params: &verify::Params, output: verify::Output)
        -> Result<()>
    {
        let output = match output {
            verify::Output::Report(report) => {
                Output::Report(output::Report {
                    verification: report,
                })
            },
            verify::Output::MessageStructure(s) => {
                Output::MessageStructure(s)
            },
        };
        Stream::output(&mut self.stream, self.params, output)
    }
}

impl Stream for StreamProxy<'_>
{
    fn output(&mut self, _params: &Params, output: Output) -> Result<()> {
        self.stream.output(self.params, output)
    }
}

pub struct Helper<'c>
{
    sequoia: &'c Sequoia,
    stream: Option<(Rc<RefCell<Box<dyn verify::VerifyDecryptStream + 'c>>>, &'c Params<'c>)>,
    vhelper: VerificationHelper<'c>,
    secret_keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>,
    key_identities: HashMap<KeyID, Arc<Cert>>,
    session_keys: Vec<SessionKey>,

    /// The fingerprint of the public key that we used to the decrypt
    /// the message.  If None and decryption was success then we
    /// decrypted it in some other way.
    decryptor: RefCell<Option<Fingerprint>>,

    prompt: Box<dyn prompt::Prompt + 'c>,
}

impl<'c> std::ops::Deref for Helper<'c> {
    type Target = VerificationHelper<'c>;

    fn deref(&self) -> &Self::Target {
        &self.vhelper
    }
}

impl<'c> std::ops::DerefMut for Helper<'c> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vhelper
    }
}

impl<'c> Helper<'c> {
    pub fn new<P>(sequoia: &'c Sequoia,
                  signatures: usize,
                  certs: Option<Vec<Cert>>,
                  secret_keys: Vec<Cert>,
                  session_keys: Vec<SessionKey>,
                  prompt: P)
        -> Self
    where
        P: prompt::Prompt + 'c
    {
        let mut keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>
            = HashMap::new();
        let mut identities: HashMap<KeyID, Arc<Cert>> = HashMap::new();
        for tsk in secret_keys {
            let cert = Arc::new(tsk.clone().strip_secret_key_material());
            for ka in tsk.keys().secret()
                // XXX: Should use the message's creation time that we do not know.
                .with_policy(sequoia.policy(), sequoia.time())
                .for_transport_encryption().for_storage_encryption()
            {
                let id: KeyID = ka.key().fingerprint().into();
                let key = ka.key();
                keys.insert(id.clone(), (tsk.clone(), key.clone()));
                identities.insert(id.clone(), cert.clone());
            }
        }

        Helper {
            sequoia: &sequoia,
            stream: None,
            vhelper: VerificationHelper::new(&sequoia, signatures, certs),
            secret_keys: keys,
            key_identities: identities,
            session_keys,
            decryptor: RefCell::new(None),
            prompt: Box::new(prompt),
        }
    }

    /// Emit some output.
    fn output(&self, output: Output) -> Result<()> {
        use std::ops::DerefMut;
        if let Some((stream, params)) = self.stream.as_ref() {
            let mut stream = stream.borrow_mut();
            Stream::output(stream.deref_mut().as_mut(), params, output)
        } else {
            Ok(())
        }
    }

    /// Checks if a session key can decrypt the packet parser using
    /// `decrypt`.
    fn try_session_key(&self, fpr: &Fingerprint,
                       algo: Option<SymmetricAlgorithm>, sk: &crypto::SessionKey,
                       decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool)
                       -> Option<Option<Cert>>
    {
        if decrypt(algo, sk) {
            // XXX: make key identities map to certs, and failing that
            // look into the cert store.
            let cert = self.key_identities.get(&KeyID::from(fpr)).cloned();
            if let Some(cert) = &cert {
                // Prefer the reverse-mapped identity.
                self.decryptor.replace(Some(cert.fingerprint()));
            } else {
                // But fall back to the public key's fingerprint.
                self.decryptor.replace(Some(fpr.clone()));
            }

            Some(cert.map(|c| (*c).clone()))
        } else {
            None
        }
    }

    /// Tries to decrypt the given PKESK packet with `keypair` and try
    /// to decrypt the packet parser using `decrypt`.
    ///
    /// The outer Result is the error returned by the output callback.
    fn try_decrypt(&self, pkesk: &PKESK,
                   sym_algo: Option<SymmetricAlgorithm>,
                   keypair: &mut dyn crypto::Decryptor,
                   decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool)
                   -> Result<Option<Option<Cert>>>
    {
        let fpr = keypair.public().fingerprint();
        let Some((sym_algo, sk)) = pkesk.decrypt(&mut *keypair, sym_algo) else {
            return Ok(None);
        };
        if let Some(decrypted) = self.try_session_key(&fpr, sym_algo, &sk, decrypt) {
            let output = if let Some(cert) = decrypted.as_ref() {
                Output::Decrypted(output::Decrypted {
                    decryptor: output::Decryptor::Cert(cert.clone(), keypair.public().clone()),
                    session_key: sk,
                })
            } else {
                Output::Decrypted(output::Decrypted {
                    decryptor: output::Decryptor::Key(keypair.public().clone()),
                    session_key: sk,
                })
            };
            self.output(output)?;

            Ok(Some(decrypted))
        } else {
            Ok(None)
        }
    }
}

impl<'c> stream::VerificationHelper for Helper<'c> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        self.vhelper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        self.vhelper.check(structure)
    }
}

impl<'c> DecryptionHelper for Helper<'c> {
    fn decrypt(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
               sym_algo: Option<SymmetricAlgorithm>,
               decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool)
               -> openpgp::Result<Option<Cert>>
    {
        tracer!(TRACE, "DecryptionHelper::decrypt");
        t!("{} PKESKs, {} SKESKs", pkesks.len(), skesks.len());
        if pkesks.len() > 0 {
            t!("PKESKs: {}",
               pkesks
               .iter()
               .map(|pkesk| {
                   pkesk.recipient()
                       .map(|r| r.to_string())
                       .unwrap_or("wildcard".into())
               })
               .collect::<Vec<String>>()
               .join(", "));
        }

        // Before anything else, try the session keys
        t!("Trying the {} session keys", self.session_keys.len());
        for sk in &self.session_keys {
            let decrypted = if let Some(sa) = sk.symmetric_algo {
                decrypt(Some(sa), &sk.session_key)
            } else {
                // We don't know which algorithm to use,
                // try to find one that decrypts the message.
                (1u8..=19)
                    .map(SymmetricAlgorithm::from)
                    .any(|sa| decrypt(Some(sa), &sk.session_key))
            };
            if decrypted {
                self.output(Output::Decrypted(output::Decrypted {
                    decryptor: output::Decryptor::SessionKey(sk.clone()),
                    session_key: sk.session_key.clone(),
                }))?;
                return Ok(None);
            }
        }

        // Now, we try the secret keys that the user supplied on the
        // command line.

        // The outer Result is the error returned by the output callback.
        let mut decrypt_key = |slf: &Self, pkesk, cert, key: &Key<_, _>, may_prompt: bool| {
            let cancel_;
            let prompt: &Box<dyn prompt::Prompt> = if may_prompt {
                &slf.prompt
            } else {
                cancel_ = Box::new(prompt::Cancel::new()) as Box<dyn prompt::Prompt>;
                &cancel_
            };

            if let Ok(key) = slf.vhelper.sequoia()
                .decrypt_key(Some(cert), key.clone(), true, prompt)
            {
                let mut keypair = key.into_keypair()
                    .expect("decrypted secret key material");

                slf.try_decrypt(pkesk, sym_algo, &mut keypair, decrypt)
            } else {
                Ok(None)
            }
        };

        // First, we try those keys that we can use without prompting
        // for a password.
        t!("Trying the unencrypted PKESKs");
        for pkesk in pkesks {
            let keyid = pkesk.recipient().map(KeyID::from)
                .unwrap_or_else(KeyID::wildcard);
            if let Some((cert, key)) = self.secret_keys.get(&keyid) {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false)? {
                    return Ok(fp);
                }
            }
        }

        // Second, we try those keys that are encrypted.
        t!("Trying the encrypted PKESKs");
        for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient().map(KeyID::from);
            if let Some((cert, key)) = keyid.as_ref()
                .and_then(|k| self.secret_keys.get(k))
            {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true)? {
                    return Ok(fp);
                }
            }
        }

        // Third, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that we can use without
        // prompting for a password.
        t!("Trying unencrypted PKESKs for wildcard recipient");
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_none()) {
            for (cert, key) in self.secret_keys.values() {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false)? {
                    return Ok(fp);
                }
            }
        }

        // Fourth, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that are encrypted.
        t!("Trying encrypted PKESKs for wildcard recipient");
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_none()) {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            for (cert, key) in self.secret_keys.values() {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true)? {
                    return Ok(fp);
                }
            }
        }

        // Try the key store.
        t!("Trying the key store");
        match self.vhelper.sequoia().key_store_or_else() {
            Ok(ks) => {
                let mut ks = ks.lock().unwrap();
                match ks.decrypt(&pkesks[..]) {
                    // Success!
                    Ok((_i, fpr, sym_algo, sk)) => {
                        if let Some(fp) =
                            self.try_session_key(
                                &fpr, sym_algo, &sk, decrypt)
                        {
                            let keys = ks.find_key(KeyHandle::from(&fpr))
                                .with_context(|| {
                                    format!("Looking up {}", fpr)
                                })?;
                            let Some(key) = keys.into_iter().next() else {
                                // find_key should never return an
                                // empty result.  Instead it should
                                // return an error.  But be tolerant,
                                // just in case.
                                return Err(anyhow::anyhow!("Key for {} not found", fpr));
                            };

                            self.output(
                                Output::Decrypted(output::Decrypted {
                                    decryptor: output::Decryptor::Key(
                                        key.public_key().clone()),
                                    session_key: sk,
                                }))?;

                            return Ok(fp);
                        }
                    }

                    Err(err) => {
                        match err.downcast() {
                            Ok(keystore::Error::InaccessibleDecryptionKey(keys)) => {
                                // Get a reference to the softkeys backend.
                                let mut softkeys = if let Ok(backends) = ks.backends() {
                                    let mut softkeys = None;
                                    for mut backend in backends.into_iter() {
                                        if let Ok(id) = backend.id() {
                                            if id == "softkeys" {
                                                softkeys = Some(backend);
                                                break;
                                            }
                                        }
                                    }
                                    softkeys
                                } else {
                                    None
                                };

                                for key_status in keys.into_iter() {
                                    let pkesk = key_status.pkesk().clone();
                                    let mut key = key_status.into_key();
                                    let keyid = key.keyid();
                                    let (userid, cert) = self.sequoia.best_userid_for(
                                        &KeyHandle::from(&keyid),
                                        KeyFlags::empty()
                                            .set_storage_encryption()
                                            .set_transport_encryption(),
                                        true);

                                    // If we have any cached
                                    // passwords, and the key is not
                                    // protected by a retry counter,
                                    // try the cached passwords.
                                    //
                                    // Right now, we only try the
                                    // password cache with keys
                                    // managed by the softkeys
                                    // backend, which we know are not
                                    // protected by a retry counter.
                                    // It would be better to query the
                                    // key, but the key store doesn't
                                    // expose that yet information yet
                                    // so we use this heuristic for
                                    // now.
                                    let password_cache = self.sequoia.cached_passwords()
                                        .collect::<Vec<_>>();
                                    if ! password_cache.is_empty() {
                                        // There's currently no way to
                                        // go from a key handle to the
                                        // backend.
                                        let mut on_softkeys = false;
                                        if let Some(softkeys) = softkeys.as_mut() {
                                            let devices = softkeys.devices();
                                            if let Ok(devices) = devices {
                                                for mut device in devices.into_iter() {
                                                    let keys = device.keys();
                                                    if let Ok(keys) = keys {
                                                        for mut a_key in keys.into_iter() {
                                                            if let Ok(a_id) = a_key.id() {
                                                                if key.id().ok() == Some(a_id) {
                                                                    // Same id.  We have a match.
                                                                    on_softkeys = true;
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if on_softkeys {
                                            for password in password_cache.iter() {
                                                if let Ok(()) = key.unlock(password.clone()) {
                                                    if let Some(fp) = self.try_decrypt(
                                                        &pkesk, sym_algo, &mut key, decrypt)?
                                                    {
                                                        return Ok(fp);
                                                    }
                                                }
                                            }
                                        } else {
                                            self.output(Output::Info(output::Info::NotTryingCachedPasswords(
                                                output::NotTryingCachedPasswords {
                                                    key_handle: key.key_handle(),
                                                    userid: userid.clone(),
                                                    cert: cert.as_ref().ok().map(Clone::clone),
                                                })))?
                                        }
                                    }
                                    drop(password_cache);

                                    let mut context = prompt::ContextBuilder::password(
                                        prompt::Reason::UnlockKey)
                                        .sequoia(&self.vhelper.sequoia())
                                        .key(key.fingerprint());

                                    if let Ok(cert) = cert.as_ref() {
                                        context = context.cert(Cow::Borrowed(cert));
                                    }
                                    let mut context = context.build();

                                    let mut checker = CheckRemoteKey::optional(&mut key);

                                    match self.prompt.prompt(&mut context, &mut checker) {
                                        Ok(prompt::Response::Password(_)) => {
                                            if checker.unlocked() {
                                                if let Some(fp) = self.try_decrypt(
                                                    &pkesk, sym_algo, &mut key, decrypt)?
                                                {
                                                    return Ok(fp);
                                                } else {
                                                    self.output(Output::Info(output::Info::BadSessionKey(
                                                        output::BadSessionKey {
                                                            key_handle: key.key_handle(),
                                                            userid: userid.clone(),
                                                            cert: cert.as_ref().ok().map(Clone::clone),
                                                        })))?;
                                                }
                                            }
                                        }
                                        Ok(prompt::Response::NoPassword) => {
                                        }
                                        Err(prompt::Error::Cancelled(_)) => {
                                            // Skip.
                                        }
                                        Err(err) => {
                                            return Err(err).context(
                                                "Password prompt");
                                        }
                                    }

                                }
                            }
                            // Failed to decrypt using the keystore.
                            Ok(_err) => (),
                            Err(_err) => (),
                        }
                    }
                }
            }
            Err(err) => {
                self.output(Output::Info(output::Info::KeyStoreUnreachable(
                    output::KeyStoreUnreachable {
                        error: err,
                    })))?;
            }
        }

        if skesks.is_empty() {
            self.output(
                Output::DecryptionFailed(output::DecryptionFailed {
                    pkesks: pkesks.to_vec(),
                    skesks: skesks.to_vec(),
                }))?;

            return Err(anyhow::anyhow!("No key to decrypt message"));
        }

        // Finally, try to decrypt using the SKESKs.  Before
        // prompting, try all passwords supplied on the cli.
        for password in self.sequoia.cached_passwords() {
            for skesk in skesks {
                if let Some(sk) = skesk.decrypt(&password).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
                {
                    self.output(Output::Decrypted(output::Decrypted {
                        decryptor: output::Decryptor::SKESK(skesk.clone()),
                        session_key: sk,
                    }))?;
                    return Ok(None);
                }
            }
        }

        // Now prompt for passwords.
        let mut checker = CheckSkesks::new(skesks, decrypt);

        let mut context
            = prompt::ContextBuilder::password(
                prompt::Reason::DecryptMessage)
            .sequoia(&self.vhelper.sequoia())
            .build();
        let result = match self.prompt.prompt(&mut context, &mut checker) {
            Ok(prompt::Response::Password(p)) => {
                self.sequoia.cache_password(p);

                if let Some((i, sk)) = checker.resolve() {
                    self.output(Output::Decrypted(output::Decrypted {
                        decryptor: output::Decryptor::SKESK(skesks[i].clone()),
                        session_key: sk,
                    }))?;
                    Ok(None)
                } else {
                    // We shouldn't get here: if CheckSkesks returns a
                    // password, then it should also set sk.
                    Err(anyhow::anyhow!("Decryption failed."))
                }
            },
            Ok(prompt::Response::NoPassword)
                | Err(prompt::Error::Cancelled(_)) =>
            {
                Err(anyhow::anyhow!("Decryption failed."))
            }
            Err(err) => {
                Err(err).context("Password prompt")
            }
        };

        if result.is_err() {
            self.output(
                Output::DecryptionFailed(output::DecryptionFailed {
                    pkesks: pkesks.to_vec(),
                    skesks: skesks.to_vec(),
                }))?;
        }

        result
    }
}
