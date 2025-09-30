//! Decryption.

use anyhow::Context as _;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::types::SymmetricAlgorithm;
use openpgp::fmt::hex;
use openpgp::KeyHandle;
use openpgp::crypto;
use openpgp::{Fingerprint, Cert, KeyID, Result};
use openpgp::packet;
use openpgp::packet::prelude::*;
use openpgp::parse::{
    Parse,
    PacketParser,
    PacketParserResult,
};
use openpgp::parse::stream::DecryptionHelper;
use openpgp::parse::stream::DecryptorBuilder;
use openpgp::parse::stream::MessageStructure;
use openpgp::parse::stream;
use openpgp::types::KeyFlags;

use sequoia_cert_store as cert_store;
use cert_store::store::StoreError;

use sequoia_keystore as keystore;

use crate::Sequoia;
use crate::prompt::Prompt as _;
use crate::prompt;
use crate::transitional::output::cert::emit_cert;
use crate::types::SessionKey;
use crate::verify::VerificationHelper;
use crate::verify;

const TRACE: bool = false;

impl Sequoia {
    pub fn decrypt<P, S>(&self,
                         input: &mut (dyn io::Read + Sync + Send),
                         output: &mut (dyn io::Write + Sync + Send),
                         signatures: usize, certs: Vec<Cert>, secrets: Vec<Cert>,
                         dump_session_key: bool,
                         sk: Vec<SessionKey>,
                         batch: bool,
                         prompt: P,
                         verify_output_stream: S)
        -> Result<()>
    where
        P: prompt::Prompt,
        S: verify::Stream,
    {
        let mut helper = Helper::new(
            self, signatures,
            if certs.is_empty() {
                None
            } else {
                Some(certs.clone())
            },
            secrets, sk, dump_session_key, batch, prompt);

        let params = verify::Params {
            sequoia: self,
            detached_sig_arg: None,
            detached_sig_value: None,
            signatures,
            designated_signers: if certs.is_empty() {
                None
            } else {
                Some(certs)
            },
        };
        helper.vhelper.stream
            = Some((Box::new(verify_output_stream), Cow::Owned(params)));

        let mut decryptor = DecryptorBuilder::from_reader(input)?
            .with_policy(self.policy(), None, helper)
            .context("Decryption failed")?;

        io::copy(&mut decryptor, output).context("Decryption failed")?;

        let helper = decryptor.into_helper();
        helper.print_status();
        helper.vhelper.print_status();
        Ok(())
    }

    pub fn decrypt_unwrap<P>(&self,
                             input: &mut (dyn io::Read + Sync + Send),
                             output: &mut dyn io::Write,
                             secrets: Vec<Cert>,
                             session_keys: Vec<SessionKey>,
                             dump_session_key: bool,
                             batch: bool,
                             prompt: P)
        -> Result<()>
    where
        P: prompt::Prompt
    {
        let mut helper = Helper::new(self, 0, None, secrets,
                                     session_keys,
                                     dump_session_key,
                                     batch,
                                     prompt);

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

                    io::copy(&mut pp, output)?;
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

pub struct Helper<'c> {
    sequoia: &'c Sequoia,
    vhelper: VerificationHelper<'c>,
    secret_keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>,
    key_identities: HashMap<KeyID, Arc<Cert>>,
    session_keys: Vec<SessionKey>,
    dump_session_key: bool,

    /// XXX transitional: Remove.
    batch: bool,

    /// The fingerprint of the public key that we used to the decrypt
    /// the message.  If None and decryption was success then we
    /// decrypted it in some other.
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
                  signatures: usize, certs: Option<Vec<Cert>>, secrets: Vec<Cert>,
                  session_keys: Vec<SessionKey>,
                  dump_session_key: bool,
                  batch: bool,
                  prompt: P)
        -> Self
    where
        P: prompt::Prompt + 'c
    {
        let mut keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>
            = HashMap::new();
        let mut identities: HashMap<KeyID, Arc<Cert>> = HashMap::new();
        for tsk in secrets {
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
            vhelper: VerificationHelper::new(
                &sequoia, signatures, certs),
            secret_keys: keys,
            key_identities: identities,
            session_keys,
            dump_session_key,
            batch,
            decryptor: RefCell::new(None),
            prompt: Box::new(prompt),
        }
    }

    /// Checks if a session key can decrypt the packet parser using
    /// `decrypt`.
    fn try_session_key(&self, fpr: &Fingerprint,
                       algo: Option<SymmetricAlgorithm>, sk: crypto::SessionKey,
                       decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool)
                       -> Option<Option<Cert>>
    {
        if decrypt(algo, &sk) {
            if self.dump_session_key {
                weprintln!("Session key: {}", hex::encode(&sk));
            }

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
    fn try_decrypt(&self, pkesk: &PKESK,
                   sym_algo: Option<SymmetricAlgorithm>,
                   keypair: &mut dyn crypto::Decryptor,
                   decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool)
                   -> Option<Option<Cert>>
    {
        let fpr = keypair.public().fingerprint();
        let (sym_algo, sk) = pkesk.decrypt(&mut *keypair, sym_algo)?;
        self.try_session_key(&fpr, sym_algo, sk, decrypt)
    }

    /// Prints what certificate was used to decrypt the message.
    fn print_status(&self) {
        make_qprintln!(self.quiet);

        let decryptor = self.decryptor.borrow();
        if let Some(ref fpr) = *decryptor {
            let kh = KeyHandle::from(fpr);

            if let Ok(cert) = self.sequoia.lookup_one(kh, None, true) {
                qprintln!("Decrypted by {}, {}",
                          cert.fingerprint(),
                          self.sequoia.best_userid(&cert, true).display());
            } else {
                qprintln!("Decrypted by {}, unknown", fpr);
            }
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

        make_qprintln!(self.quiet);

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
                qprintln!("Encrypted with Session Key {}",
                          sk.display_sensitive());
                return Ok(None);
            }
        }

        // Now, we try the secret keys that the user supplied on the
        // command line.

        let mut decrypt_key = |slf: &Self, pkesk, cert, key: &Key<_, _>, may_prompt: bool| {
            let cancel_;
            let prompt: &Box<dyn prompt::Prompt> = if may_prompt {
                &self.prompt
            } else {
                cancel_ = Box::new(prompt::Cancel::new()) as Box<dyn prompt::Prompt>;
                &cancel_
            };

            slf.vhelper.sequoia().decrypt_key(Some(cert), key.clone(), true, prompt)
                .ok()
                .and_then(|key| {
                    let mut keypair = key.into_keypair()
                        .expect("decrypted secret key material");

                    slf.try_decrypt(pkesk, sym_algo, &mut keypair, decrypt)
                })
        };

        // First, we try those keys that we can use without prompting
        // for a password.
        t!("Trying the unencrypted PKESKs");
        for pkesk in pkesks {
            let keyid = pkesk.recipient().map(KeyID::from)
                .unwrap_or_else(KeyID::wildcard);
            if let Some((cert, key)) = self.secret_keys.get(&keyid) {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false) {
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
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true) {
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
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false) {
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
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true) {
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
                                &fpr, sym_algo, sk, decrypt)
                        {
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
                                    // Right now,we only try the
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
                                                        &pkesk, sym_algo, &mut key, decrypt)
                                                    {
                                                        return Ok(fp);
                                                    }
                                                }
                                            }
                                        } else {
                                            eprintln!(
                                                "{}, {} is locked, but not \
                                                 trying cached passwords, \
                                                 because the key may be \
                                                 protected by a retry counter.",
                                                keyid, userid.display());
                                        }
                                    }
                                    drop(password_cache);

                                    loop {
                                        if self.batch {
                                            eprintln!(
                                                "{}, {} is locked, but not \
                                                 prompting for a password, \
                                                 because you passed --batch.",
                                                keyid, userid.display());
                                            break;
                                        }

                                        let mut context = prompt::ContextBuilder::password(
                                            prompt::Reason::UnlockKey)
                                            .sequoia(&self.vhelper.sequoia())
                                            .key(key.fingerprint());

                                        if let Ok(cert) = cert.as_ref() {
                                            context = context.cert(Cow::Borrowed(cert));
                                        }
                                        let mut context = context.build();

                                        match self.prompt.prompt(&mut context) {
                                            Ok(prompt::Response::Password(p)) => {
                                                if let Err(_err) = key.unlock(p) {
                                                    weprintln!("Bad password.");
                                                    continue;
                                                }
                                            }
                                            Ok(prompt::Response::NoPassword) => {
                                                weprintln!("Skipping {}, {}",
                                                           keyid,
                                                           userid.display());
                                                break;
                                            }
                                            Err(prompt::Error::Cancelled(_)) => {
                                                // Skip.
                                                break;
                                            }
                                            Err(err) => {
                                                return Err(err).context(
                                                    "Password prompt");
                                            }
                                        };

                                        if let Some(fp) = self.try_decrypt(
                                            &pkesk, sym_algo, &mut key, decrypt)
                                        {
                                            return Ok(fp);
                                        } else {
                                            break;
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
                weprintln!("Warning: unable to connect to keystore: {}",
                           err);
            }
        }

        if skesks.is_empty() {
            weprintln!("No key to decrypt message.  The message appears \
                        to be encrypted to:");
            weprintln!();

            for recipient in pkesks.iter().map(|p| p.recipient()) {
                if let Some(r) = recipient {
                    let certs = self.sequoia.lookup(
                        std::iter::once(&r),
                        Some(KeyFlags::empty()
                             .set_storage_encryption()
                             .set_transport_encryption()),
                        false,
                        true);

                    match certs {
                        Ok(certs) => {
                            for cert in certs {
                                emit_cert(&mut io::stderr(), self.sequoia, &cert)?;
                            }
                        }
                        Err(err) => {
                            if let Some(StoreError::NotFound(_))
                                = err.downcast_ref()
                            {
                                weprintln!(initial_indent = " - ",
                                           "{}, certificate not found", r);
                            } else {
                                weprintln!(initial_indent = " - ",
                                           "{}, error looking up certificate: {}",
                                           r, err);
                            }
                        }
                    }
                } else {
                    weprintln!(initial_indent = " - ",
                               "anonymous recipient, certificate not found");
                }
            }

            weprintln!();
            return Err(anyhow::anyhow!("No key to decrypt message"));
        }

        // Finally, try to decrypt using the SKESKs.  Before
        // prompting, try all passwords supplied on the cli.
        for password in self.sequoia.cached_passwords() {
            for skesk in skesks {
                if let Some(sk) = skesk.decrypt(&password).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
                {
                    if self.dump_session_key {
                        weprintln!("Session key: {}", hex::encode(&sk));
                    }
                    return Ok(None);
                }
            }
        }

        // Now prompt for passwords.
        loop {
            let mut context
                = prompt::ContextBuilder::password(
                    prompt::Reason::DecryptMessage)
                .sequoia(&self.vhelper.sequoia())
                .build();
            let password = match self.prompt.prompt(&mut context) {
                Ok(prompt::Response::Password(p)) => p,
                Ok(prompt::Response::NoPassword)
                    | Err(prompt::Error::Cancelled(_)) =>
                {
                    break Err(anyhow::anyhow!("Decryption failed."));
                }
                Err(err) => {
                    break Err(err).context("Password prompt");
                }
            };

            for skesk in skesks {
                if let Some(sk) = skesk.decrypt(&password).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
                {
                    if self.dump_session_key {
                        weprintln!("Session key: {}", hex::encode(&sk));
                    }
                    return Ok(None);
                }
            }

            weprintln!("Incorrect password.");
        }
    }
}
