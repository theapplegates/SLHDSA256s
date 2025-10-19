use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::armor;
use openpgp::cert::ValidCert;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::cert::amalgamation::key::ValidKeyAmalgamation;
use openpgp::crypto::Password;
use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::serialize::stream::Armorer;
use openpgp::serialize::stream::Compressor;
use openpgp::serialize::stream::Encryptor;
use openpgp::serialize::stream::LiteralWriter;
use openpgp::serialize::stream::Message;
use openpgp::serialize::stream::Signer;
use openpgp::serialize::stream::padding::Padder;
use openpgp::types::CompressionAlgorithm;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use crate::Result;
use crate::Sequoia;
use crate::cert::CertError;
use crate::cert;
use crate::prompt::check::CheckNewPassword;
use crate::prompt;
use crate::types::CompressionMode;
use crate::types::EncryptPurpose;

/// The trait for collecting output.
pub trait Stream {
    /// Output from [`encrypt`](Builder::encrypt).
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

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// Emitted when encryption fails.
    ///
    /// Provides some information about why encryption was not
    /// possible.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct EncryptionFailed {
        pub unusable_certs: Vec<CertError>,
    }

    /// Information about how we're going to encrypt and sign the
    /// message before we do the actual encryption.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Encrypting {
        /// The recipients.
        pub recipients: Vec<(Cert, Vec<Fingerprint>)>,

        /// Set to true if the user may not be able to decrypt the
        /// message, because the secret key material is not available
        /// for any of the recipients.
        pub undecryptable: bool,

        /// The number of passwords that the message is encrypted to.
        pub passwords: Vec<Password>,

        /// The signers, if any.
        pub signers: Vec<(Cert, Fingerprint)>,
    }

    /// Information about how we encrypted and signed the message
    /// after we do the actual encryption.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Encrypted {
    }
}

/// The variants of this enum are the different types of output that
/// [`encrypt`](Builder::encrypt) emits.
#[non_exhaustive]
#[derive(Debug)]
pub enum Output {
    /// Emitted when encryption fails.
    ///
    /// Provides some information about why encryption was not
    /// possible.
    EncryptionFailed(output::EncryptionFailed),

    /// Information about how we're going to encrypt and sign the
    /// message before we do the actual encryption.
    Encrypting(output::Encrypting),

    /// Information about how we encrypted and signed the message
    /// after we do the actual encryption.
    Encrypted(output::Encrypted),
}

impl Sequoia {
    /// Returns a builder providing control over how to encrypt a message.
    ///
    /// See [`Builder`] for details.
    pub fn encrypt(&self) -> Builder<'_>
    {
        Builder {
            params: Params {
                sequoia: self,
                signers: Vec::new(),
                notations: Vec::new(),

                prompt_for_passwords: 0,
                passwords: Vec::new(),
                recipients: Vec::new(),

                armor_headers: Some(Vec::new()),

                encryption_purpose: EncryptPurpose::Universal,
                compression_mode: CompressionMode::Pad,
                use_expired_encryption_keys: false,

                filename: Vec::new(),
            }
        }
    }
}

/// The encryption parameters.
///
/// These parameters are used by [`encrypt`](Builder::encrypt).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,

    signers: Vec<Cert>,
    notations: Vec<(bool, NotationData)>,

    prompt_for_passwords: usize,
    passwords: Vec<Password>,
    recipients: Vec<Cert>,

    /// If Some, ASCII-armor.  Otherwise, binary.
    armor_headers: Option<Vec<(String, String)>>,

    encryption_purpose: EncryptPurpose,
    compression_mode: CompressionMode,
    use_expired_encryption_keys: bool,

    filename: Vec<u8>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns the configured signers.
    pub fn signers(&self) -> impl Iterator<Item=&Cert> {
        self.signers.iter()
    }

    /// Returns the configured notations.
    pub fn notations(&self) -> impl Iterator<Item=&(bool, NotationData)> {
        self.notations.iter()
    }

    /// Returns whether ASCII-armor is enabled.
    pub fn ascii_armor(&self) -> bool {
        self.armor_headers.is_some()
    }

    /// Returns the configured ASCII-armor headers.
    pub fn ascii_armor_headers(&self) -> impl Iterator<Item=&(String, String)> {
        static EMPTY: Vec<(String, String)> = Vec::new();

        if let Some(h) = self.armor_headers.as_ref() {
            h.iter()
        } else {
            EMPTY.iter()
        }
    }

    /// Returns the passwords that user will be prompted to enter.
    ///
    /// Each password will be used to encrypt the message.
    pub fn prompt_for_passwords(&self) -> usize {
        self.prompt_for_passwords
    }

    /// Returns the passwords that will be used to encrypt the message.
    pub fn passwords(&self) -> impl Iterator<Item=&Password> {
        self.passwords.iter()
    }

    /// Returns the recipient certificates.
    pub fn recipients(&self) -> impl Iterator<Item=&Cert> {
        self.recipients.iter()
    }

    /// Returns the encryption purpose.
    pub fn encryption_purpose(&self) -> EncryptPurpose {
        self.encryption_purpose.clone()
    }

    /// Returns the compression mode.
    pub fn compression_mode(&self) -> CompressionMode {
        self.compression_mode.clone()
    }

    /// Returns whether expired encryption keys will be used.
    pub fn use_expired_encryption_keys(&self) -> bool {
        self.use_expired_encryption_keys
    }

    /// Returns the filename that will be embedded in the literal data
    /// packet.
    pub fn unsafe_filename(&self) -> &[u8] {
        &self.filename
    }
}

/// Encrypt messages.
///
/// This command builder is used to encrypt messages.
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

    /// Signs the message with the specified certificate.
    ///
    /// This adds the certificate to the list of certificates that the
    /// message will be signed with.  It is possible to add multiple
    /// signatures to a message.
    ///
    /// The message will be signed with one valid (live, non-revoked)
    /// signing-capable key associated with the certificate for which
    /// the secret key material is available.  If the certificate has
    /// no valid signing-capable keys with secret key material, then
    /// an error will be returned.
    ///
    /// Messages should normally be signed by at least one
    /// certificate; it is strongly discouraged to send unsigned
    /// messages as the messages cannot be authenticated.
    pub fn add_signer(mut self, signer: Cert) -> Self {
        self.params.signers.push(signer);
        self
    }

    /// Signs the message with the specified certificates.
    ///
    /// See [`Builder::add_signer`] for details.
    pub fn add_signers(mut self, signers: impl Iterator<Item=Cert>)
        -> Self
    {
        self.params.signers.extend(signers);
        self
    }

    /// Adds a notation to the signatures.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notation(mut self, critical: bool, notation: NotationData) -> Self
    {
        self.params.notations.push((critical, notation));
        self
    }

    /// Adds notation to the signatures.
    ///
    /// The first value of the tuple is the notation's criticality.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notations(mut self,
                         notations: impl Iterator<Item=(bool, NotationData)>)
        -> Self
    {
        self.params.notations.extend(notations);
        self
    }

    /// Encrypts the message with one or more passwords obtained from
    /// the user.
    ///
    /// The user is prompted for the passwords.  If the user cancels
    /// the prompt, the operation is aborted.
    ///
    /// By default, the user is not prompted for a password.
    ///
    /// A recipient only needs to know one of the passwords to decrypt
    /// the message.
    pub fn prompt_for_passwords(mut self, count: usize) -> Self {
        self.params.prompt_for_passwords = count;
        self
    }

    /// Encrypts the message with the specified password.
    ///
    /// This adds the password to the list of passwords that will be
    /// used to encrypt the message.  It is possible to encrypt a
    /// message with multiple passwords.
    ///
    /// A recipient only needs to know one of the passwords to decrypt
    /// the message.
    pub fn add_password(mut self, password: Password) -> Self {
        self.params.passwords.push(password);
        self
    }

    /// Encrypts the message with the specified passwords.
    ///
    /// This adds the passwords to the list of passwords that will be
    /// used to encrypt the message.  It is possible to encrypt a
    /// message with multiple passwords.
    ///
    /// A recipient only needs to know one of the passwords to decrypt
    /// the message.
    pub fn add_passwords(mut self, passwords: impl Iterator<Item=Password>)
        -> Self
    {
        self.params.passwords.extend(passwords);
        self
    }

    /// Encrypts the message for the specified certificate.
    ///
    /// This adds the certificate to the list of certificates that the
    /// message will be encrypted for.  It is possible to encrypt a
    /// message for multiple certificates.
    ///
    /// The message will be encrypt for all valid (live, non-revoked)
    /// encryption-capable keys associated with the certificate and
    /// compatible with the encryption purpose (see
    /// [`Builder::encryption_purpose`]).  If the certificate has no
    /// valid encryption-capable keys, then an error will be returned.
    pub fn add_recipient(mut self, recipient: Cert) -> Self {
        self.params.recipients.push(recipient);
        self
    }

    /// Encrypts the message for the specified certificates.
    ///
    /// See [`Builder::add_recipient`] for details.
    pub fn add_recipients(mut self, recipients: impl Iterator<Item=Cert>)
        -> Self
    {
        self.params.recipients.extend(recipients);
        self
    }

    /// Sets the encryption purpose.
    ///
    /// The default is [`EncryptPurpose::Universal`].
    pub fn encryption_purpose(mut self, encryption_purpose: EncryptPurpose)
        -> Self
    {
        self.params.encryption_purpose = encryption_purpose;
        self
    }

    /// Sets the compression mode.
    ///
    /// The default is [`CompressionMode::Pad`].
    pub fn compression_mode(mut self, compression_mode: CompressionMode)
        -> Self
    {
        self.params.compression_mode = compression_mode;
        self
    }

    /// Sets whether to use encryption keys that are expired.
    ///
    /// Occasionally, users let their certificates expire.  It can
    /// sometimes be better to encrypt a message to an expired
    /// certificate than to send it in cleartext.
    ///
    /// This is not enabled by default, and you should avoid using
    /// this unless the user explicitly opts in.
    pub fn use_expired_encryption_keys(mut self,
                                       use_expired_encryption_keys: bool)
        -> Self
    {
        self.params.use_expired_encryption_keys = use_expired_encryption_keys;
        self
    }

    /// Sets whether ASCII armor is used.
    ///
    /// If disabled, then the message is binary encoded.
    ///
    /// The default is to using ASCII armor and not add any headers.
    pub fn ascii_armor(mut self, use_ascii_armor: bool)
        -> Self
    {
        self.params.armor_headers = if use_ascii_armor {
            Some(Vec::new())
        } else {
            None
        };
        self
    }

    /// Enables ASCII armor and sets the ASCII-armor headers.
    ///
    /// This implicitly enables ASCII armor, and uses the specified
    /// headers.
    ///
    /// Note: the headers are informative and are neither encrypted
    /// nor protected by any signature.
    pub fn ascii_armor_headers<K, V>(mut self,
                                     headers: impl Iterator<Item=(K, V)>)
        -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.params.armor_headers = Some(
            headers
                .map(|(k, v)| {
                    (k.into(), v.into())
                })
                .collect());
        self
    }

    /// Sets the filename in the literal data packet.
    ///
    /// This is deprecated and should no longer be used.  This is
    /// available for backwards compatibility.
    ///
    /// Note: the filename is not protected by any signatures and
    /// could be manipulated by an attacker without detection.  If you
    /// need to encode a filename, you should use a container format
    /// like `pax` (tar's successor) or `zip`.
    ///
    ///   [`pax`]: https://en.wikipedia.org/wiki/Pax_(command)
    ///
    /// The filename is limited to 255 bytes.  An error is returned if
    /// `filename` contains more than 255 bytes.
    pub fn unsafe_filename<F>(mut self, filename: F)
        -> Result<Self>
    where
        F: AsRef<[u8]>
    {
        let filename = filename.as_ref();

        if filename.len() > 255 {
            Err(anyhow::anyhow!("Filename too long ({} bytes of 255 bytes)",
                                filename.len()))
        } else {
            self.params.filename = filename.to_vec();
            Ok(self)
        }
    }
}

impl<'sequoia> Builder<'sequoia> {
    /// Encrypts the specified message with the configured parameters.
    ///
    /// The encrypted data is written to `output`.  By default, the
    /// message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be encrypted.
    ///
    /// On failure some of the encrypted data may have been written to
    /// the output writer.  This should be ignored.
    ///
    /// If you don't want to implement [`Stream`], you can pass `&mut
    /// Vec<Output>` to collect the status messages, or `()` to ignore
    /// them.
    pub fn encrypt<'a, I, O, S, P>(&self, mut input: I, output: O,
                                   prompt: P, mut stream: S)
        -> Result<()>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream + 'a,
        P: prompt::Prompt,
    {
        let &Builder {
            params: Params {
                sequoia,
                ref signers,
                ref notations,

                prompt_for_passwords,
                ref passwords,
                ref recipients,

                ref encryption_purpose,
                ref compression_mode,
                use_expired_encryption_keys,

                ref armor_headers,

                ref filename,
            },
        } = self;

        let mut signers = sequoia.get_signing_keys(&signers, None, &prompt)?;

        let mut passwords = passwords.to_vec();
        for _ in 0..prompt_for_passwords {
            let mut checker = CheckNewPassword::required();

            let mut context = prompt::ContextBuilder::password(
                prompt::Reason::EncryptMessage)
                .sequoia(sequoia)
                .build();

            match prompt.prompt(&mut context, &mut checker)? {
                prompt::Response::Password(password) => {
                    passwords.push(password);
                }
                prompt::Response::NoPassword => {
                    // This is technically unreachable, but let's not
                    // panic.
                    return Err(anyhow::anyhow!(
                        "Internal error: failed to prompt for a password"));
                }
            }
        }

        if recipients.len() + passwords.len() == 0 {
            return Err(anyhow::anyhow!(
                "Neither recipient nor password given"));
        }

        // Returns the encryption capable keys for the given
        // certificate.  If there are none, lint the certificate.
        fn get_encryption_keys<'a>(vc: &ValidCert<'a>,
                                   sequoia: &Sequoia,
                                   mode: &KeyFlags,
                                   use_expired_encryption_keys: bool)
            -> std::result::Result<
                (bool, Vec<ValidKeyAmalgamation<'a, PublicParts, UnspecifiedRole, bool>>),
                Vec<cert::CertProblem>>
        {
            // XXX: In this block, instead of using sequoia.best_userid(&cert,
            // true), it'd be nice to use the cert designator that the
            // user used, instead or additionally.

            // This cert's subkeys we selected for encryption.
            let mut selected_keys = Vec::new();

            // As a fallback, we may consider expired keys.
            let mut expired_keys = Vec::new();

            let mut problems: Vec<cert::CertProblem> = Vec::new();

            let mut encryption_capable_keys = 0;
            for ka in vc.keys() {
                if let Some(key_flags) = ka.key_flags() {
                    if (&key_flags & mode).is_empty() {
                        // Not for encryption.
                        continue;
                    }
                } else {
                    // No key flags.  Not for encryption.
                    continue;
                }
                encryption_capable_keys += 1;

                let mut have_problem = false;
                if ! ka.key().pk_algo().is_supported() {
                    problems.push(cert::CertProblem::UnsupportedAlgorithm(
                        cert::problem::UnsupportedAlgorithm {
                            cert: vc.fingerprint(),
                            key: ka.key().fingerprint(),
                            algo: ka.key().pk_algo(),
                        }));
                    have_problem = true;
                }
                if let RevocationStatus::Revoked(sigs) = ka.revocation_status() {
                    problems.push(cert::CertProblem::KeyRevoked(
                        cert::problem::KeyRevoked {
                            cert: vc.fingerprint(),
                            key: ka.key().fingerprint(),
                            revocations: sigs.into_iter().cloned().collect(),
                        }));
                    have_problem = true;
                }
                if let Err(err) = ka.alive() {
                    let creation_time = ka.key().creation_time();
                    let expiration_time = ka.key_expiration_time();

                    problems.push(cert::CertProblem::NotLive(
                        cert::problem::NotLive {
                            cert: vc.fingerprint(),
                            key: ka.key().fingerprint(),
                            creation_time,
                            expiration_time,
                            reference_time: sequoia.time(),
                            error: err,
                        }));

                    if ! have_problem {
                        if let Some(expiration_time) = expiration_time.as_ref() {
                            if *expiration_time < sequoia.time() {
                                // The only problem is that the key is expired.
                                expired_keys.push((ka, expiration_time.clone()));
                            }
                        }
                    }
                } else if ! have_problem {
                    selected_keys.push(ka);
                }
            }

            if selected_keys.is_empty() && use_expired_encryption_keys
                && ! expired_keys.is_empty()
            {
                expired_keys.sort_by_key(|(_key, t)| *t);

                if let Some((key, _expiration_time)) = expired_keys.pop() {
                    selected_keys.push(key);
                }
            }

            if selected_keys.is_empty() {
                // We didn't find any keys for this certificate.

                // See if there are encryption-capable subkeys that
                // are just invalid.
                for ka in vc.cert().keys() {
                    if let Err(err) = ka.with_policy(sequoia.policy(), sequoia.time()) {
                        problems.push(cert::CertProblem::KeyInvalid(
                            cert::problem::KeyInvalid {
                                cert: vc.fingerprint(),
                                key: ka.key().fingerprint(),
                                error: err,
                            }));
                    }
                }

                if problems.is_empty() {
                    problems.push(cert::CertProblem::NoUsableKeys(
                        cert::problem::NoUsableKeys {
                            cert: vc.fingerprint(),
                            capabilities: mode.clone(),
                            unusable: encryption_capable_keys,
                        }));
                }

                Err(problems)
            } else {
                let mut have_one_secret = false;
                let mut recipient_subkeys = Vec::new();
                for ka in selected_keys {
                    have_one_secret |= sequoia.have_secret_key(ka.amalgamation());
                    recipient_subkeys.push(ka);
                }

                Ok((have_one_secret, recipient_subkeys))
            }
        }

        let mut unusable_certs = Vec::new();

        let mut vc = Vec::new();
        for cert in recipients.iter() {
            let revocation_status
                = cert.revocation_status(sequoia.policy(), sequoia.time());
            if let RevocationStatus::Revoked(sigs) = revocation_status {
                unusable_certs.push(cert::CertError {
                    cert: cert.clone(),
                    problems: vec![
                        cert::CertProblem::CertRevoked(
                            cert::problem::CertRevoked {
                                cert: cert.fingerprint(),
                                revocations: sigs.into_iter().cloned().collect(),
                            }),
                    ],
                });
            } else {
                match cert.with_policy(sequoia.policy(), sequoia.time()) {
                    Ok(vc_) => vc.push(vc_),
                    Err(err) => {
                        unusable_certs.push(cert::CertError {
                            cert: cert.clone(),
                            problems: vec![
                                cert::CertProblem::CertInvalid(
                                    cert::problem::CertInvalid {
                                        cert: cert.fingerprint(),
                                        error: err
                                    }),
                            ],
                        });
                    }
                }
            }
        }

        let mode = KeyFlags::from(encryption_purpose);

        // Tracks whether we have a secret for at least one of the
        // encryption subkeys.
        let mut have_one_secret = false;

        let mut recipient_subkeys = Vec::new();
        for vc in vc {
            match get_encryption_keys(&vc, sequoia, &mode, use_expired_encryption_keys) {
                Ok((have_secret, keys)) => {
                    have_one_secret |= have_secret;
                    recipient_subkeys.extend(keys);
                }
                Err(problems) => {
                    unusable_certs.push(cert::CertError {
                        cert: vc.cert().clone(),
                        problems,
                    })
                }
            }
        }

        if ! unusable_certs.is_empty() {
            let unusable_cert = &unusable_certs[0];
            let err = if let cert::CertProblem::CertInvalid(_)
                = unusable_cert.problems[0]
            {
                anyhow::anyhow!(
                    "{}, {} is not valid according to the current policy",
                    unusable_cert.cert.fingerprint(),
                    sequoia.best_userid(&unusable_cert.cert, true).display())
            } else if let cert::CertProblem::CertRevoked(_)
                = unusable_cert.problems[0]
            {
                anyhow::anyhow!(
                    "Can't encrypt to {}, {}: it is revoked",
                    unusable_cert.cert.fingerprint(),
                    sequoia.best_userid(&unusable_cert.cert, true).display())
            } else if unusable_cert.no_usable_keys()
                .map(|p| p.unusable == 0)
                .unwrap_or(false)
            {
                anyhow::anyhow!(
                    "Cert {}, {} has no encryption-capable keys",
                    unusable_cert.cert.fingerprint(),
                    sequoia.best_userid(&unusable_cert.cert, true).display())
            } else {
                anyhow::anyhow!(
                    "Cert {}, {} has no suitable encryption key",
                    unusable_cert.cert.fingerprint(),
                    sequoia.best_userid(&unusable_cert.cert, true).display())
            };

            stream.output(
                &self.params,
                Output::EncryptionFailed(output::EncryptionFailed {
                    unusable_certs
                }))?;

            return Err(err);
        } else {
            let mut recipients = recipient_subkeys
                .iter()
                .map(|ka| {
                    (ka.cert(), vec![ ka.key().fingerprint() ])
                })
                .collect::<Vec<(&Cert, _)>>();
            recipients.dedup_by(|(cert_a, ref mut key_a), (cert_b, key_b)| {
                if cert_a.fingerprint() == cert_b.fingerprint() {
                    // A will be removed.
                    key_b.append(key_a);

                    true
                } else {
                    false
                }
            });
            let recipients = recipients
                .into_iter()
                .map(|(cert, keys)| {
                    (cert.clone(), keys)
                })
                .collect::<Vec<_>>();

            stream.output(
                &self.params,
                Output::Encrypting(output::Encrypting {
                    recipients,
                    undecryptable: ! have_one_secret,
                    passwords: passwords.clone(),
                    signers: signers.iter()
                        .map(|(cert, signer)| {
                            (cert.clone(), signer.public().fingerprint())
                        })
                        .collect(),
                }))?;
        }

        let mut message = Message::new(output);
        if let Some(armor_headers) = armor_headers {
            let mut armorer = Armorer::new(message).kind(armor::Kind::Message);
            for (k, v) in armor_headers {
                armorer = armorer.add_header(k, v);
            }
            message = armorer.build()?;
        }

        // We want to encrypt a literal data packet.
        let encryptor =
            Encryptor::for_recipients(message, recipient_subkeys)
            .add_passwords(passwords);

        let mut sink = encryptor.build()
            .context("Failed to create encryptor")?;

        match compression_mode {
            CompressionMode::None => (),
            CompressionMode::Pad => sink = Padder::new(sink).build()?,
            CompressionMode::Zip => sink =
                Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?,
            CompressionMode::Zlib => sink =
                Compressor::new(sink).algo(CompressionAlgorithm::Zlib).build()?,
            CompressionMode::Bzip2 => sink =
                Compressor::new(sink).algo(CompressionAlgorithm::BZip2).build()?,
        }

        // Optionally sign message.
        if let Some(first) = signers.pop() {
            // Create a signature template.
            let mut builder = SignatureBuilder::new(SignatureType::Binary);
            for (critical, n) in notations.iter() {
                builder = builder.add_notation(
                    n.name(),
                    n.value(),
                    Some(n.flags().clone()),
                    *critical)?;
            }

            let mut signer = Signer::with_template(sink, first.1, builder)?;

            for s in signers {
                signer = signer.add_signer(s.1)?;
            }
            for r in recipients.iter() {
                signer = signer.add_intended_recipient(r);
            }
            sink = signer.build()?;
        }

        let literal_writer = LiteralWriter::new(sink).filename(filename)?;

        let mut writer_stack = literal_writer
            .build()
            .context("Failed to create literal writer")?;

        // Finally, copy stdin to our writer stack to encrypt the data.
        std::io::copy(&mut input, &mut writer_stack)
            .context("Failed to encrypt")?;

        writer_stack.finalize().context("Failed to encrypt")?;

        stream.output(
            &self.params,
            Output::Encrypted(output::Encrypted {
            }))?;

        Ok(())
    }
}
