use std::sync::Arc;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::crypto::Signer;
use openpgp::packet::Key;
use openpgp::packet::Signature;
use openpgp::packet::UserID;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::store::UserIDQueryParams;

use crate::Result;
use crate::Sequoia;
use crate::prompt;
use crate::transitional::print_error_chain;
use crate::types::MyAsRef;
use crate::types::Safe;

/// Returns the active certification, if any, for the specified bindings.
///
/// Note: if `n` User IDs are provided, then the returned vector has
/// `n` elements.
pub fn active_certification<U>(
    sequoia: &Sequoia,
    cert: &Cert, userids: impl Iterator<Item=U>,
    issuer: &Key<openpgp::packet::key::PublicParts,
                 openpgp::packet::key::UnspecifiedRole>)
    -> Vec<(U, Option<Signature>)>
where
    U: MyAsRef<UserID>
{
    let issuer_kh = issuer.key_handle();

    userids.map(|userid_ref| {
        let userid = userid_ref.as_ref();

        let ua = match cert.userids()
            .filter(|ua| ua.userid() == userid).next()
        {
            Some(ua) => ua,
            None => return (userid_ref, None),
        };

        // Get certifications that:
        //
        //  - Have a creation time,
        //  - Are not younger than the reference time,
        //  - Are not expired,
        //  - Alias the issuer, and
        //  - Satisfy the policy.
        let mut certifications = ua.bundle().certifications()
            .filter(|sig| {
                if let Some(ct) = sig.signature_creation_time() {
                    ct <= sequoia.time()
                        && sig.signature_validity_period()
                        .map(|vp| {
                            sequoia.time() < ct + vp
                        })
                        .unwrap_or(true)
                        && sig.get_issuers().iter().any(|i| i.aliases(&issuer_kh))
                        && sequoia.policy().signature(
                            sig, HashAlgoSecurity::CollisionResistance).is_ok()
                } else {
                    false
                }
            })
            .collect::<Vec<&Signature>>();

        // Sort so the newest signature is first.
        certifications.sort_unstable_by(|a, b| {
            a.signature_creation_time().unwrap()
                .cmp(&b.signature_creation_time().unwrap())
                .reverse()
                .then(a.mpis().cmp(&b.mpis()))
        });

        // Return the first valid signature, which is the most recent one
        // that is no younger than sequoia.time().
        let pk = ua.cert().primary_key().key();
        let certification = certifications.into_iter()
            .filter_map(|sig| {
                let sig = sig.clone();
                if sig.verify_userid_binding(issuer, pk, userid).is_ok() {
                    Some(sig)
                } else {
                    None
                }
            })
            .next();
        (userid_ref, certification)
    }).collect()
}

/// Creates a non-exportable certification for the specified bindings.
///
/// This does not import the certification or the certificate into
/// the certificate store.
fn certify(sequoia: &Sequoia,
           emit_provenance_messages: bool,
           signer: &mut dyn Signer, cert: &Cert, userids: &[UserID],
           depth: u8, amount: usize)
    -> Result<Cert>
{
    let mut builder =
        SignatureBuilder::new(SignatureType::GenericCertification)
        .set_signature_creation_time(sequoia.time())?;

    if depth != 0 || amount != 120 {
        builder = builder.set_trust_signature(depth, amount.min(255) as u8)?;
    }

    builder = builder.set_exportable_certification(false)?;

    let certifications = active_certification(
        sequoia, cert,
        userids.iter(),
        signer.public())
        .into_iter()
        .map(|(userid, active_certification)| {
            if let Some(_) = active_certification {
                if emit_provenance_messages {
                    sequoia.info(format_args!(
                        "Provenance information for {}, {} \
                         exists and is current, not updating it",
                        cert.fingerprint(),
                        Safe(userid)));
                }
                return vec![];
            }

            match builder.clone().sign_userid_binding(
                signer,
                cert.primary_key().key(),
                &userid)
                .with_context(|| {
                    format!("Creating certification for {}, {}",
                            cert.fingerprint(),
                            Safe(userid))
                })
            {
                Ok(sig) => {
                    if emit_provenance_messages {
                        sequoia.info(format_args!(
                            "Recorded provenance information \
                             for {}, {}",
                            cert.fingerprint(),
                            Safe(userid)));
                    }
                    vec![ Packet::from(userid.clone()), Packet::from(sig) ]
                }
                Err(err) => {
                    let err = err.context(format!(
                        "Warning: recording provenance information \
                         for {}, {}",
                        cert.fingerprint(),
                        Safe(userid)));
                    print_error_chain(&err);
                    vec![]
                }
            }
        })
        .collect::<Vec<Vec<Packet>>>()
        .into_iter()
        .flatten()
        .collect::<Vec<Packet>>();

    if certifications.is_empty() {
        Ok(cert.clone())
    } else {
        Ok(cert.clone().insert_packets(certifications)?.0)
    }
}

/// Certify the certificates using the specified CA.
///
/// The certificates are certified for User IDs with the specified
/// email address.  If no email address is specified, then all valid
/// User IDs are certified.  The results are returned; they are not
/// imported into the certificate store.
///
/// If a certificate cannot be certified for whatever reason, a
/// diagnostic is emitted, and the certificate is returned as is.
///
/// `prompt` is used to prompt for a password to unlock the trust root
/// or a CAs.  Normally the trust root and the CAs' secret key
/// material is not protected by a password, but the user could change
/// this.
pub fn certify_downloads<P>(sequoia: &Sequoia,
                            emit_provenance_messages: bool,
                            ca: Arc<LazyCert<'static>>,
                            certs: Vec<Cert>, email: Option<&str>,
                            prompt: P)
    -> Vec<Cert>
where
    P: prompt::Prompt,
{
    let ca = || -> Result<_> {
        let ca = ca.to_cert()?;

        Ok(sequoia.get_certification_key(ca, None, &prompt)?)
    };
    let mut ca_signer = match ca() {
        Ok(signer) => signer,
        Err(err) => {
            let err = err.context(
                "Warning: not recording provenance information, \
                 failed to load CA key");
            if sequoia.config().verbose() {
                print_error_chain(&err);
            }
            return certs;
        }
    };

    // Normalize the email.  If it is not valid, just return it as is.
    let email = email.map(|email| {
        match UserIDQueryParams::is_email(&email) {
            Ok(email) => email,
            Err(_) => email.to_string(),
        }
    });

    let certs: Vec<Cert> = certs.into_iter().map(|cert| {
        let vc = match cert.with_policy(sequoia.policy(), sequoia.time()) {
            Err(err) => {
                let err = err.context(format!(
                    "Warning: not recording provenance information \
                     for {}, not valid",
                    cert.fingerprint()));
                if sequoia.config().verbose() {
                    print_error_chain(&err);
                }
                return cert;
            }
            Ok(vc) => vc,
        };

        let userids = if let Some(email) = email.as_ref() {
            // Only the specified email address is authenticated.
            let userids = vc.userids()
                .filter_map(|ua| {
                    if let Ok(Some(e)) = ua.userid().email_normalized() {
                        if &e == email {
                            return Some(ua.userid().clone());
                        }
                    }
                    None
                })
                .collect::<Vec<UserID>>();

            if userids.is_empty() {
                if sequoia.config().verbose() {
                    sequoia.info(format_args!(
                        "Warning: not recording provenance information \
                         for {}, it does not contain a valid User ID with \
                         the specified email address ({:?})",
                        cert.fingerprint(),
                        email));
                }
                return cert;
            }

            userids
        } else {
            vc.userids().map(|ua| ua.userid().clone()).collect()
        };

        match certify(
            sequoia, emit_provenance_messages,
            &mut ca_signer, &cert, &userids[..],
            0, sequoia_wot::FULLY_TRUSTED)
        {
            Ok(cert) => cert,
            Err(err) => {
                let err = err.context(format!(
                    "Warning: not recording provenance information \
                     for {}, failed to certify it",
                    cert.fingerprint()));
                if sequoia.config().verbose() {
                    print_error_chain(&err);
                }

                cert
            }
        }
    }).collect();

    certs
}

