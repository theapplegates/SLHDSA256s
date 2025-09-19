use sequoia::openpgp;
use openpgp::packet::UserID;

use sequoia::verify;
use sequoia::types::TrustThreshold;
use sequoia::types::PreferredUserID;

use sequoia::wot::Paths;

use crate::Result;
use crate::Sq;
use crate::common::ui::Safe;
use crate::common::pki::output::print_path;

/// The context in which verify is called.
///
/// This controls the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyContext {
    Verify,
    Decrypt,
    Download,
}

pub struct Stream<'a> {
    sq: &'a Sq,
    #[allow(dead_code)]
    context: VerifyContext,
}

impl<'a> Stream<'a> {
    pub fn new(sq: &'a Sq, context: VerifyContext) -> Self
    {
        Self {
            sq,
            context,
        }
    }
}

impl verify::Stream for Stream<'_> {
    fn output(&mut self,
              params: &verify::Params,
              output: verify::Output)
        -> Result<()>
    {
        make_qprintln!(params.sequoia().config().quiet());

        match output {
            verify::Output::MessageStructure(structure) => {
                for layer in structure.layers {
                    match layer {
                        verify::output::MessageLayer::Compression(
                            verify::output::message_layer::CompressionLayer {
                                algo,
                                ..
                            }) =>
                        {
                            qprintln!("Compressed using {}", algo);
                        }
                        verify::output::MessageLayer::Encryption(
                            verify::output::message_layer::EncryptionLayer {
                                sym_algo,
                                aead_algo,
                                ..
                            }) =>
                        {
                            if let Some(aead_algo) = aead_algo {
                                qprintln!("Encrypted and protected using {}/{}",
                                          sym_algo, aead_algo);
                            } else {
                                qprintln!("Encrypted using {}", sym_algo);
                            }
                        }
                        verify::output::MessageLayer::Signature(
                            verify::output::message_layer::SignatureLayer {
                                sigs,
                                ..
                            }) =>
                        {
                            for sig in sigs {
                                self.print_sig(params, sig);
                            }
                        }
                        // Unknown layer.  Ignore it.  Likely `sequoia`
                        // was upgraded.
                        _ => (),
                    }
                }
            }
            verify::Output::Report(report) => {
                if report.authenticated || ! self.sq.quiet() {
                    // XXX transitional: don't always show for
                    // decrypt.  Decrypt does it itself.
                    if self.context != VerifyContext::Decrypt
                        || ! report.authenticated
                    {
                        self.print_status(report);
                    }
                }
            }
            _ => (),
        }

        Ok(())
    }
}

impl Stream<'_> {
    pub fn print_status(&self, report: verify::output::Report) {
        fn p(s: &mut String, what: &str, threshold: usize, quantity: usize) {
            if quantity >= threshold {
                use std::fmt::Write;
                use crate::output::pluralize::Pluralize;
                let dirty = ! s.is_empty();
                write!(s, "{}{}",
                       if dirty { ", " } else { "" },
                       quantity.of(what))
                    .expect("writing to a string is infallible");
            }
        }

        let mut status = String::new();
        p(&mut status, "authenticated signature", 0, report.authenticated_signatures);
        p(&mut status, "unauthenticated signature", 1, report.unauthenticated_signatures);
        p(&mut status, "uncheckable signature", 1, report.uncheckable_signatures);
        p(&mut status, "bad signature", 1, report.bad_signatures);
        p(&mut status, "bad key", 1, report.broken_keys);
        p(&mut status, "broken signatures", 1, report.broken_signatures);
        if ! status.is_empty() {
            weprintln!("{}.", status);
        }
    }

    fn print_sig(&mut self,
                 _params: &verify::Params,
                 sig: verify::output::Signature)
    {
        make_qprintln!(self.sq.quiet());
        use crate::print_error_chain;

        let authenticated = sig.verified();

        let info = sig.info;
        let result = match sig.status {
            verify::output::SignatureStatus::Verified(
                verify::output::signature_status::Verified {
                    sig,
                    cert,
                    key,
                    direct,
                    wot,
                    ..
                }) =>
            {
                (sig, cert, key, direct, wot)
            }
            verify::output::SignatureStatus::GoodChecksum(
                verify::output::signature_status::GoodChecksum {
                    sig,
                    cert,
                    key,
                    direct,
                    wot,
                    ..
                }) =>
            {
                (sig, cert, key, direct, wot)
            }
            verify::output::SignatureStatus::MissingKey(
                verify::output::signature_status::MissingKey {
                    sig,
                    ..
                }) =>
            {
                let issuer = sig.get_issuers().get(0)
                    .expect("missing key checksum has an issuer")
                    .to_string();
                let what = match sig.level() {
                    0 => "signature".into(),
                    n => format!("level {} notarization", n),
                };
                weprintln!("Can't authenticate {} allegedly made by {}: \
                            missing certificate.",
                           what, issuer);

                self.sq.hint(format_args!(
                    "Consider searching for the certificate using:"))
                    .sq().arg("network").arg("search")
                    .arg(issuer)
                    .done();
                return;
            }
            verify::output::SignatureStatus::UnboundKey(
                verify::output::signature_status::UnboundKey {
                    cert,
                    error,
                    ..
                }) =>
            {
                weprintln!("Signing key on {} is not bound:",
                           cert.fingerprint());
                print_error_chain(&error);
                return;
            }
            verify::output::SignatureStatus::BadKey(
                verify::output::signature_status::BadKey {
                    cert,
                    error, ..
                }) =>
            {
                weprintln!("Signing key on {} is bad:",
                           cert.fingerprint());
                print_error_chain(&error);
                return;
            }
            verify::output::SignatureStatus::BadSignature(
                verify::output::signature_status::BadSignature {
                    sig,
                    key,
                    error,
                    ..
                }) =>
            {
                let what = match sig.level() {
                    0 => "signature".into(),
                    n => format!("level {} notarizing signature", n),
                };
                weprintln!("Error verifying {} made by {}:",
                           what, key);
                print_error_chain(&error);
                return;
            }
            verify::output::SignatureStatus::MalformedSignature(
                verify::output::signature_status::MalformedSignature {
                    error,
                    ..
                }) =>
            {
                weprintln!("Malformed signature:");
                print_error_chain(&error);
                return;
            }
            verify::output::SignatureStatus::UnknownSignature(
                verify::output::signature_status::UnknownSignature {
                    sig,
                    ..
                }) =>
            {
                weprintln!("Error parsing signature: {}", sig.error());
                print_error_chain(&sig.error());
                return;
            }
            verify::output::SignatureStatus::Unknown(
                verify::output::signature_status::Unknown {
                    error,
                    ..
                }) =>
            {
                weprintln!("Error parsing signature: {}", error);
                return;
            }
            _ => {
                weprintln!("Unknown error parsing signature");
                return;
            }
        };

        let (sig, cert, _issuer, _direct, wot) = result;

        let cert_fpr = cert.fingerprint();
        let mut signer_userid = self.sq.sequoia.best_userid(&cert, true);

        let mut prefix = "";

        if let Some(verify::output::WebOfTrust { mut authentication_paths, .. }) = wot {
            // We used the web of trust.
            prefix = "  ";

            // Web of trust.
            qprintln!("Authenticating {} ({}) using the web of trust:",
                      cert_fpr, signer_userid.userid_lossy());

            if authentication_paths.is_empty()
                && info.iter().any(|i| {
                    matches!(i, &verify::output::SignatureInfo::NoUserIDs)
                })
            {
                weprintln!(indent=prefix,
                           "{} cannot be authenticated.  \
                            It has no User IDs",
                           cert_fpr);
            }

            // Add missing self-signed user IDs as unauthenticated.
            //
            // If we can't authenticate any user IDs at all, then we
            // would only show the fingerprint, which is not terribly
            // helpful.  Instead, re-add the self-signed user IDs.
            if let Ok(vc) = cert.with_policy(
                self.sq.sequoia.policy(), self.sq.sequoia.time())
            {
                for ua in vc.userids() {
                    if ! authentication_paths.iter().any(|(u, _)| u == ua.userid()) {
                        authentication_paths.push((ua.userid().clone(), Paths::new()));
                    }
                }
            }

            let authenticated_userids = authentication_paths
                .iter()
                .filter_map(|(userid, paths)| {
                    let amount = paths.amount();

                    let authenticated = if amount >= sequoia::wot::FULLY_TRUSTED {
                        weprintln!(indent=prefix,
                                   "Fully authenticated \
                                    ({} of {}) {}, {}",
                                   amount,
                                   TrustThreshold::Full,
                                   cert_fpr,
                                   Safe(userid));
                        true
                    } else if amount > 0 {
                        weprintln!(indent=prefix,
                                   "Partially authenticated \
                                    ({} of {}) {}, {} ",
                                   amount,
                                   TrustThreshold::Full,
                                   cert_fpr,
                                   Safe(userid));
                        false
                    } else {
                        weprintln!(indent=prefix,
                                   "{}: {} is unauthenticated \
                                    and may be an impersonation!",
                                   cert_fpr,
                                   Safe(userid));
                        false
                    };

                    for (i, (path, amount)) in paths.iter().enumerate() {
                        let prefix = if paths.len() > 1 {
                            qprintln!("{}  Path #{} of {}, \
                                       trust amount {}:",
                                      prefix,
                                      i + 1, paths.len(), amount);
                            format!("{}    ", prefix)
                        } else {
                            format!("{}  ", prefix)
                        };

                        if ! self.sq.quiet() {
                            let _ =
                                print_path(&mut std::io::stderr(),
                                           &path.into(), userid,
                                           &prefix);
                        }
                    }

                    if authenticated {
                        Some(userid)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            if ! authenticated_userids.is_empty() {
                // If we managed to authenticate the
                // signer's user ID, prefer that one.
                if let Some(u) = sig.signers_user_id()
                    .and_then(|u| {
                        authenticated_userids.contains(
                            &&UserID::from(u))
                            .then_some(u)
                    })
                {
                    signer_userid = PreferredUserID::from_string(
                        String::from_utf8_lossy(u),
                        TrustThreshold::Full.into());
                } else {
                    // Else just pick the first one.
                    signer_userid = PreferredUserID::from_string(
                        String::from_utf8_lossy(
                            authenticated_userids[0].value()),
                        TrustThreshold::Full.into());
                }
            }
        }

        let label = cert_fpr.to_string();

        let level = sig.level();
        match (level == 0, authenticated) {
            (true,  true)  => {
                weprintln!(indent=prefix,
                           "Authenticated signature made by {} ({})",
                           label, signer_userid.userid_lossy());
            }
            (false, true)  => {
                weprintln!(indent=prefix,
                           "Authenticated level {} notarization \
                            made by {} ({})",
                           level, label, signer_userid.userid_lossy());
            }
            (true,  false) => {
                weprintln!(indent=prefix,
                           "Can't authenticate signature made by {} ({}): \
                            the certificate can't be authenticated.",
                           label, signer_userid.userid_lossy());

                if let Ok(u) = signer_userid.userid() {
                    self.sq.sequoia.hint(format_args!(
                        "After checking that {} belongs to {}, \
                         you can mark it as authenticated using:",
                        cert_fpr, u))
                        .sq().arg("pki").arg("link").arg("add")
                        .arg_value("--cert", cert_fpr)
                        .arg_value("--userid", u)
                        .done();
                }
            }
            (false, false) => {
                weprintln!(indent=prefix,
                           "Can't authenticate level {} notarization \
                            made by {} ({}): the certificate \
                            can't be authenticated.",
                           level, label, signer_userid.userid_lossy());

                if let Ok(u) = signer_userid.userid() {
                    self.sq.sequoia.hint(format_args!(
                        "After checking that {} belongs to {}, \
                         you can mark it as authenticated using:",
                        cert_fpr, u))
                        .sq().arg("pki").arg("link").arg("add")
                        .arg_value("--cert", cert_fpr)
                        .arg_value("--userid", u)
                        .done();
                }
            }
        };

        qprintln!("");
    }
}
