use std::collections::BTreeSet;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::packet::UserID;
use openpgp::types::RevocationStatus;

use sequoia_wot as wot;
use wot::store::Backend;
use wot::store::Store;
use wot::store::StoreError;

use sequoia_cert_store as cert_store;
use cert_store::Store as _;
use cert_store::store::UserIDQueryParams;

use crate::Result;
use crate::Sequoia;
use crate::types::Query;
use crate::types::QueryKind;
use crate::types::Safe;
use crate::types::TrustAmount;

const TRACE: bool = false;

pub use crate::transitional::concise_human_readable::OutputType;
pub use crate::transitional::concise_human_readable::ConciseHumanReadableOutputNetwork;
pub use crate::transitional::concise_human_readable::print_path;
pub use crate::transitional::concise_human_readable::print_path_header;
pub use crate::transitional::concise_human_readable::print_path_error;

pub fn required_trust_amount(trust_amount: Option<TrustAmount<usize>>,
                             certification_network: bool)
    -> Result<usize>
{
    let amount = if let Some(v) = &trust_amount {
        v.amount()
    } else {
        if certification_network {
            // Look for multiple paths.  Specifically, try to find 10
            // paths.
            10 * wot::FULLY_TRUSTED
        } else {
            wot::FULLY_TRUSTED
        }
    };

    Ok(amount)
}

/// The context in which list is called.
///
/// This controls the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListContext {
    PKI,
    Download,
}

impl Sequoia {
    /// List bindings.
    ///
    /// See [`Builder`] for details.
    pub fn list<Q>(&self, queries: Vec<Q>,
                   o: &mut dyn std::io::Write)
        -> Result<()>
    where
        Q: Into<Query>,
    {
        self.list_builder(queries).execute(o)
    }

    /// Returns a builder that can be used to configure
    /// `Sequoia::list`'s behavior.
    pub fn list_builder<Q>(&self, queries: Vec<Q>) -> Builder
    where
        Q: Into<Query>,
    {
        let queries: Vec<Query>
            = queries.into_iter().map(|q| q.into()).collect();

        Builder {
            sequoia: self,
            context: ListContext::PKI,
            queries,
            gossip: false,
            unusable: false,
            certification_network: false,
            trust_amount: None,
            show_paths: false,
        }
    }
}

/// Lists bindings.
///
/// This command builder lists bindings.
///
/// By default, it returns all bindings that are fully authenticated.
pub struct Builder<'a> {
    sequoia: &'a Sequoia,
    context: ListContext,
    queries: Vec<Query>,
    gossip: bool,
    unusable: bool,
    certification_network: bool,
    trust_amount: Option<TrustAmount<usize>>,
    show_paths: bool,
}

impl Builder<'_> {
    /// Sets gossip mode.
    ///
    /// By default gossip mode is disabled.
    ///
    /// When gossip mode is enabled, this function returns all usable
    /// bindings (see [`Builder::unusable`]) and any
    /// unauthenticated paths to binding.  An unauthenticated path is
    /// one that doesn't include a trust root.
    ///
    /// Consider the following scenario: Alice has certified Bob's
    /// certificate and the caller wants to authenticate Bob's
    /// certificate.  If the caller does not consider Alice to be a
    /// trusted introducer (either directly as a trust root, or
    /// indirectly), then the path `Alice -> Bob` will not be
    /// returned.  When gossip mode is enabled, such paths are also
    /// returned.  The aggregate trust amount is still accurate.
    ///
    /// Gossip is useful to determine who certified a given binding
    /// even if the certified is not considered a trusted introducer.
    ///
    /// Note: Enabling gossip mode is not equivalent to setting the
    /// trust amount to 0 using [`Builder::trust_amount`].
    /// Setting the trust amount to 0 will return all valid bindings,
    /// but it will not return any unauthenticated paths.
    pub fn gossip(&mut self, gossip: bool) -> &mut Self {
        self.gossip = gossip;
        self
    }

    /// Sets whether unusable bindings should be returned.
    ///
    /// By default unusable bindings are not returned.  An unusable
    /// binding is one where the binding is not valid according to the
    /// current cryptographic policy, the certificate or user ID is
    /// revoked, or the binding is not live.  Setting this option
    /// causes these bindings to be returned.
    ///
    /// Note: the bindings still have to meet the trust threshold.  As
    /// such, this option is only meaningful if gossip mode is also
    /// enabled (see [`Builder::gossip`]).
    pub fn unusable(&mut self, unusable: bool) -> &mut Self {
        self.unusable = unusable;
        self
    }

    /// Sets whether the network should be viewed as a certification
    /// network.
    ///
    /// By default, `Sequoia::authenticate` treats the network as an
    /// authentication network.  That means if Alice certifies Bob's
    /// certificate and Bob certifies Carol's certificate, then
    /// relying on Alice is not enough to authenticate Carol's
    /// certificate: Alice only certified Bob's certificate; she did
    /// not indicate that he should be treated as a trusted
    /// introducer.  In a certification network, all certifications
    /// are treated as delegations.
    ///
    /// Certification networks are useful for understanding how well a
    /// group of people are connected.  They should not be use for
    /// authentication purposes.
    pub fn certification_network(&mut self, certification_network: bool)
        -> &mut Self
    {
        self.certification_network = certification_network;
        self
    }

    /// Sets the threshold at which a binding is considered
    /// authenticated.
    ///
    /// By default a binding is considered authenticated if the trust
    /// amount is at least `sequoia_wot::FULLY_TRUSTED` (120).
    ///
    /// If gossip mode is enabled, that mode takes precedence, and the
    /// trust amount is ignored.
    pub fn trust_amount<T>(&mut self, trust_amount: T)
        -> &mut Self
    where
        T: Into<Option<TrustAmount<usize>>>
    {
        self.trust_amount = trust_amount.into();
        self
    }

    /// Sets the execution context.
    ///
    /// This controls what output is shown.
    ///
    /// TRANSITIONAL.
    pub fn context(&mut self, context: ListContext) -> &mut Self {
        self.context = context;
        self
    }

    /// Whether to show the authenticated paths in the output.
    ///
    /// By default only bindings are shown.  When enabled, for each
    /// binding that is shown, some paths are also displayed.  Note:
    /// because there may be many paths, not all paths are shown, but
    /// a sufficient number are shown to justify the judgment.
    ///
    /// TRANSITIONAL.
    pub fn show_paths(&mut self, show_paths: bool) -> &mut Self {
        self.show_paths = show_paths;
        self
    }

    /// Execute authenticate with the configured parameters.
    pub fn execute(&self, o: &mut dyn std::io::Write) -> Result<()> {
        let &Builder {
            sequoia,
            ref context,
            ref queries,
            gossip,
            unusable,
            certification_network,
            trust_amount,
            show_paths,
        } = self;

        tracer!(TRACE, "authenticate");

        make_qprintln!(sequoia.config().quiet());

        let queries_;
        let queries = if queries.is_empty() {
            queries_ = vec![ Query::all() ];
            &queries_
        } else {
            queries
        };

        let return_all = queries.iter().any(|q| matches!(q.kind, QueryKind::All));

        // Build the network.
        let cert_store = sequoia.cert_store_or_else()?;
        if return_all {
            cert_store.precompute();
        }

        let mut n = wot::NetworkBuilder::rooted(cert_store, &*sequoia.trust_roots());
        if certification_network {
            n = n.certification_network();
        }
        let n = n.build();

        let required_amount =
            required_trust_amount(trust_amount, certification_network)?;
        t!("required amount: {} (gossip: {})", required_amount, gossip);

        // Map a key handle to the named certificates.
        let resolve_key_handle = |kh: &KeyHandle| -> Vec<Fingerprint> {
            match kh {
                KeyHandle::Fingerprint(fpr) => vec![ fpr.clone() ],
                KeyHandle::KeyID(_) => {
                    if let Ok(certs) = cert_store.lookup_by_cert(&kh) {
                        certs.into_iter().map(|c| c.fingerprint()).collect()
                    } else {
                        // We don't error out here: at the end of this
                        // function we check that all queries matched at
                        // least one certificate.
                        vec![]
                    }
                }
            }
        };

        // Get the candidates.
        //
        // The `bool` means: always show the certificate, even if it can't
        // be authenticated.  The `Vec<usize>` are the queries that
        // resolve to that binding.
        let mut bindings: Vec<(Fingerprint, Option<UserID>, bool, Vec<usize>)>
            = Vec::new();

        // Whether query #index matched something.
        let mut queries_satisfied = vec![false; queries.len()];

        for (i, query) in queries.iter().enumerate() {
            match &query.kind {
                QueryKind::AuthenticatedCert(kh) | QueryKind::Cert(kh) => {
                    t!("Authenticating {}", kh);

                    let cert_authenticated
                        = matches!(query.kind, QueryKind::AuthenticatedCert(_));

                    for fpr in resolve_key_handle(kh) {
                        let count = bindings.len();
                        bindings.extend(
                            n.certified_userids_of(&fpr)
                                .into_iter()
                                .map(|userid| {
                                    (fpr.clone(), Some(userid),
                                     cert_authenticated, vec![ i ])
                                }));

                        if bindings.len() == count {
                            // No user IDs.  Add the certificate.
                            bindings.push((fpr.clone(), None,
                                           cert_authenticated, vec![ i ]));
                        }
                    }
                }
                QueryKind::UserID(userid) => {
                    t!("Authenticating user ID: {:?}", userid);

                    bindings.extend(
                        n.lookup_synopses_by_userid(UserID::from(&userid[..]))
                            .into_iter()
                            .map(|fpr| {
                                (fpr, Some(UserID::from(&userid[..])),
                                 false, vec![ i ])
                            }));
                }
                QueryKind::EmailBinding(_, email) | QueryKind::Email(email) =>
                {
                    let kh = if let QueryKind::EmailBinding(kh, _) = &query.kind {
                        t!("Authenticating binding: {}, {:?}", kh, email);
                        Some(kh)
                    } else {
                        t!("Authenticating email: {:?}", email);
                        None
                    };

                    let userid_check = UserID::from(format!("<{}>", email));
                    if let Ok(Some(email_check)) = userid_check.email() {
                        if email != email_check {
                            return Err(anyhow::anyhow!(
                                "{:?} does not appear to be an email address",
                                email));
                        }
                    } else {
                        return Err(anyhow::anyhow!(
                            "{:?} does not appear to be an email address",
                            email));
                    }

                    // Now, iterate over all of the certifications of the target,
                    // and select the bindings where the User ID matches the email
                    // address.
                    let b = if let Some(kh) = kh.as_ref() {
                        let fprs = resolve_key_handle(kh);
                        fprs.into_iter().flat_map(|fpr| {
                            n.certified_userids_of(&fpr)
                                .into_iter()
                                .map(|userid| (fpr.clone(), Some(userid)))
                                .collect::<Vec<_>>()
                                .into_iter()
                        }).collect::<Vec<_>>()
                    } else {
                        n.lookup_synopses_by_email(&email)
                            .into_iter()
                            .map(|(fp, userid)| (fp, Some(userid)))
                            .collect()
                    };

                    let email_normalized = userid_check.email_normalized()
                        .expect("checked").expect("checked");
                    bindings.extend(
                        b.into_iter().filter_map(|(fingerprint, userid_other)| {
                            if let Some(email_other_normalized)
                                = userid_other.as_ref()
                                .and_then(|u| u.email_normalized().ok())
                                .flatten()
                            {
                                if email_normalized == email_other_normalized {
                                    Some((fingerprint, userid_other.clone(),
                                          false, vec![ i ]))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }));
                }
                QueryKind::UserIDBinding(kh, userid) => {
                    t!("Authenticating {}, {:?}", kh, userid);
                    for fpr in resolve_key_handle(kh) {
                        bindings.push((fpr, Some(UserID::from(&userid[..])),
                                       false, vec![ i ]));
                    }
                }
                QueryKind::Domain(pattern) | QueryKind::Pattern(pattern) => {
                    let pattern_;
                    let (query_params, pattern)
                        = if let QueryKind::Domain(_) = query.kind
                    {
                        t!("Authenticating domain {}", pattern);

                        let domain = UserIDQueryParams::is_domain(pattern)?;
                        let mut query_params = UserIDQueryParams::new();
                        query_params.set_email(true)
                            .set_anchor_start(false);
                        pattern_ = format!("@{}", domain);

                        (query_params, &pattern_)
                    } else {
                        if pattern.is_empty() {
                            t!("Authenticating everything");
                        } else {
                            t!("Authenticating user IDs matching {:?}", pattern);
                        }

                        let mut query_params = UserIDQueryParams::new();
                        query_params
                            .set_email(false)
                            .set_anchor_start(false)
                            .set_anchor_end(false)
                            .set_ignore_case(true);

                        (query_params, pattern)
                    };

                    if ! pattern.is_empty() {
                        // If the pattern doesn't match anything, don't
                        // abort yet.  There might be other queries.
                        if let Ok(matches)
                            = cert_store.select_userid(&query_params, pattern)
                        {
                            bindings.extend(
                                matches
                                    .into_iter()
                                    .flat_map(|cert| {
                                        cert.userids()
                                            .filter(|userid| {
                                                t!("Checking {}, {}",
                                                   cert.fingerprint(),
                                                   String::from_utf8_lossy(userid.value()));

                                                query_params.check(&userid, pattern)
                                            })
                                            .map(|userid| {
                                                (cert.fingerprint(), Some(userid),
                                                 false, vec![ i ])
                                            })
                                            .collect::<Vec<_>>()
                                            .into_iter()
                                    }));
                        }
                    } else {
                        bindings.extend(
                            n.certified_userids()
                                .into_iter()
                                .map(|(fp, userid)| {
                                    (fp, Some(userid), false, vec![ i ])
                                }));
                    }
                }
                QueryKind::All => {
                    // --all is always satisfied.
                    queries_satisfied[i] = true;

                    let mut certs = BTreeSet::new();
                    bindings.extend(
                        n.certified_userids()
                            .into_iter()
                            .map(|(fp, userid)| {
                                certs.insert(fp.clone());

                                (fp, Some(userid), false, vec![ i ])
                            }));

                    // Add certificates without user IDs.
                    let all_certs: BTreeSet<_> = n.iter_fingerprints().collect();
                    bindings.extend(
                        all_certs.difference(&certs).map(|fp| {
                            (fp.clone(), None, false, vec![ i ])
                        }));
                }
            }
        }

        // There may be multiple certifications of the same
        // User ID.  Dedup.
        bindings.sort_by(
            |(a_fpr, a_userid, _, _), (b_fpr, b_userid, _, _)|
            {
                a_fpr.cmp(b_fpr)
                    .then(a_userid.cmp(b_userid))
            });
        bindings.dedup_by(
            |(a_fpr, a_userid, a_show, a_idx), (b_fpr, b_userid, b_show, b_idx)|
            {
                if a_fpr == b_fpr && a_userid == b_userid {
                    // debup removes a, so we merge into b.
                    b_idx.extend_from_slice(&a_idx[..]);
                    *b_show |= *a_show;
                    true
                } else {
                    false
                }
            });
        t!("Checking {} bindings", bindings.len());

        // The number of matching bindings that we showed.
        let mut bindings_authenticated = 0;

        // The number of bindings that we skipped because the certificate
        // or user ID was invalid / unusable.
        let mut bindings_unusable = 0;

        let mut output = ConciseHumanReadableOutputNetwork::new(
            o, sequoia, required_amount, show_paths);

        // Look up the certificate, and return it if it is valid.
        let check_cert = |fpr: &Fingerprint| -> Result<Cert> {
            // Look up the certificate.
            let kh = KeyHandle::from(fpr);
            let lc = match cert_store.lookup_by_cert(&kh) {
                Ok(certs) => {
                    assert_eq!(certs.len(), 1, "there can be only one");
                    certs.into_iter().next().unwrap()
                }
                Err(err) => {
                    // See if it is a subkey.
                    if let Some(StoreError::NotFound(_)) = err.downcast_ref() {
                        if let Ok(certs)
                            = cert_store.lookup_by_cert_or_subkey(&kh)
                        {
                            return Err(anyhow::anyhow!(
                                "{} appears to be a subkey of {}",
                                fpr,
                                certs.iter()
                                    .map(|c| c.fingerprint().to_string())
                                    .collect::<Vec<String>>()
                                    .join(", ")));
                        }
                    }

                    return Err(err);
                }
            };

            let cert = lc.to_cert()
                .with_context(|| format!("{} is unusable", fpr))?;

            // Check if the certificate is valid according to the current
            // policy.
            let vc = cert.with_policy(sequoia.policy(), sequoia.time())
                .with_context(|| format!("{} is unusable", fpr))?;

            // Check if the certificate is live.
            let _ = vc.alive()
                .with_context(|| format!("{} is not live", fpr))?;

            // Check that it is not revoked.
            if let RevocationStatus::Revoked(sigs)
                = cert.revocation_status(sequoia.policy(), sequoia.time())
            {
                if let Some((reason, message))
                    = sigs[0].reason_for_revocation()
                {
                    return Err(anyhow::anyhow!(
                        "{} is revoked: {}{}.",
                        cert.fingerprint(),
                        reason,
                        Safe(message)));
                } else {
                    return Err(anyhow::anyhow!(
                        "{} is revoked: unspecified reason.",
                        cert.fingerprint()));
                }
            }

            Ok(cert.clone())
        };

        // Check that the user ID is valid.
        let check_userid = |cert: &Cert, userid: &UserID| -> Result<()> {
            if let Some(ua)
                = cert.userids().find(|ua| ua.userid() == userid)
            {
                if let RevocationStatus::Revoked(sigs)
                    = ua.revocation_status(sequoia.policy(), sequoia.time())
                {
                    if let Some((reason, message))
                        = sigs[0].reason_for_revocation()
                    {
                        return Err(anyhow::anyhow!(
                            "{}, {} is revoked: {}{}.",
                            cert.fingerprint(),
                            userid,
                            reason,
                            Safe(message)));
                    } else {
                        return Err(anyhow::anyhow!(
                            "{}, {} is revoked: unspecified reason.",
                            cert.fingerprint(), userid));
                    }
                }
            }

            Ok(())
        };

        // bool: true if the lint is for the certificate (not the user ID).
        let mut lints: Vec<(anyhow::Error, bool, &[usize])>
            = Vec::with_capacity(queries.len());

        for (fingerprint, userid, cert_authenticated, i) in bindings.iter() {
            if let Some(userid) = userid {
                let paths = if gossip {
                    n.gossip(fingerprint.clone(), userid.clone())
                } else {
                    n.authenticate(
                        userid.clone(), fingerprint.clone(), required_amount)
                };

                let aggregated_amount = paths.amount();
                t!("{}, {:?}: {}", fingerprint, userid, aggregated_amount);
                let userid_authenticated = if aggregated_amount >= required_amount {
                    // We authenticated the binding!
                    true
                } else if gossip && (aggregated_amount > 0 || unusable) {
                    // We're in gossip mode, show all bindings...
                    true
                } else if gossip && aggregated_amount == 0 {
                    // ... as long as the certificate is valid...
                    let cert = match check_cert(&fingerprint) {
                        Err(err) => {
                            t!("Skipping {}: {}", fingerprint, err);
                            bindings_unusable += 1;
                            lints.push((err, true, &i));
                            continue;
                        }
                        Ok(cert) => cert
                    };

                    // ... and the user ID is not revoked.
                    if let Err(err) = check_userid(&cert, &userid)
                    {
                        t!("Skipping {}, {}: {}", fingerprint, userid, err);
                        if ! *cert_authenticated {
                            bindings_unusable += 1;
                            lints.push((err, false, &i));
                            continue;
                        }
                        false
                    } else {
                        true
                    }
                } else if *cert_authenticated {
                    // The binding is not authenticated, but we should
                    // show the certificate if it is valid.
                    if let Err(err) = check_cert(&fingerprint) {
                        t!("Skipping {}: {}", fingerprint, err);
                        bindings_unusable += 1;
                        lints.push((err, true, &i));
                        continue;
                    }

                    false
                } else {
                    // Don't show it.
                    t!("Failed to sufficiently authenticate the binding");

                    if aggregated_amount == 0 {
                        if let Err(err) = check_cert(&fingerprint) {
                            t!("{}: {}", fingerprint, err);
                            bindings_unusable += 1;
                            lints.push((err, true, &i));
                        } else {
                            if ! n.certified_userids_of(fingerprint)
                                .contains(userid)
                            {
                                lints.push((
                                    anyhow::anyhow!(
                                        "{:?} was never certified for {}",
                                        String::from_utf8_lossy(userid.value()),
                                        fingerprint),
                                    false, &i));
                            }
                        }
                    }

                    continue;
                };

                output.add_cert(fingerprint)?;
                if userid_authenticated {
                    let paths = paths.into_iter().collect::<Vec<(wot::Path, usize)>>();
                    output.add_paths(paths, fingerprint, userid, aggregated_amount)?;

                    bindings_authenticated += 1;
                }
            } else {
                // A certificate with no User ID bindings.
                if gossip || *cert_authenticated {
                    if ! unusable {
                        if let Err(err) = check_cert(fingerprint) {
                            t!("Skipping {}: {}", fingerprint, err);
                            bindings_unusable += 1;
                            lints.push((err, true, &i));
                            continue;
                        }
                    }

                    output.add_cert(fingerprint)?;
                    bindings_authenticated += 1;
                } else {
                    t!("Skipping {}: no user IDs", fingerprint);
                    continue;
                }
            }

            for i in i.into_iter() {
                queries_satisfied[*i] = true;
            }
        }

        output.finalize()?;

        let mut unsatisfied = 0;
        for (i, satisfied) in queries_satisfied.into_iter().enumerate() {
            if satisfied {
                continue;
            }
            unsatisfied += 1;

            // We didn't show anything.  Try to figure out what was wrong.
            let query = &queries[i];

            if *context == ListContext::PKI {
                if gossip {
                    qprintln!("No valid bindings match {}.",
                              query.argument.as_deref().unwrap_or("the query"));
                } else {
                    qprintln!("No bindings matching {} could be authenticated.",
                              query.argument.as_deref().unwrap_or("the query"));
                }
            }

            for (lint, for_cert, is) in lints.iter() {
                if ! gossip && *for_cert {
                    use QueryKind::*;
                    match queries[i].kind {
                        AuthenticatedCert(_) | Cert(_)
                            | UserIDBinding(_, _) | EmailBinding(_, _) | All =>
                        {
                            ()
                        }
                        UserID(_) | Email(_) | Domain(_) | Pattern(_) => {
                            // It's a certificate-specific lint, but we're
                            // matching on user IDs.  Skip it.
                            continue;
                        }
                    }
                }
                if is.contains(&i) {
                    qprintln!(initial_indent = "  - ",
                              "Warning: {}",
                              crate::transitional::one_line_error_chain(lint));
                }
            }
        }

        // See if the trust roots exist.
        if unsatisfied > 0 && ! gossip && *context == ListContext::PKI {
            if n.roots().iter().all(|r| {
                let fpr = r.fingerprint();
                if let Err(err) = n.lookup_synopsis_by_fpr(&fpr) {
                    qprintln!("Looking up trust root ({}): {}.",
                              fpr, err);
                    true
                } else {
                    false
                }
            })
            {
                qprintln!("Warning: No trust roots found.");
            }
        }

        if *context == ListContext::PKI {
            if bindings.is_empty() {
                // There are no matching bindings.

                qprintln!("No valid bindings match the query.");

                if queries.len() == 1 {
                    if let QueryKind::Pattern(pattern) = &queries[0].kind {
                        // Tell the user about `sq network fetch`.
                        sequoia.hint(format_args!(
                            "Try searching public directories:"))
                            .sq().arg("network").arg("search")
                            .arg(pattern)
                            .done();
                    }
                } else if n.iter_fingerprints().next().is_none() {
                    qprintln!("Warning: The certificate store does not contain any \
                               certificates.");

                    if return_all {
                        sequoia.hint(format_args!(
                            "Consider creating a key for yourself:"))
                            .sq().arg("key").arg("generate")
                            .arg_value("--name", "your-name")
                            .arg_value("--email", "your-email-address")
                            .arg("--own-key")
                            .done();

                        sequoia.hint(format_args!(
                            "Consider importing other peoples' certificates:"))
                            .sq().arg("cert").arg("import")
                            .arg("a-cert-file.pgp")
                            .done();

                        sequoia.hint(format_args!(
                            "Try searching public directories for other peoples' \
                             certificates:"))
                            .sq().arg("network").arg("search")
                            .arg("some-mail-address")
                            .done();
                    }
                }
            } else if gossip {
                // We are in gossip mode.  Mention `sq pki link` as a way to
                // mark bindings as authenticated.
                if bindings_authenticated > 0 {
                    qprintln!("After checking that a user ID really belongs to \
                               a certificate, use `sq pki link add` to mark \
                               the binding as authenticated, or use \
                               `sq network search FINGERPRINT|EMAIL` to look for \
                               new certifications.");
                } else {
                    qprintln!("No bindings are valid.");
                }
            }

            if bindings.len() - bindings_authenticated > 0 {
                // Some of the matching bindings were not shown.  Tell the
                // user about the `--gossip` option.
                let bindings = bindings.len();
                assert!(bindings > 0);
                let bindings_not_authenticated
                    = bindings - bindings_authenticated - bindings_unusable;

                if bindings == 1 {
                    qprintln!("1 binding found.");
                } else {
                    qprintln!("{} bindings found.", bindings);
                }

                if bindings_unusable == 1 {
                    qprintln!("Skipped 1 binding, which is unusable.");
                } else if bindings_unusable > 1 {
                    qprintln!("Skipped {} bindings, which are unusable.",
                              bindings_unusable);
                }

                if bindings_not_authenticated == 1 {
                    qprintln!("Skipped 1 binding, which could not be authenticated.");
                    qprintln!("Pass `--gossip` to see the unauthenticated binding.");
                } else if bindings_not_authenticated > 1 {
                    qprintln!("Skipped {} bindings, which could not be authenticated.",
                              bindings_not_authenticated);
                    qprintln!("Pass `--gossip` to see the unauthenticated bindings.");
                }
            }
        }

        if unsatisfied == 1 {
            if gossip {
                if queries.len() == 1 {
                    Err(anyhow::anyhow!("No bindings match the query."))
                } else {
                    Err(anyhow::anyhow!("No bindings match one of the queries."))
                }
            } else {
                if queries.len() == 1 {
                    Err(anyhow::anyhow!(
                        "No bindings matching the query could be authenticated."))
                } else {
                    Err(anyhow::anyhow!(
                        "No bindings matching one of the queries could be authenticated."))
                }
            }
        } else if unsatisfied > 1 {
            if gossip {
                Err(anyhow::anyhow!("No bindings match {} of the queries.",
                                    unsatisfied))
            } else {
                Err(anyhow::anyhow!(
                    "No bindings matching {} of the queries could be authenticated.",
                    unsatisfied))
            }
        } else {
            Ok(())
        }
    }
}
