use std::time::SystemTime;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::packet::prelude::*;
use openpgp::policy::Policy;
use openpgp::types::KeyFlags;

use sequoia_cert_store as cert_store;
use cert_store::store::StoreError;

use sequoia_wot as wot;

use crate::NULL_POLICY;
use crate::Sequoia;
use crate::types::PreferredUserID;

impl Sequoia {
    fn primary_userid<T>(policy: &dyn Policy, time: T, cert: &Cert)
        -> Option<UserID>
    where
        T: Into<Option<SystemTime>>
    {
        let time = time.into();

        // Try to be more helpful by including a User ID in the
        // listing.  We'd like it to be the primary one.  Use
        // decreasingly strict policies.
        let mut primary_uid = None;

        // First, apply our policy.
        if let Ok(vcert) = cert.with_policy(policy, time) {
            if let Ok(primary) = vcert.primary_userid() {
                primary_uid = Some(primary.userid());
            }
        }

        // Second, apply the null policy.
        if primary_uid.is_none() {
            if let Ok(vcert) = cert.with_policy(NULL_POLICY, time) {
                if let Ok(primary) = vcert.primary_userid() {
                    primary_uid = Some(primary.userid());
                }
            }
        }

        // As a last resort, pick the first user id.
        if primary_uid.is_none() {
            if let Some(primary) = cert.userids().next() {
                primary_uid = Some(primary.userid());
            }
        }

        primary_uid.map(Clone::clone)
    }

    /// Returns a representative user ID.
    ///
    /// This prefers the primary user ID under the specified policy.
    /// If the certificate is not valid under the specified policy, it
    /// falls back to the NULL policy.  As a last resort, it picks the
    /// first user ID.
    pub(crate) fn self_userid<T>(policy: &dyn Policy, time: T, cert: &Cert)
        -> PreferredUserID
    where
        T: Into<Option<SystemTime>>
    {
        let time = time.into();

        if let Some(userid) = Sequoia::primary_userid(policy, time, cert) {
            PreferredUserID::from_userid(userid, 0)
        } else {
            PreferredUserID::unknown()
        }
    }

    /// Best-effort heuristic to compute the primary User ID of a given cert.
    ///
    /// The returned string is already sanitized, and safe for displaying.
    ///
    /// If `use_wot` is set, then we use the best authenticated user
    /// ID.  If `use_wot` is not set, then we use the primary user ID.
    pub fn best_userid<'u>(&self, cert: &'u Cert, use_wot: bool)
        -> PreferredUserID
    {
        let primary_uid = Sequoia::primary_userid(
            self.policy(), self.time(), cert);

        if let Some(primary_uid) = primary_uid {
            let fpr = cert.fingerprint();

            let mut candidate: (&UserID, usize) = (&primary_uid, 0);

            #[allow(clippy::never_loop)]
            loop {
                // Don't fail if we can't query the user's web of trust.
                if ! use_wot { break; };
                let Ok(q) = self.wot_query() else { break; };
                let q = q.build();
                let authenticate = move |userid: &UserID| {
                    let paths = q.authenticate(userid, &fpr, wot::FULLY_TRUSTED);
                    paths.amount()
                };

                // We're careful to *not* use a ValidCert so that we see all
                // user IDs, even those that are not self signed.

                candidate = (&primary_uid, authenticate(&primary_uid));

                for userid in cert.userids() {
                    let userid = userid.component();

                    if candidate.1 >= wot::FULLY_TRUSTED {
                        // Done.
                        break;
                    }

                    if userid == &primary_uid {
                        // We already considered this one.
                        continue;
                    }

                    let amount = authenticate(&userid);
                    if amount > candidate.1 {
                        candidate = (userid, amount);
                    }
                }

                break;
            }

            let (uid, amount) = candidate;
            PreferredUserID::from_userid(uid.clone(), amount)
        } else {
            // Special case, there is no user id.
            PreferredUserID::unknown()
        }
    }

    /// Best-effort heuristic to compute the primary User ID of a given cert.
    ///
    /// The returned string is already sanitized, and safe for displaying.
    ///
    /// If `use_wot` is set, then we use the best authenticated user
    /// ID.  If `use_wot` is not set, then we use the primary user ID.
    pub fn best_userid_for<'u, F>(&self,
                                  key_handle: &KeyHandle,
                                  keyflags: F,
                                  use_wot: bool)
                                  -> (PreferredUserID, Result<Cert>)
    where
        F: Into<Option<KeyFlags>>,
    {
        let certs = self.lookup(std::iter::once(key_handle),
                                keyflags.into(), false, true);

        match certs {
            Ok(certs) => {
                assert!(! certs.is_empty());

                // Compute the best user ID and the associated trust
                // amount for each cert.
                let mut certs = certs.into_iter().map(|c| {
                    (self.best_userid(&c, use_wot), c)
                }).collect::<Vec<_>>();

                // Sort by trust amount, then fingerprint.  This way,
                // if two certs have the same trust amount, at least
                // the result will be stable.
                certs.sort_by_key(
                    |(puid, cert)| (puid.trust_amount(), cert.fingerprint()));

                // Then pick the one with the highest trust amount.
                let best =
                    certs.into_iter().rev().next().expect("at least one");
                (best.0, Ok(best.1))
            }
            Err(err) => {
                if let Some(StoreError::NotFound(_))
                    = err.downcast_ref()
                {
                    (PreferredUserID::from_string("(certificate not found)", 0),
                     Err(err))
                } else {
                    (PreferredUserID::from_string(
                        format!("(error looking up certificate: {})", err), 0),
                     Err(err))
                }
            }
        }
    }
}
