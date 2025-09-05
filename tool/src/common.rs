use std::collections::BTreeSet;

use sequoia::openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::policy::NullPolicy;

pub mod cert_designator;
pub mod file;

mod revoke;
pub use revoke::get_secret_signer;
pub use revoke::RevocationOutput;

pub mod key;

pub mod password;
pub mod pki;
pub mod userid;

pub mod types;
pub mod ui;

pub const NULL_POLICY: &NullPolicy = unsafe { &NullPolicy::new() };

/// Dealias and deduplicate a list of key handles.
///
/// A signature often has a fingerprint issuer packet and a key ID
/// issuer packet where the key ID is just the key ID of the
/// fingerprint.  Remove these aliases.
pub fn key_handle_dealias(khs: &[KeyHandle]) -> impl Iterator<Item = KeyHandle> {
    let mut fprs: Vec<Fingerprint> = Vec::with_capacity(khs.len());
    let mut keyids: Vec<KeyID> = Vec::with_capacity(khs.len());

    khs.iter().fold((&mut fprs, &mut keyids), |(fprs, keyids), kh| {
        match kh {
            KeyHandle::Fingerprint(fpr) => fprs.push(fpr.clone()),
            KeyHandle::KeyID(keyid) => keyids.push(keyid.clone()),
        }

        (fprs, keyids)
    });

    fprs.sort();
    fprs.dedup();

    keyids.sort();
    keyids.dedup();

    // Remove any key IDs that alias a fingerprint.
    let dedup: BTreeSet<KeyID> = fprs
        .iter()
        .map(|fpr| KeyID::from(fpr))
        .collect();

    keyids.retain(|keyid| ! dedup.contains(keyid));

    fprs.into_iter().map(KeyHandle::from)
        .chain(keyids.into_iter().map(KeyHandle::from))
}
