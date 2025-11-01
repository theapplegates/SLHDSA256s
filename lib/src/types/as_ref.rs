//! A local copy of the standard library's AsRef trait.

use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;

/// A local copy of the standard library's AsRef trait.
///
/// We need a local copy of AsRef, as we need to implement AsRef for
/// UserID, but due to the orphan rule, we can't.  Instead we have to
/// make a local copy of AsRef or UserID.  Copying AsRef is less
/// invasive.
pub trait MyAsRef<T>
where
    T: ?Sized,
{
    fn as_ref(&self) -> &T;
}

impl MyAsRef<UserID> for UserID {
    fn as_ref(&self) -> &UserID {
        self
    }
}

impl MyAsRef<UserID> for &UserID {
    fn as_ref(&self) -> &UserID {
        self
    }
}
