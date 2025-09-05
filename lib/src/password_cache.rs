use sequoia_openpgp as openpgp;
use openpgp::crypto::Password;

use crate::Sequoia;

impl Sequoia {
    /// Caches a password.
    pub fn cache_password(&self, password: Password) {
        let mut cache = self.password_cache.lock().unwrap();

        if ! cache.contains(&password) {
            cache.push(password);
        }
    }

    /// Caches a password.
    pub fn cache_passwords(&self, passwords: impl Iterator<Item=Password>) {
        let mut cache = self.password_cache.lock().unwrap();

        for password in passwords {
            if ! cache.contains(&password) {
                cache.push(password);
            }
        }
    }

    /// Returns the cached passwords.
    pub fn cached_passwords(&self) -> impl Iterator<Item=Password> {
        self.password_cache.lock().unwrap().clone().into_iter()
    }
}
