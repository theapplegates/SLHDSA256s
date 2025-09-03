use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

/// The different kinds of queries that we support.
#[derive(Debug, Clone)]
pub enum QueryKind {
    AuthenticatedCert(KeyHandle),
    Cert(KeyHandle),
    UserID(String),
    Email(String),
    UserIDBinding(KeyHandle, String),
    EmailBinding(KeyHandle, String),
    Domain(String),
    Pattern(String),
    All,
}

#[derive(Debug, Clone)]
pub struct Query {
    /// The user-supplied command-line argument, e.g., `--cert
    /// FINGERPRINT`.
    pub argument: Option<String>,
    pub kind: QueryKind,
}

impl Query {
    /// Returns a `Query` that matches all bindings.
    pub fn all() -> Self {
        Query {
            argument: None,
            kind: QueryKind::All,
        }
    }

    /// Returns a `Query` for a key handle.
    ///
    /// `argument` is the user-supplied command-line argument, e.g.,
    /// `--cert FINGERPRINT`.
    pub fn for_key_handle(argument: Option<String>, kh: KeyHandle)
        -> Query
    {
        Query {
            argument,
            kind: QueryKind::Cert(kh),
        }
    }
}
