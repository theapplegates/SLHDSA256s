use typenum::Unsigned;

use sequoia::types::Query;
use sequoia::types::QueryKind;

use crate::cli;
use cli::types::CertDesignators;
use cli::types::cert_designator;
use cli::types::userid_designator;
use cli::types::UserIDDesignators;

impl<Arguments, Prefix, Options, Doc>
    CertDesignators<Arguments, Prefix, Options, Doc>
where
    Arguments: typenum::Unsigned,
    Prefix: cert_designator::ArgumentPrefix,
{
    /// Converts a set of certificate designators to a set of queries.
    pub fn cert_query(self, certs_are_authenticated: bool)
        -> Vec<Query>
    {
        let arguments = Arguments::to_usize();
        let file_arg = (arguments & cert_designator::FileArg::to_usize()) > 0;
        let special_arg = (arguments & cert_designator::SpecialArg::to_usize()) > 0;
        let self_arg = (arguments & cert_designator::SelfArg::to_usize()) > 0;

        assert!(! file_arg);
        assert!(! special_arg);
        assert!(! self_arg);

        self.iter()
            .map(|designator| {
                use cert_designator::CertDesignator::*;
                let kind = match designator {
                    Stdin | File(_) | Special(_) | Self_ => {
                        unreachable!("Not allowed in this context");
                    }
                    Cert(kh) => {
                        if certs_are_authenticated {
                            QueryKind::AuthenticatedCert(kh.clone())
                        } else {
                            QueryKind::Cert(kh.clone())
                        }
                    }
                    UserID(userid) => QueryKind::UserID(userid.clone()),
                    Email(email) => QueryKind::Email(email.clone()),
                    Domain(domain) => QueryKind::Domain(domain.clone()),
                    Grep(pattern) => QueryKind::Pattern(pattern.clone()),
                };

                Query {
                    argument: Some(designator.argument::<Prefix>()),
                    kind,
                }
            })
            .collect()
    }
}

impl<Prefix, Options, Doc>
    CertDesignators<cert_designator::CertArg, Prefix, Options, Doc>
where
    Options: typenum::Unsigned,
    Prefix: cert_designator::ArgumentPrefix,
{
    /// Creates a query for a binding consisting of a certificate
    /// designator and a user ID designator.
    pub fn binding_query<UserIDArguments, UserIDOptions, UserIDDocumentation>
        (self,
         userid: UserIDDesignators<UserIDArguments,
                                   UserIDOptions, UserIDDocumentation>)
        -> Vec<Query>
    where
        UserIDArguments: typenum::Unsigned,
        UserIDOptions: typenum::Unsigned,
    {
        // One required value.
        let cert_options = Options::to_usize();
        let cert_one_value
            = (cert_options & cert_designator::OneValue::to_usize()) > 0;
        let cert_optional_value
            = (cert_options & cert_designator::OptionalValue::to_usize()) > 0;
        assert!(cert_one_value);
        assert!(! cert_optional_value);

        // One required value.
        let userid_options = UserIDOptions::to_usize();
        let userid_one_value
            = (userid_options & userid_designator::OneValue::to_usize()) > 0;
        let userid_optional_value
            = (userid_options & userid_designator::OptionalValue::to_usize()) > 0;
        assert!(userid_one_value);
        assert!(! userid_optional_value);

        assert_eq!(self.len(), 1);
        let cert = self.iter().next().unwrap();
        let kh = if let cert_designator::CertDesignator::Cert(kh) = cert {
            kh
        } else {
            unreachable!("Only CertArg");
        };

        assert_eq!(userid.len(), 1);
        let userid = userid.iter().next().unwrap();
        let kind = match userid {
            userid_designator::UserIDDesignator::UserID(_, userid) => {
                QueryKind::UserIDBinding(kh.clone(), userid.clone())
            }
            userid_designator::UserIDDesignator::Email(_, email) => {
                QueryKind::EmailBinding(kh.clone(), email.clone())
            }
            userid_designator::UserIDDesignator::Name(_, _name) => {
                unreachable!("--name is disabled")
            }
        };

        vec![
            Query {
                argument: Some(format!("{} {}",
                                       cert.argument::<Prefix>(),
                                       userid.argument::<UserIDArguments>())),
                kind,
            }
        ]
    }
}

impl<Arguments, Prefix, Options, Doc>
    From<CertDesignators<Arguments, Prefix, Options, Doc>> for Vec<Query>
where
    Arguments: typenum::Unsigned,
    Prefix: cert_designator::ArgumentPrefix,
{
    fn from(designators: CertDesignators<Arguments, Prefix, Options, Doc>)
        -> Vec<Query>
    {
        designators.cert_query(false)
    }
}

impl<Arguments, Options, Documentation>
    From<UserIDDesignators<Arguments, Options, Documentation>> for Vec<Query>
where
    Arguments: typenum::Unsigned,
{
    fn from(designators: UserIDDesignators<Arguments, Options, Documentation>)
        -> Vec<Query>
    {
        designators.iter()
            .map(|designator| {
                use userid_designator::UserIDDesignator::*;
                let kind = match designator {
                    UserID(_, userid) => QueryKind::UserID(userid.clone()),
                    Email(_, email) => QueryKind::Email(email.clone()),
                    Name(_, _name) => {
                        unreachable!("--name is disabled");
                    }
                };

                Query {
                    argument: Some(designator.argument::<Arguments>()),
                    kind,
                }
            })
            .collect()
    }
}
