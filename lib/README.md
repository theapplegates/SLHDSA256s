# Features

If you enable the `clap` feature then several types in the `config`
implement some `clap` traits.  For instance, `CipherSuite` and
`Profile` implement `clap::ValueEnum`.  This allows these types to be
directly used with clap without having to wrap them, which would
otherwise be required due to Rust's orphan rule (a crate can only
implement a trait for a given struct or enum if the crate defines the
struct or enum, or the crate defines the trait).
