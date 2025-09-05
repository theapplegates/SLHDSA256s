// This module contains functions and types that are needed for
// transition sq to a library.  After the transition most of these
// types can probably be removed.
#![allow(dead_code)]

use std::borrow::Borrow;

#[allow(unused_macros)]
#[macro_use] mod macros;

pub mod output;
pub mod stdin;

use output::hint::Hint;
use crate::Sequoia;

impl Sequoia {
    /// Prints a hint for the user.
    pub fn hint(&self, msg: std::fmt::Arguments) -> Hint {
        Hint::new(! self.config.hints())
            .hint(msg)
    }
}

// Sometimes the same error cascades, e.g.:
//
// ```
// $ sq-wot --time 20230110T0406   --keyring sha1.pgp path B5FA089BA76FE3E17DC11660960E53286738F94C 231BC4AB9D8CAB86D1622CE02C0CE554998EECDB FABA8485B2D4D5BF1582AA963A8115E774FA9852 "<carol@example.org>"
// [ ] FABA8485B2D4D5BF1582AA963A8115E774FA9852 <carol@example.org>: not authenticated (0%)
//   ◯ B5FA089BA76FE3E17DC11660960E53286738F94C ("<alice@example.org>")
//   │   No adequate certification found.
//   │   No binding signature at time 2023-01-10T04:06:00Z
//   │     No binding signature at time 2023-01-10T04:06:00Z
//   │     No binding signature at time 2023-01-10T04:06:00Z
// ...
// ```
//
// Compress these.
pub(crate) fn error_chain(err: &anyhow::Error) -> Vec<String> {
    let mut errs = std::iter::once(err.to_string())
        .chain(err.chain().map(|source| source.to_string()))
        .collect::<Vec<String>>();
    errs.dedup();
    errs
}

/// Prints the error and causes, if any.
pub(crate) fn print_error_chain(err: &anyhow::Error) {
    weprintln!();
    weprintln!(initial_indent="  Error: ", "{}", err);

    if err.backtrace().status() == std::backtrace::BacktraceStatus::Captured {
        weprintln!();
        weprintln!(initial_indent="         ", "{}", err.backtrace());
    }
    err.chain().skip(1).for_each(
        |cause| weprintln!(initial_indent="because: ", "{}", cause));
}

/// Returns the error chain as a string.
///
/// The error and causes are separated by `error_separator`.  The
/// causes are separated by `cause_separator`, or, if that is `None`,
/// `error_separator`.
pub(crate) fn display_error_chain<'a, E, C>(err: E,
                                            error_separator: &str,
                                            cause_separator: C)
    -> String
where E: Borrow<anyhow::Error>,
      C: Into<Option<&'a str>>
{
    let err = err.borrow();
    let cause_separator = cause_separator.into();

    let error_chain = error_chain(err);
    match error_chain.len() {
        0 => unreachable!(),
        1 => {
            error_chain.into_iter().next().expect("have one")
        }
        2 => {
            format!("{}{}{}",
                    error_chain[0],
                    error_separator,
                    error_chain[1])
        }
        _ => {
            if let Some(cause_separator) = cause_separator {
                format!("{}{}{}",
                        error_chain[0],
                        error_separator,
                        error_chain[1..].join(cause_separator))
            } else {
                error_chain.join(error_separator)
            }
        }
    }

}

pub(crate) fn one_line_error_chain<E>(err: E) -> String
where E: Borrow<anyhow::Error>,
{
    display_error_chain(err, ": ", ", because ")
}
