use std::fmt::Write;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::packet::UserID;

use sequoia_wot as wot;
use wot::PathLints;
use wot::FULLY_TRUSTED;

use crate::ca_creation_time;
use crate::transitional::error_chain;
use crate::transitional::output::wrapping::NBSP;
use crate::types::Safe;

/// Prints information on a Path for a UserID
pub fn print_path(output: &mut dyn std::io::Write,
                  path: &PathLints, target_userid: &UserID, prefix: &str)
    -> Result<()>
{
    let certification_count = path.certifications().count();
    wwriteln!(stream=output, initial_indent=format!("{}◯─┬ ", prefix),
              subsequent_indent=format!("{}│ │ ", prefix),
              "{}", path.root().key_handle());
    wwriteln!(stream=output, initial_indent=format!("{}│ └ ", prefix),
              subsequent_indent=format!("{}│   ", prefix),
              "{}",
              if certification_count == 0 {
                  format!("{}", Safe(target_userid))
              } else if let Some(userid) = path.root().primary_userid() {
                  format!("({})", Safe(&userid))
              } else {
                  format!("")
              });

    if path.certifications().count() == 0 {
        wwriteln!(stream=output, indent=prefix, "│");
        wwriteln!(stream=output, initial_indent=format!("{}└── ", prefix),
                  subsequent_indent=format!("{}    ", prefix),
                  "Self-signed user ID.");
        return Ok(());
    }

    for (last, (cert, certification)) in path
        .certs()
        .zip(path.certifications())
        .enumerate()
        .map(|(j, c)| {
            if j + 1 == certification_count {
                (true, c)
            } else {
                (false, c)
            }
        })
    {
        let mut line = String::new();
        if let Some(certification) = certification.certification() {
            if certification.amount() < FULLY_TRUSTED {
                write!(&mut line,
                   "partially certified (amount: {}{}of{}120)",
                    certification.amount(), NBSP, NBSP,
                )?;
            } else {
                write!(&mut line, "certified")?;
            }

            if last {
                write!(&mut line, " the following binding")?;
            } else {
                write!(&mut line, " the following certificate")?;
            }

            if certification.creation_time() != ca_creation_time() {
                write!(&mut line,
                       " on {}",
                       chrono::DateTime::<chrono::Utc>::from(
                           certification.creation_time()
                       )
                       .format("%Y‑%m‑%d")
                )?;
            }

            if let Some(e) = certification.expiration_time() {
                write!(&mut line,
                    " (expiry: {})",
                    chrono::DateTime::<chrono::Utc>::from(e).format("%Y‑%m‑%d")
                )?;
            }
            if certification.depth() > 0.into() {
                write!(&mut line, " as a")?;
                if certification.depth() == 1.into() {
                    write!(&mut line, " introducer (depth: {})",
                           certification.depth())?;
                } else {
                    write!(&mut line,
                        " meta-introducer (depth: {})",
                        certification.depth()
                    )?;
                }
            }
        } else {
            write!(&mut line, " No adequate certification found.")?;
        }

        wwriteln!(stream=output, indent=prefix, "│");
        wwriteln!(stream=output, indent=format!("{}│  ", prefix), "{}", line);
        wwriteln!(stream=output, indent=prefix, "│");

        for err in cert.errors().iter().chain(cert.lints()) {
            for (i, msg) in error_chain(err).into_iter().enumerate() {
                wwriteln!(
                    stream=output,
                    indent=format!(
                        "{}│  {}", prefix, if i == 0 { "" } else { "  " }),
                    "{}", msg);
            }
        }
        for err in certification.errors().iter().chain(certification.lints()) {
            for (i, msg) in error_chain(err).into_iter().enumerate() {
                wwriteln!(
                    stream=output,
                    indent=format!(
                        "{}│  {}", prefix, if i == 0 { "" } else { "  " }),
                    "{}", msg);
            }
        }

        wwriteln!(stream=output,
                  initial_indent=format!("{}{}─┬ ", prefix,
                                         if last { "└" } else { "├" }),
                  subsequent_indent=format!("{}{} │ ", prefix,
                                            if last { " " } else { "│" }),
                  "{}", certification.target());
        wwriteln!(stream=output,
                  initial_indent=format!("{}{} └ ", prefix,
                                         if last { " " } else { "│" }),
                  subsequent_indent=format!("{}{}   ", prefix,
                                            if last { " " } else { "│" }),
                  "{}",
                  if last {
                      format!("{}", Safe(target_userid))
                  } else if let Some(userid) =
                  certification.target_cert().and_then(|c| c.primary_userid())
                  {
                      format!("({})", Safe(userid.userid()))
                  } else {
                      "".into()
                  });

        if last {
            let target = path.certs().last().expect("have one");
            for err in target.errors().iter().chain(target.lints()) {
                for (i, msg) in error_chain(err).into_iter().enumerate() {
                    wwriteln!(
                        stream=output,
                        indent=format!(
                            "{}│  {}", prefix, if i == 0 { "" } else { "  " }),
                        "{}", msg);
                }
            }
        }
    }

    wwriteln!(stream=output, "");
    Ok(())
}
