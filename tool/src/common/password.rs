//! Common password-related functionality such as prompting.

use sequoia::prompt;

use crate::Sq;

/// Prompt to repeat a password.
const REPEAT_PROMPT: &str = "Repeat the password";

pub struct Prompt<'a> {
    sq: &'a Sq,
    // Adds (password n of t) to the message.
    password: usize,
    password_count: usize,
    // Whether the user can skip this by entering the empty strip.  If
    // so, `prompt::Error::Cancelled` is returned instead of
    // `Response::NoPassword`.
    cancel: bool,
}

impl<'a> Prompt<'a> {
    /// Returns a new prompt.
    ///
    /// `cancel` means that if the user just hits enter, then we
    /// immediately return `prompt::Error::Cancel`.  Note: this is
    /// separate from allowing an empty password!
    pub fn new(sq: &'a Sq, cancel: bool) -> Self {
        Prompt {
            sq,
            password: 0,
            password_count: 0,
            cancel,
        }
    }

    /// Adds "(password n of t)".
    ///
    /// Cancel is disabled.
    pub fn npasswords(sq: &'a Sq, password: usize, count: usize) -> Self {
        Prompt {
            sq,
            password,
            password_count: count,
            cancel: false,
        }
    }
}

impl<'a> prompt::Prompt for Prompt<'a> {
    fn prompt(&self, context: &mut prompt::Context)
        -> std::result::Result<prompt::Response, prompt::Error>
    {
        if self.sq.batch {
            return Err(prompt::Error::Disabled(Some(
                "Cannot prompt for password in batch mode".into())));
        }

        let mut prompt = context.prompt();

        if self.cancel {
            prompt.push_str(" (black to skip)");
        } else if context.reason().optional() {
            prompt.push_str(" (press enter to not use a password)");
        }

        // Add (password n of t), if appropriate.
        if self.password_count > 0 {
            assert_eq!(context.reason(), prompt::Reason::EncryptMessage);
            assert!(self.password > 0);
            assert!(self.password <= self.password_count);

            if self.password_count > 1 {
                prompt.push_str(&format!(
                    " (password {} of {})",
                    self.password, self.password_count));
            }
        } else {
            assert_eq!(self.password, 0);
            assert_eq!(self.password_count, 0);
        }

        let width = prompt.len().max(REPEAT_PROMPT.len());
        let p0 = format!("{:>1$}: ", prompt, width);
        let p1 = format!("{:>1$}: ", REPEAT_PROMPT, width);

        loop {
            let password = rpassword::prompt_password(&p0)?;

            if password.is_empty() && self.cancel {
                weprintln!("Skipping.");
                return Err(prompt::Error::Cancelled(None));
            }

            if context.reason().confirm() {
                let password_repeat = rpassword::prompt_password(&p1)?;

                if password != password_repeat {
                    weprintln!("The passwords do not match.  Try again.");
                    weprintln!();
                    continue;
                }
            }

            return if password.is_empty() {
                Ok(prompt::Response::NoPassword)
            } else {
                Ok(prompt::Response::Password(password.into()))
            };
        }
    }
}
