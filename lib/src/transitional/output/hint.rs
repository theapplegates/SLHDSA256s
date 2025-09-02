//! Formats hints for users.

use std::collections::BTreeMap;
use std::fmt;
use std::io::IsTerminal;
use std::io::Write;

/// Wraps the given command to width, adding continuation backslashes.
///
/// The first line is prefixed with `indent` and wrapped `to_width`,
/// any continuations are prefixed with `continuation_indent` and
/// wrapped to `continuation_width`.
pub fn wrap_command<S: AsRef<str>>(command: &[S],
                                   hide: &[S],
                                   indent: &str,
                                   to_width: usize,
                                   continuation_indent: &str,
                                   continuation_width: usize)
    -> String
{
    let prompt = platform! {
        unix => { "$" },
        windows => { ">" },
    };

    let mut hide
        = BTreeMap::from_iter(hide.iter().map(|s| (s.as_ref(), false)));

    let result = command
        .iter()
        .filter(|&item| {
            // Remove all of the items in command which are also in
            // hide.
            if let Some(used) = hide.get_mut(item.as_ref()) {
                *used = true;
                // Don't show it.
                false
            } else {
                // Show it.
                true
            }
        })
        .fold(vec![format!("{}{}", indent, prompt)], |mut s, arg| {
            let first = s.len() == 1;

            let arg = arg.as_ref();
            if arg == "|" {
                let last = s.last_mut().expect("have one");
                *last = format!("{} \\", last);
                s.push(format!("  {}", arg));
                return s;
            }

            // Quote the argument, if necessary.
            let quote = |arg: &str| -> String {
                if arg.contains(&[
                    '\"',
                ]) {
                    format!("'{}'", arg)
                } else if arg.chars().any(char::is_whitespace)
                    || arg.contains(&[
                        '`', '#', '$', '&', '*', '(', ')',
                        '\\', '|', '[', ']', '{', '}',
                        ';', '\'', '<', '>', '?', '!',
                    ])
                {
                    format!("\"{}\"", arg)
                } else {
                    arg.to_string()
                }
            };

            // If we have --foo=bar, then only but bar in quotes.
            let mut quoted = None;
            if arg.starts_with("--") {
                if let Some(i) = arg.find('=') {
                    if arg[0..i].chars().all(|c| {
                        c.is_alphanumeric() || c == '-'
                    })
                    {
                        quoted = Some(format!("{}={}",
                                              &arg[..i],
                                              quote(&arg[i + 1..])));
                    }
                }
            }

            let arg = if let Some(quoted) = quoted {
                quoted
            } else {
                quote(arg)
            };

            let last = s.last_mut().expect("have one");

            let last_chars = last.chars().count();
            let arg_chars = arg.chars().count();

            let max_width = if first { to_width } else { continuation_width };
            if last_chars + 1 + arg_chars <= max_width {
                *last = format!("{} {}", last, arg);
            } else {
                *last = format!("{} \\", last);
                s.push(format!("{}{}", continuation_indent, arg));
            }

            s
        })
        .join("\n");

    #[cfg(debug_assertions)]
    for (arg, used) in hide.into_iter() {
        if ! used {
            panic!("Example `{}` includes an argument to hide (`{}`), but the \
                    argument wasn't used by the example!",
                   command.iter()
                       .map(|arg| arg.as_ref().to_string())
                       .collect::<Vec<String>>()
                       .join(" "),
                   arg);
        }
    }

    result
}

/// Formats a hint for the user.
pub struct Hint {
    /// Whether to suppress printing the hint.
    quiet: bool,

    /// Whether this is the first hint in this hint block.
    first: bool,
}

impl Hint {
    /// Constructs a new hint, optionally suppressing it.
    pub fn new(quiet: bool) -> Self {
        Hint {
            quiet,
            first: true,
        }
    }

    /// Displays a message to the user.
    ///
    /// It will be prefixed with "Hint: ", and should either end in a
    /// full stop or colon, depending on whether or not a command hint
    /// follows.
    pub fn hint(mut self, msg: fmt::Arguments) -> Self {
        if ! self.quiet {
            weprintln!();
            weprintln!(
                initial_indent=if self.first { "Hint: " } else { "      " },
                subsequent_indent="      ",
                "{}", msg);
            self.first = false;
        }
        self
    }

    /// Suggests an `sq` command to the user.
    pub fn sq(self) -> Command {
        Command::new(self, "sq")
    }

    /// Suggests a free-form command to the user.
    ///
    /// Note: if you want to suggest an `sq` invocation, use
    /// [`Hint::sq`] instead.
    pub fn command(self, argv0: &str) -> Command {
        Command::new(self, argv0)
    }
}

/// A structured command hint.
pub struct Command {
    hint: Hint,
    args: Vec<(String, Option<String>)>,
}

impl Command {
    fn new(hint: Hint, argv0: &str) -> Self {
        Command {
            hint,
            args: vec![(argv0.into(), None)],
        }
    }

    /// Adds `arg` to the command.
    pub fn arg<S: ToString>(mut self, arg: S) -> Self {
        self.args.push((arg.to_string(), None));
        self
    }

    /// Adds `arg` to the command, but show the user the replacement.
    pub fn arg_hidden<S: ToString, R: ToString>(
        mut self, arg: S, replacement: R)
        -> Self
    {
        self.args.push((arg.to_string(), Some(replacement.to_string())));
        self
    }

    /// Adds an argument `arg` with value to the command.
    pub fn arg_value<S: ToString, V: ToString>(mut self, arg: S, value: V)
                                               -> Self
    {
        self.args.push(
            (format!("{}={}", arg.to_string(), value.to_string()),
             None));
        self
    }

    /// Adds an argument `arg` with value to the command, but show the
    /// user the replacement value.
    pub fn arg_value_hidden<S: ToString, V: ToString, R: ToString>(
        mut self, arg: S, value: V, replacement_value: R)
        -> Self
    {
        self.args.push(
            (format!("{}={}", arg.to_string(), value.to_string()),
             Some(format!("{}={}",
                          arg.to_string(),
                          replacement_value.to_string()))));
        self
    }

    /// Emits the command hint.
    pub fn done(self) -> Hint {
        if ! self.hint.quiet {
            // If we're connected to a terminal, flush stdout to
            // reduce the chance of incorrectly interleaving output
            // and hints.
            let mut stdout = std::io::stdout();
            if stdout.is_terminal() {
                // Best effort.
                let _ = stdout.flush();
            }

            let width = crate::transitional::output::wrapping::stderr_terminal_width();

            let args = self.args.iter()
                .map(|(arg, replacement)| {
                    if let Some(replacement) = replacement {
                        replacement
                    } else {
                        arg
                    }
                })
                .collect::<Vec<_>>();

            eprintln!();
            eprintln!("{}", wrap_command(
                &args, &[], "  ", width, "    ", width));
        }

        self.hint
    }
}
