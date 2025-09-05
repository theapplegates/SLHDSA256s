//! Types used in the command-line parser.

use std::io::Read;
use std::io::stdin;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Reads from stdin, and prints a warning to stderr if no input is
/// read within a certain amount of time.
pub struct StdinWarning {
    do_warn: bool,
    /// The thing that is being waited for.  See `StdinWarning::emit`.
    thing: &'static str,
}

/// Print a warning if we don't get any input after this amount of
/// time.
const STDIN_TIMEOUT: Duration = std::time::Duration::new(2, 0);

impl StdinWarning {
    /// Emit a custom warning if no input is received.
    pub fn new(thing: &'static str) -> Self {
        Self {
            do_warn: true,
            thing,
        }
    }

    /// Emit a warning that a certificate is expected if no input is
    /// received.
    pub fn openpgp() -> Self {
        Self::new("OpenPGP data")
    }

    /// Emit a warning that certificates are expected if no input is
    /// received.
    pub fn certs() -> Self {
        Self::new("OpenPGP certificates")
    }

    pub fn emit(&self) {
        eprintln!("Waiting for {} on stdin...", self.thing);
    }
}

impl Read for StdinWarning {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if self.do_warn {
            if buf.len() == 0 {
                return Ok(0);
            }

            // We may warn the user.  We don't want to print the
            // warning if we read anything.  If we try to read two
            // bytes, we might read one byte, block, print the
            // warning, and then later read a second byte.  That's not
            // great.  Thus, we don't read more than a single byte.
            buf = &mut buf[..1];

            // Don't warn again.
            self.do_warn = false;

            thread::scope(|s| {
                let (sender, receiver) = mpsc::channel::<()>();

                s.spawn(move || {
                    if let Err(mpsc::RecvTimeoutError::Timeout)
                        = receiver.recv_timeout(STDIN_TIMEOUT)
                    {
                        self.emit();
                    }
                });

                let result = stdin().read(buf);
                // Force the thread to exit now.
                drop(sender);
                result
            })
        } else {
            stdin().read(buf)
        }
    }
}

