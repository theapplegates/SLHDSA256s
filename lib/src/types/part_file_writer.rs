//! Common file handling support.

use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use tempfile::NamedTempFile;

use sequoia_openpgp as openpgp;
use openpgp::crypto::mem::Protected;

use crate::Result;

/// A writer that writes to a temporary file first, then persists the
/// file under the desired name.
///
/// This has two benefits.  First, consumers only see the file once we
/// are done writing to it, i.e. they don't see a partial file.
///
/// Second, we guarantee not to overwrite the file until the operation
/// is finished.  Therefore, it is safe to use the same file as input
/// and output.
pub struct PartFileWriter {
    path: PathBuf,
    sink: Option<NamedTempFile>,
    // If true, copy the temporary file instead of renaming it.
    copy: bool,
}

impl io::Write for PartFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sink()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink()?.flush()
    }
}

impl Drop for PartFileWriter {
    fn drop(&mut self) {
        if let Err(e) = self.persist() {
            weprintln!(initial_indent = "Error: ", "{}", e);
            std::process::exit(1);
        }
    }
}

impl PartFileWriter {
    /// Opens a file for writing.
    ///
    /// The file will be created under a different name in the target
    /// directory, and will only be renamed to `path` once
    /// [`PartFileWriter::persist`] is called or the object is
    /// dropped.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<PartFileWriter> {
        let path = path.as_ref().to_path_buf();
        let parent = path.parent()
            .ok_or(anyhow::anyhow!("cannot write to the root"))?;
        let file_name = path.file_name()
            .ok_or(anyhow::anyhow!("cannot write to .."))?;

        let mut sink = tempfile::Builder::new();

        // By default, temporary files are 0x600 on Unix.  But, we
        // rather want created files to respect umask.
        platform! {
            unix => {
                use std::os::unix::fs::PermissionsExt;
                let all_read_write =
                    std::fs::Permissions::from_mode(0o666);

                // The permissions will be masked by the user's umask.
                sink.permissions(all_read_write);
            },
            windows => {
                // We cannot do the same on Windows.
            },
        }

        // Try to create tempfile in parent, if that fails use the
        // default OS location (mostly /tmp).
        let mut copy = false;
        let sink = match sink
            .prefix(file_name)
            .suffix(".part")
            .tempfile_in(parent) {
                Ok(s) => s,
                Err(_) => {
                    // It seems that we have limited possibilities in
                    // `parent`, choose the default location for temp
                    // files and use copy for persisting as it is less
                    // invasive.  This also catches the case where we
                    // crossed filesystem boundaries.
                    copy = true;
                    sink
                        .prefix(file_name)
                        .suffix(".part")
                        .tempfile()?
                },
            };

        Ok(PartFileWriter {
            path,
            sink: Some(sink),
            copy,
        })
    }

    /// Returns a mutable reference to the file, or an error.
    fn sink(&mut self) -> io::Result<&mut NamedTempFile> {
        self.sink.as_mut().ok_or(io::Error::new(
            io::ErrorKind::Other,
            anyhow::anyhow!("file already persisted")))
    }

    const DEFAULT_BUF_SIZE: usize = 64 * 1024;

    /// Persists the file under its final name.
    pub fn persist(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.sink.take() {
            if self.copy {
                file.rewind()?;

                let mut open_options = OpenOptions::new();
                open_options.create(true)
                    .write(true)
                    .truncate(true);

                platform! {
                    unix => {
                        use std::os::unix::fs::OpenOptionsExt;

                        open_options.custom_flags(libc::O_NOFOLLOW);
                    },
                    windows => {
                        use std::fs::OpenOptions;
                        use std::os::windows::prelude::*;

                        // Do not allow others to read or modify this
                        // file while we have it open for writing.
                        open_options.share_mode(0);
                    },
                }

                let mut target = open_options.open(&self.path)?;

                // We use read()/write() instead of std::io::copy so
                // that we can zero the internal buffer.
                let mut buffer: Protected = [0; Self::DEFAULT_BUF_SIZE].into();

                while let Ok(len) = file.read(buffer.as_mut()) {
                    if len == 0 {
                        break;
                    }
                    target.write_all(&buffer[0..len])?;
                }
                target.flush()?;
            } else {
                file.persist(&self.path)?;
            }
        }
        Ok(())
    }
}
