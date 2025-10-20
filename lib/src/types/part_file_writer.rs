/// Common file handling support.

use std::io;
use std::path::Path;
use std::path::PathBuf;

use tempfile::NamedTempFile;

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

        let sink = sink
            .prefix(file_name)
            .suffix(".part")
            .tempfile_in(parent)?;

        Ok(PartFileWriter {
            path,
            sink: Some(sink),
        })
    }

    /// Returns a mutable reference to the file, or an error.
    fn sink(&mut self) -> io::Result<&mut NamedTempFile> {
        self.sink.as_mut().ok_or(io::Error::new(
            io::ErrorKind::Other,
            anyhow::anyhow!("file already persisted")))
    }

    /// Persists the file under its final name.
    pub fn persist(&mut self) -> Result<()> {
        if let Some(file) = self.sink.take() {
            file.persist(&self.path)?;
        }
        Ok(())
    }
}
