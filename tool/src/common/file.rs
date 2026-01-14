//! Common file handling support.

use std::{
    fs, io::{self, stdout, Write}
};

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use anyhow::{Context, Result};

use sequoia::openpgp::{
    self as openpgp,
    armor,
    serialize::stream::{Armorer, Message},
};

use sequoia::types::PartFileWriter;

use crate::{
    cli::types::FileOrStdout,
    sq::Sq,
};

impl FileOrStdout {
    /// Returns whether the stream is stdout.
    pub fn is_stdout(&self) -> bool {
        self.path().is_none()
    }

    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use.
    ///
    /// This is suitable for any kind of OpenPGP data, decrypted or
    /// authenticated payloads.
    pub fn create_safe(
        &self,
        sq: &Sq,
    ) -> Result<Box<dyn Write + Sync + Send>> {
        self.create(sq, false)
    }

    /// Like [`FileOrStdout::create_safe`], but allows overwriting the
    /// target.
    ///
    /// The overwrite check respects both `sq.overwrite` and
    /// `overwrite`!
    pub fn create_safe_overwrite(
        &self,
        sq: &Sq,
        overwrite: bool
    ) -> Result<Box<dyn Write + Sync + Send>> {
        self.create(sq, overwrite)
    }

    /// Opens the file (or stdout) for writing data that is NOT safe
    /// for non-interactive use.
    pub fn create_unsafe(
        &self,
        sq: &Sq,
    ) -> Result<Box<dyn Write + Sync + Send>> {
        self.create(sq, false)
    }

    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use because it is an OpenPGP data stream.
    ///
    /// Emitting armored data with the label `armor::Kind::SecretKey`
    /// implicitly configures this output to emit secret keys.
    pub fn create_pgp_safe<'a>(
        &self,
        sq: &Sq,
        binary: bool,
        kind: armor::Kind,
    ) -> Result<Message<'a>> {
        // Allow secrets to be emitted if the armor label says secret
        // key.
        let mut o = self.clone();
        if kind == armor::Kind::SecretKey {
            o = o.for_secrets();
        }
        let sink = o.create_safe(sq)?;

        let mut message = Message::new(sink);
        if ! binary {
            message = Armorer::new(message).kind(kind).build()?;
        }
        Ok(message)
    }

    /// Helper function, do not use directly. Instead, use create_or_stdout_safe
    /// or create_or_stdout_unsafe.
    fn create(&self, sq: &Sq, overwrite: bool)
        -> Result<Box<dyn Write + Sync + Send>>
    {
        let sink = self._create_sink(sq, overwrite)?;
        if self.is_for_secrets() || ! cfg!(debug_assertions) {
            // We either expect secrets, or we are in release mode.
            Ok(sink)
        } else {
            // In debug mode, if we don't expect secrets, scan the
            // output for inadvertently leaked secret keys.
            Ok(Box::new(SecretLeakDetector::new(sink)))
        }
    }
    fn _create_sink(&self, sq: &Sq, overwrite: bool)
        -> Result<Box<dyn Write + Sync + Send>>
    {
        if let Some(path) = self.path() {
            if !path.exists() || sq.overwrite || overwrite {
                Ok(Box::new(
                    PartFileWriter::create(path)
                        .context("Failed to create output file")?,
                ))
            } else {
                // If path points to a special file (char device,
                // block device, fifo, socket) use it, even if
                // `overwrite` is `false`.
                #[cfg(unix)]
                if let Ok(p) = fs::metadata(path) {
                    if p.file_type().is_char_device()
                        || p.file_type().is_block_device()
                        || p.file_type().is_fifo()
                        || p.file_type().is_socket()
                    {
                        return Ok(Box::new(
                            PartFileWriter::create(path)
                                .with_context(|| {
                                    format!("Failed to open special file {}",
                                            path.display())
                                })?,
                        ))
                    }
                }
                Err(anyhow::anyhow!(
                    "File {} exists, use \"sq --overwrite ...\" to overwrite",
                    path.display(),
                ))
            }
        } else {
            Ok(Box::new(stdout()))
        }
    }
}

/// A writer that buffers all data, and scans for secret keys on drop.
///
/// This is used to assert that we only write secret keys in places
/// where we expect that.  As this buffers all data, and has a
/// performance impact, we only do this in debug builds.
struct SecretLeakDetector<W: io::Write + Send + Sync> {
    sink: W,
    data: Vec<u8>,
}

impl<W: io::Write + Send + Sync> io::Write for SecretLeakDetector<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.sink.write(buf)?;
        self.data.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

impl<W: io::Write + Send + Sync> Drop for SecretLeakDetector<W> {
    fn drop(&mut self) {
        let _ = self.detect_leaks();
    }
}

impl<W: io::Write + Send + Sync> SecretLeakDetector<W> {
    /// Creates a shim around `sink` that scans for inadvertently
    /// leaked secret keys.
    fn new(sink: W) -> Self {
        SecretLeakDetector {
            sink,
            data: Vec::with_capacity(4096),
        }
    }

    /// Scans the buffered data for secret keys, panic'ing if one is
    /// found.
    fn detect_leaks(&self) -> Result<()> {
        use openpgp::Packet;
        use openpgp::parse::{Parse, PacketParserResult, PacketParser};

        let mut ppr = PacketParser::from_bytes(&self.data)?;
        while let PacketParserResult::Some(pp) = ppr {
            match &pp.packet {
                Packet::SecretKey(_) | Packet::SecretSubkey(_) =>
                    panic!("Leaked secret key: {:?}", pp.packet),
                _ => (),
            }
            let (_, next_ppr) = pp.recurse()?;
            ppr = next_ppr;
        }

        Ok(())
    }
}
