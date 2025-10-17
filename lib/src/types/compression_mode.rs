#[derive(Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum CompressionMode {
    None,
    Pad,
    Zip,
    Zlib,
    Bzip2
}
