use sequoia_openpgp as openpgp;

/// Converts sequoia::openpgp types for rendering.
pub trait Convert<T> {
    /// Performs the conversion.
    fn convert(self) -> T;
}

impl Convert<humantime::FormattedDuration> for std::time::Duration {
    fn convert(self) -> humantime::FormattedDuration {
        humantime::format_duration(self)
    }
}

impl Convert<humantime::FormattedDuration> for openpgp::types::Duration {
    fn convert(self) -> humantime::FormattedDuration {
        humantime::format_duration(self.into())
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for std::time::SystemTime {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        chrono::DateTime::<chrono::offset::Utc>::from(self)
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for openpgp::types::Timestamp {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        std::time::SystemTime::from(self).convert()
    }
}
