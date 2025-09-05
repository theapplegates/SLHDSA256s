use sequoia_wot as wot;

/// The degree to which a binding needs to be authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustThreshold {
    /// The binding must be fully authenticated.
    Full = wot::FULLY_TRUSTED as isize,
    /// The binding must be minimally authenticated (>= 1 out of 120).
    Minimal = 1,
    /// The binding doesn't need to be authenticated.
    YOLO = 0,
}

impl From<TrustThreshold> for usize {
    fn from(a: TrustThreshold) -> usize {
        a as isize as usize
    }
}

impl From<&TrustThreshold> for usize {
    fn from(a: &TrustThreshold) -> usize {
        *a as isize as usize
    }
}

impl std::fmt::Display for TrustThreshold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", usize::from(self))
    }
}
