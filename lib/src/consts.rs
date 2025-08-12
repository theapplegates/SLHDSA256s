//! Some useful constants.

/// The seconds in a day
pub const SECONDS_IN_DAY : u64 = 24 * 60 * 60;
/// The seconds in a year
pub const SECONDS_IN_YEAR : u64 =
    // Average number of days in a year.
    (365.2422222 * SECONDS_IN_DAY as f64) as u64;
