//! Lightweight pluralization support.

use std::fmt;

use super::wrapping::NBSP;

/// Pluralizes countable things when formatted.
pub struct Pluralized<'t, 's> {
    /// The amount of things we have.
    count: usize,

    /// Of these things.
    thing: &'t str,

    /// Use this plural suffix.
    plural_suffix: &'s str,
}

impl fmt::Display for Pluralized<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}{}",
               self.count,
               NBSP,
               self.thing,
               if self.count == 1 { "" } else { self.plural_suffix })
    }
}

impl<'t, 's> Pluralized<'t, 's> {
    /// Changes the plural suffix.
    pub fn plural<'n>(self, suffix: &'n str) -> Pluralized<'t, 'n> {
        Pluralized {
            count: self.count,
            thing: self.thing,
            plural_suffix: suffix,
        }
    }
}

/// Provides convenient pluralization.
///
/// # Examples
///
/// ```
/// use sequoia::transitional::output::pluralize::Pluralize;
/// use sequoia::transitional::output::wrapping::NBSP;
/// assert_eq!(&3.of("apple").to_string(), &format!("3{}apples", NBSP));
/// assert_eq!(&2.of("bus").plural("es").to_string(), &format!("2{}buses", NBSP))
/// ```
pub trait Pluralize<'t> {
    fn of(self, thing: &'t str) -> Pluralized<'t, 'static>;
}

impl<'t> Pluralize<'t> for usize {
    fn of(self, thing: &'t str) -> Pluralized<'t, 'static> {
        Pluralized {
            count: self,
            thing: thing,
            plural_suffix: "s",
        }
    }
}
