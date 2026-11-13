//! TCP sequence numbers: arithmetic modulo 2^32, ordered within half the
//! number space (RFC 9293 section 3.4).

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct Seq(pub(crate) u32);

impl Seq {
    pub(crate) fn add(self, count: usize) -> Self {
        Self(self.0.wrapping_add(count as u32))
    }

    pub(crate) fn sub(self, count: usize) -> Self {
        Self(self.0.wrapping_sub(count as u32))
    }

    /// The signed distance from `earlier` to `self`: positive when `self`
    /// comes after it.
    pub(crate) fn since(self, earlier: Self) -> i64 {
        i64::from(self.0.wrapping_sub(earlier.0) as i32)
    }

    /// The distance from `earlier` to `self`, which must not come before it.
    pub(crate) fn offset_from(self, earlier: Self) -> usize {
        debug_assert!(self.since(earlier) >= 0, "{self:?} before {earlier:?}");
        self.0.wrapping_sub(earlier.0) as usize
    }

    pub(crate) fn is_before(self, other: Self) -> bool {
        self.since(other) < 0
    }

    pub(crate) fn is_after(self, other: Self) -> bool {
        self.since(other) > 0
    }

    pub(crate) fn max(self, other: Self) -> Self {
        if self.is_before(other) {
            other
        } else {
            self
        }
    }
}

impl fmt::Debug for Seq {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Seq({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_wraps_around_the_number_space() {
        let near_end = Seq(u32::MAX - 10);
        let wrapped = near_end.add(20);
        assert_eq!(wrapped, Seq(9));
        assert!(near_end.is_before(wrapped));
        assert!(wrapped.is_after(near_end));
        assert_eq!(wrapped.since(near_end), 20);
        assert_eq!(near_end.since(wrapped), -20);
        assert_eq!(wrapped.offset_from(near_end), 20);
        assert_eq!(near_end.max(wrapped), wrapped);
        assert_eq!(wrapped.sub(20), near_end);
    }
}
