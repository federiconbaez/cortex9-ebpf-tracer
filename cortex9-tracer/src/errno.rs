//! errno names for negative syscall return values.

#[path = "errno_table.rs"]
mod table;

/// Symbolic name for errno `e` (positive), e.g. `2 -> ENOENT`.
pub fn name(e: u32) -> Option<&'static str> {
    table::ERRNO.get(e as usize).copied().flatten()
}

/// If `ret` looks like a failed syscall (`-4095..=-1`), the errno value.
///
/// Values below -4095 are not errors by kernel convention (for example
/// large pointers returned by `mmap` on some ABIs).
pub fn from_ret(ret: i64) -> Option<u32> {
    if (-4095..0).contains(&ret) {
        Some((-ret) as u32)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(name(1), Some("EPERM"));
        assert_eq!(name(2), Some("ENOENT"));
        assert_eq!(name(11), Some("EAGAIN"));
        assert_eq!(name(110), Some("ETIMEDOUT"));
        assert_eq!(name(0), None);
        assert_eq!(name(9999), None);
    }

    #[test]
    fn ret_classification() {
        assert_eq!(from_ret(-2), Some(2));
        assert_eq!(from_ret(-4095), Some(4095));
        assert_eq!(from_ret(-4096), None);
        assert_eq!(from_ret(0), None);
        assert_eq!(from_ret(42), None);
    }
}
