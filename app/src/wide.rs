/// Convert a &str to a null-terminated UTF-16 Vec for Win32 APIs that need dynamic strings.
pub fn wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
