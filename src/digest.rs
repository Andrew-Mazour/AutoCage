//! Small, allocation-bounded digest formatting helper.

use std::fmt::Write;

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String is infallible.
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
