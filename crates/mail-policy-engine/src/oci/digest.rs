//! Content digests.
//!
//! OCI addresses content by digest, so every digest in this crate is the
//! SHA-256 of the exact bytes it covers.

use sha2::{Digest, Sha256};

/// The hexadecimal SHA-256 of the given bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The OCI digest of the given bytes, for example `sha256:ab12...`.
pub fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// Whether a recorded digest matches the given bytes.
pub fn digest_matches(recorded: &str, bytes: &[u8]) -> bool {
    recorded == digest_of(bytes)
}
