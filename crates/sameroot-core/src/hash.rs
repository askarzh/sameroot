//! BLAKE3 typed ids (`spec/01-encoding.md`).
//!
//! Every object type hashes with its own BLAKE3 derive-key context, so the id of
//! one type can never be presented as the id of another.

use std::fmt;

/// Derive-key contexts of format 1.
pub mod context {
    /// Signed entry headers.
    pub const ENTRY: &str = "sameroot 1 entry";
    /// Database genesis.
    pub const GENESIS: &str = "sameroot 1 genesis";
    /// Delegation certificates.
    pub const CERT: &str = "sameroot 1 cert";
    /// Certificate voids.
    pub const VOID: &str = "sameroot 1 void";
    /// Succession forwards (design 0004 §8.1).
    pub const FORWARD: &str = "sameroot 1 forward";
    /// The commitment to the next owner key in a genesis (design 0004 §8.1).
    pub const NEXT_OWNER: &str = "sameroot 1 next owner";
}

/// The number of leading zero bits of a digest: the proof of work of a record whose
/// id it is (design 0004 §6).
pub fn work_bits(d: &Digest) -> u32 {
    let mut n = 0;
    for b in d.0 {
        if b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// A 32-byte BLAKE3 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// The all-zero digest (used as `valueHash` of deletes).
    pub const ZERO: Digest = Digest([0; 32]);

    /// Hashes `bytes` under a derive-key `context`.
    pub fn derive(context: &str, bytes: &[u8]) -> Digest {
        Digest(blake3::derive_key(context, bytes))
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Parses lowercase or uppercase hex.
    pub fn from_hex(s: &str) -> Option<Digest> {
        let bytes = unhex(s)?;
        Some(Digest(bytes.try_into().ok()?))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", &self.to_hex()[..12])
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses hex; `None` on odd length or a non-hex character.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
