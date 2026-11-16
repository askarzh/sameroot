//! Pure, sans-I/O core of Sameroot.
//!
//! Implements format 1 (`docs/design/0001-architecture.md` §5–§10): the frozen
//! CBOR profile, BLAKE3 typed ids, Ed25519 identities with strict verification,
//! entry headers with detached values, genesis, delegation certificates, the access
//! presets, and last-writer-wins ordering. No networking, no storage, no async:
//! every function here is deterministic, so that every replica, and every
//! implementation, reaches the same verdict for the same input.

pub mod cbor;
pub mod cert;
pub mod entry;
mod fields;
pub mod forward;
pub mod genesis;
pub mod hash;
pub mod identity;
pub mod ledger;
pub mod logic;
pub mod refs;
pub mod resolve;
pub mod succession;
pub mod verify;

pub use cert::{Area, Cert, ChainError, Keep, SignedCert, SignedVoid, Void, VoidTarget};
pub use entry::{Header, Op, Path, SignedEntry, Subspace, value_hash, wins};
pub use fields::FormatError;
pub use forward::{Forward, SignedForward, owner_commitment};
pub use genesis::{
    Contract, Genesis, Limits, NegateRight, Predecessor, Resolution, Rule, SignedGenesis,
};
pub use hash::{Digest, work_bits};
pub use identity::{PublicKey, SecretKey, Signature, VerifyError};
pub use verify::{
    Accepted, Reject, VoidAccepted, verify_entry, verify_forward, verify_value, verify_void,
};

/// The format version this crate implements (`v` in every signed object).
pub const FORMAT_VERSION: u64 = 1;

/// Milliseconds since the Unix epoch (for callers; the core never reads a clock).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
