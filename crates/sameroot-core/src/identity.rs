//! Identities and signatures (`spec/02-identities.md`).
//!
//! An identity is an Ed25519 public key. Signatures are always over a 32-byte
//! typed id (see [`crate::hash`]), never over raw payloads. Verification is pinned
//! to the strict cofactorless rules: canonical `S`, canonical encodings of the
//! public key and of `R`, small-order public keys and `R` rejected, no batch
//! verification. Libraries disagree on these edge cases; pinning them is what keeps
//! replicas of different implementations from splitting.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::hash::{Digest, hex, unhex};

/// An Ed25519 public key: an identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub [u8; 32]);

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

/// A secret signing key.
#[derive(Clone)]
pub struct SecretKey(SigningKey);

/// Why a signature does not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The public key bytes are not a canonical encoding of a valid point.
    #[error("public key is not a canonical, valid point")]
    BadPublicKey,
    /// The public key is a small-order point.
    #[error("public key has small order")]
    WeakPublicKey,
    /// The signature does not verify under the strict rules.
    #[error("signature does not verify")]
    BadSignature,
}

impl SecretKey {
    /// Generates a new key from the operating system's random source.
    pub fn generate() -> SecretKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("operating system random source");
        SecretKey(SigningKey::from_bytes(&seed))
    }

    /// A key from its 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> SecretKey {
        SecretKey(SigningKey::from_bytes(&seed))
    }

    /// The 32-byte seed (keep it secret).
    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The public key.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    /// Signs a typed id.
    pub fn sign(&self, id: &Digest) -> Signature {
        Signature(self.0.sign(&id.0).to_bytes())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({:?})", self.public())
    }
}

impl PublicKey {
    /// Verifies `signature` over the typed id `id` under the strict rules.
    pub fn verify(&self, id: &Digest, signature: &Signature) -> Result<(), VerifyError> {
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| VerifyError::BadPublicKey)?;
        // Reject non-canonical encodings of the public key: the decoded point must
        // compress back to exactly these bytes.
        if key.to_edwards().compress().to_bytes() != self.0 {
            return Err(VerifyError::BadPublicKey);
        }
        if key.is_weak() {
            return Err(VerifyError::WeakPublicKey);
        }
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        // verify_strict: canonical S, small-order R rejected; a non-canonical R
        // cannot equal the recomputed (canonical) R.
        key.verify_strict(&id.0, &sig)
            .map_err(|_| VerifyError::BadSignature)
    }

    /// Lowercase hex (the display form until the multicodec string is specified).
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Parses 64 hex characters.
    pub fn from_hex(s: &str) -> Option<PublicKey> {
        Some(PublicKey(unhex(s)?.try_into().ok()?))
    }

    /// The first 8 bytes in hex, for logs and short display.
    pub fn short(&self) -> String {
        hex(&self.0[..4])
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.short())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}…)", hex(&self.0[..6]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::context;

    #[test]
    fn sign_and_verify() {
        let sk = SecretKey::from_seed([7; 32]);
        let id = Digest::derive(context::ENTRY, b"hello");
        let sig = sk.sign(&id);
        assert_eq!(sk.public().verify(&id, &sig), Ok(()));
        let other = Digest::derive(context::GENESIS, b"hello");
        assert_eq!(
            sk.public().verify(&other, &sig),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn rejects_small_order_and_non_canonical_keys() {
        let id = Digest::derive(context::ENTRY, b"x");
        let sig = Signature([0; 64]);
        // The identity point (y = 1) has small order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            PublicKey(identity).verify(&id, &sig),
            Err(VerifyError::WeakPublicKey)
        );
        // y = p + 1 is a non-canonical encoding of the identity point.
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xee;
        non_canonical[31] = 0x7f;
        assert!(matches!(
            PublicKey(non_canonical).verify(&id, &sig),
            Err(VerifyError::BadPublicKey) | Err(VerifyError::WeakPublicKey)
        ));
    }

    #[test]
    fn rejects_non_canonical_s() {
        let sk = SecretKey::from_seed([9; 32]);
        let id = Digest::derive(context::ENTRY, b"y");
        let mut sig = sk.sign(&id);
        // Add the group order L to S (little-endian): same signature mathematically,
        // non-canonical encoding. Strict verification must reject it.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut carry = 0u16;
        for (byte, l) in sig.0[32..].iter_mut().zip(L) {
            let s = u16::from(*byte) + u16::from(l) + carry;
            *byte = s as u8;
            carry = s >> 8;
        }
        assert_eq!(
            sk.public().verify(&id, &sig),
            Err(VerifyError::BadSignature)
        );
    }
}
