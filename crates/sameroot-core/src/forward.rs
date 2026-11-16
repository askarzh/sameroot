//! Succession forwards (design 0004 §8.1).
//!
//! A `Forward` is a ledger record of the parent database, signed by its owner, that
//! names the database succeeding it, the successor's owner, and the cut. It is what
//! makes a successor legitimate: anyone can write a genesis that claims a parent.

use crate::FORMAT_VERSION;
use crate::cbor::{self, Map, Value};
use crate::fields::{Fields, FormatError, digest_value, key_value};
use crate::hash::{Digest, context};
use crate::identity::{PublicKey, SecretKey, Signature};

/// A forward to a successor database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    /// The parent database (the one this record is in).
    pub db: Digest,
    /// The successor's database id (its genesis id).
    pub successor: Digest,
    /// The successor's owner key.
    pub owner: PublicKey,
    /// The parent's ledger root at the cut.
    pub cut_root: Digest,
}

impl Forward {
    /// The canonical CBOR value.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("v", Value::Uint(FORMAT_VERSION))
            .insert("db", digest_value(&self.db))
            .insert("successor", digest_value(&self.successor))
            .insert("owner", key_value(&self.owner))
            .insert("cutRoot", digest_value(&self.cut_root));
        Value::Map(m)
    }

    /// The forward id: BLAKE3 ("sameroot 1 forward") of the canonical forward.
    pub fn id(&self) -> Digest {
        Digest::derive(context::FORWARD, &cbor::encode(&self.to_value()))
    }

    /// Signs the forward (with the parent owner's key).
    pub fn sign(self, key: &SecretKey) -> SignedForward {
        let sig = key.sign(&self.id());
        SignedForward { forward: self, sig }
    }
}

/// A forward with the parent owner's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedForward {
    /// The forward.
    pub forward: Forward,
    /// Signature by the parent's owner over `forward.id()`.
    pub sig: Signature,
}

impl SignedForward {
    /// The forward id.
    pub fn id(&self) -> Digest {
        self.forward.id()
    }

    /// Canonical bytes `{ "h": forward, "s": signature }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("h", self.forward.to_value())
            .insert("s", Value::Bytes(self.sig.0.to_vec()));
        cbor::encode(&Value::Map(m))
    }

    /// Strict decode (the signature is checked by [`crate::verify::verify_forward`]).
    pub fn decode(bytes: &[u8]) -> Result<SignedForward, FormatError> {
        let value = cbor::decode(bytes)?;
        let f = Fields::new("signed forward", &value, &["h", "s"])?;
        let h = Fields::new(
            "forward",
            f.value("h")?,
            &["v", "db", "successor", "owner", "cutRoot"],
        )?;
        h.version(FORMAT_VERSION)?;
        Ok(SignedForward {
            forward: Forward {
                db: h.digest("db")?,
                successor: h.digest("successor")?,
                owner: h.key("owner")?,
                cut_root: h.digest("cutRoot")?,
            },
            sig: f.signature("s")?,
        })
    }
}

/// The commitment to a next owner key that a genesis carries in `nextOwner`.
pub fn owner_commitment(key: &PublicKey) -> Digest {
    Digest::derive(context::NEXT_OWNER, &key.0)
}
