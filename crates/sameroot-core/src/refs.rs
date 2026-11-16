//! The reference index and the ledger commitment (design 0004 §4.1).
//!
//! The record trie (design 0003 §4) proves that a record is in a ledger, but not
//! that no void of its certificate, and no negation of it, is there too. So the
//! ledger commitment also covers a derived index of which records reference which
//! subjects:
//!
//! ```text
//! refKey(tag, s) = BLAKE3_derive("sameroot 1 ref subject", tag ‖ s)
//! bucket         = { idsRoot: ledger-trie root over the referencing records, count }
//! refLeaf        = BLAKE3_derive("sameroot 1 ref leaf", refKey ‖ idsRoot ‖ u64be(count))
//! refRoot        = the sparse trie (§4.3 shape) over refKeys with refLeaf slots
//! ledgerRoot     = BLAKE3_derive("sameroot 1 ledger commitment", recordRoot ‖ refRoot)
//! ```
//!
//! The index is a pure function of the record set: every referencing record is
//! indexed, effective or not. Equal record roots imply equal reference roots, so sync
//! compares record roots only and every node derives its own index.

use std::collections::{BTreeMap, BTreeSet};

use crate::cert::{Void, VoidTarget};
use crate::entry::Header;
use crate::hash::Digest;
use crate::ledger::{Kind, Trie, context, sparse_root};

/// What a reference names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefTag {
    /// A certificate id (cert voids).
    Cert = 0,
    /// A public key (key voids).
    Key = 1,
    /// A target entry id (negations).
    Target = 2,
}

/// The index key of a subject.
pub fn ref_key(tag: RefTag, subject: &[u8; 32]) -> Digest {
    let mut b = Vec::with_capacity(33);
    b.push(tag as u8);
    b.extend_from_slice(subject);
    Digest::derive(context::REF_SUBJECT, &b)
}

/// The subject an entry references: a negation, its target.
pub fn entry_ref(h: &Header) -> Option<Digest> {
    h.target.map(|t| ref_key(RefTag::Target, &t.0))
}

/// The subject a void references: its certificate or key.
pub fn void_ref(v: &Void) -> Digest {
    match &v.target {
        VoidTarget::Cert(c) => ref_key(RefTag::Cert, &c.0),
        VoidTarget::Key(k) => ref_key(RefTag::Key, &k.0),
    }
}

/// The slot hash of one bucket.
pub fn ref_leaf(key: &Digest, ids_root: &Digest, count: u64) -> Digest {
    let mut b = Vec::with_capacity(72);
    b.extend_from_slice(&key.0);
    b.extend_from_slice(&ids_root.0);
    b.extend_from_slice(&count.to_be_bytes());
    Digest::derive(context::REF_LEAF, &b)
}

/// The ledger commitment over a record root and a reference root.
pub fn ledger_commitment(record_root: &Digest, ref_root: &Digest) -> Digest {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&record_root.0);
    b[32..].copy_from_slice(&ref_root.0);
    Digest::derive(context::COMMITMENT, &b)
}

/// The reference index of one ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefIndex {
    buckets: BTreeMap<Digest, BTreeSet<(Kind, Digest)>>,
}

impl RefIndex {
    /// The empty index.
    pub fn new() -> RefIndex {
        RefIndex::default()
    }

    /// Records that record `(kind, id)` references `key`. Returns false if it was
    /// already indexed.
    pub fn insert(&mut self, key: Digest, kind: Kind, id: Digest) -> bool {
        self.buckets.entry(key).or_default().insert((kind, id))
    }

    /// The records referencing `key`.
    pub fn bucket(&self, key: &Digest) -> Option<&BTreeSet<(Kind, Digest)>> {
        self.buckets.get(key)
    }

    /// Number of subjects.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// True if nothing references anything.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// The reference root.
    pub fn root(&self) -> Digest {
        let leaves: Vec<(Digest, Digest)> = self
            .buckets
            .iter()
            .map(|(k, set)| {
                let ids = Trie::build(set.iter().copied()).root();
                (*k, ref_leaf(k, &ids, set.len() as u64))
            })
            .collect();
        sparse_root(&leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::leaf_hash;

    fn id(n: u64) -> Digest {
        Digest::derive("test", &n.to_be_bytes())
    }

    #[test]
    fn sparse_root_is_the_ledger_root() {
        for n in [0u64, 1, 2, 3, 17, 300] {
            let records: Vec<(Kind, Digest)> = (0..n)
                .map(|i| {
                    let k = if i % 3 == 0 { Kind::Void } else { Kind::Entry };
                    (k, id(i))
                })
                .collect();
            let mut leaves: Vec<(Digest, Digest)> = records
                .iter()
                .map(|(k, d)| (*d, leaf_hash(*k, d)))
                .collect();
            leaves.sort();
            assert_eq!(
                sparse_root(&leaves),
                Trie::build(records).root(),
                "{n} records"
            );
        }
    }

    #[test]
    fn index_root_is_a_function_of_the_set() {
        let refs: Vec<(Digest, Kind, Digest)> = (0..50u64)
            .map(|i| {
                let tag = [RefTag::Cert, RefTag::Key, RefTag::Target][(i % 3) as usize];
                (ref_key(tag, &id(i % 7).0), Kind::Void, id(100 + i))
            })
            .collect();
        let mut a = RefIndex::new();
        for (k, kind, d) in &refs {
            a.insert(*k, *kind, *d);
        }
        let mut b = RefIndex::new();
        for (k, kind, d) in refs.iter().rev() {
            b.insert(*k, *kind, *d);
        }
        assert_eq!(a.root(), b.root());
        assert!(
            !a.insert(refs[0].0, refs[0].1, refs[0].2),
            "duplicates are no-ops"
        );
        let before = a.root();
        a.insert(refs[0].0, Kind::Entry, id(999));
        assert_ne!(a.root(), before, "a new reference changes the root");
        // Tags separate subjects: the same 32 bytes as a cert and as a key differ.
        assert_ne!(
            ref_key(RefTag::Cert, &id(1).0),
            ref_key(RefTag::Key, &id(1).0)
        );
        // The empty index has the root of the empty ledger.
        assert_eq!(RefIndex::new().root(), Trie::new().root());
    }
}
