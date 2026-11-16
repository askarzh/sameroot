//! Property tests: the decoders take any bytes without panicking and accept only
//! canonical forms; the ledger trie ignores insertion order and its proofs hold.
//!
//! The decoders are what a node runs on bytes from untrusted peers, so this is the
//! fuzzing these crates get in CI (`cargo test`); raise `PROPTEST_CASES` to run longer.

use proptest::collection::vec;
use proptest::prelude::*;
use sameroot_core::cbor::{self, Map, Value};
use sameroot_core::ledger::{Kind, Node, Trie};
use sameroot_core::*;

/// Any CBOR value of the data model, a few levels deep.
fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::Uint),
        any::<u64>().prop_map(Value::Nint),
        vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        "[a-z0-9 é]{0,12}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 64, 6, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..6).prop_map(Value::Array),
            // Distinct keys: a map with a repeated key isn't a value of the model.
            proptest::collection::btree_map("[a-z]{1,6}", inner, 0..6).prop_map(|kv| {
                let mut m = Map::new();
                for (k, v) in kv {
                    m.insert(&k, v);
                }
                Value::Map(m)
            }),
        ]
    })
}

/// A valid signed entry, for mutation.
fn signed_entry() -> SignedEntry {
    let owner = SecretKey::from_seed([3; 32]);
    let g = Genesis::new("p", owner.public(), logic::presets::own_subspace(), 1_000).sign(&owner);
    Header {
        db: g.id(),
        subspace: Subspace::Owner(owner.public()),
        path: Path::parse("notes/a").unwrap(),
        op: Op::Put,
        ts: 2_000,
        exp: None,
        value_size: 5,
        value_hash: value_hash(b"hello"),
        target: None,
        signer: owner.public(),
        cert: None,
        work: 0,
    }
    .sign(&owner)
}

/// Every record decoder on `bytes`: none may panic.
fn decode_all(bytes: &[u8]) {
    let _ = SignedEntry::decode(bytes);
    let _ = SignedCert::decode(bytes);
    let _ = SignedVoid::decode(bytes);
    let _ = SignedForward::decode(bytes);
    let _ = SignedGenesis::decode(bytes);
    let _ = Node::decode_at(bytes, &[]);
    let _ = Node::decode_at(bytes, &[3, 7]);
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn cbor_round_trips(v in value()) {
        let bytes = cbor::encode(&v);
        prop_assert_eq!(cbor::decode(&bytes).unwrap(), v);
    }

    /// Whatever the decoder accepts is canonical: it encodes back to the same bytes.
    #[test]
    fn cbor_accepts_only_canonical_bytes(bytes in vec(any::<u8>(), 0..256)) {
        if let Ok(v) = cbor::decode(&bytes) {
            prop_assert_eq!(cbor::encode(&v), bytes);
        }
    }

    /// Mostly-valid CBOR (an encoded value with a byte changed) reaches the decoders'
    /// deeper paths.
    #[test]
    fn cbor_survives_mutations(v in value(), at in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let mut bytes = cbor::encode(&v);
        let i = at.index(bytes.len());
        bytes[i] = byte;
        if let Ok(w) = cbor::decode(&bytes) {
            prop_assert_eq!(cbor::encode(&w), bytes);
        }
    }

    #[test]
    fn record_decoders_take_any_bytes(bytes in vec(any::<u8>(), 0..1024)) {
        decode_all(&bytes);
    }

    #[test]
    fn record_decoders_take_mutated_records(
        at in vec(any::<prop::sample::Index>(), 1..4),
        bytes in vec(any::<u8>(), 3),
    ) {
        let good = signed_entry();
        let mut b = good.encode();
        for (i, x) in at.iter().zip(&bytes) {
            let j = i.index(b.len());
            b[j] = *x;
        }
        decode_all(&b);
        // A changed record that still decodes is either the same record or fails its
        // signature: no other valid record hides one byte away.
        if let Ok(e) = SignedEntry::decode(&b)
            && e.id() != good.id()
        {
            prop_assert!(e.header.signer.verify(&e.id(), &e.sig).is_err());
        }
    }

    #[test]
    fn the_root_ignores_insertion_order(
        (ids, shuffled) in vec(any::<[u8; 32]>(), 0..150)
            .prop_flat_map(|v| (Just(v.clone()), Just(v).prop_shuffle()))
    ) {
        let a = Trie::build(ids.iter().map(|i| (Kind::Entry, Digest(*i))));
        let b = Trie::build(shuffled.iter().map(|i| (Kind::Entry, Digest(*i))));
        prop_assert_eq!(a.root(), b.root());
        let distinct: std::collections::HashSet<_> = ids.iter().collect();
        prop_assert_eq!(a.count(), distinct.len());
    }

    #[test]
    fn proofs_hold(ids in vec(any::<[u8; 32]>(), 1..120), probe in any::<[u8; 32]>()) {
        let t = Trie::build(ids.iter().map(|i| (Kind::Entry, Digest(*i))));
        let root = t.root();
        for i in &ids {
            prop_assert!(t.prove(&Digest(*i)).proves_inclusion(&root, Kind::Entry, &Digest(*i)));
        }
        let p = Digest(probe);
        if !ids.contains(&probe) {
            prop_assert!(t.prove(&p).proves_absence(&root, &p));
            prop_assert!(!t.prove(&p).proves_inclusion(&root, Kind::Entry, &p));
        }
    }
}
