//! Admission of records (design 0003 §2).
//!
//! [`verify_entry`], [`verify_void`] and [`verify_forward`] are pure functions of the
//! genesis, the signed record and its dependencies (the certificates of its chain, a
//! void's keep list): no clock, no other records, no state.
//! That is what makes every replica admit the same records in any order. Local
//! admission policy (deferring future-dated entries, budgets) is separate: see
//! [`deferred`].

use crate::cert::{ChainError, MAX_CHAIN, SignedCert, SignedVoid, VoidTarget, authority};
use crate::entry::{Header, Op, SignedEntry, Subspace, value_hash};
use crate::forward::{SignedForward, owner_commitment};
use crate::genesis::Genesis;
use crate::hash::{Digest, work_bits};
use crate::identity::{PublicKey, VerifyError};
use crate::ledger::{Kind, Trie};
use crate::logic::{self, Inputs, V};

/// Why a record is not admissible in a database.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    /// The record names a different database.
    #[error("record belongs to another database")]
    WrongDatabase,
    /// The signature doesn't verify.
    #[error("signature: {0}")]
    Signature(#[from] VerifyError),
    /// The path breaks the format limits.
    #[error("path exceeds the limits")]
    Path,
    /// A put's value is too large.
    #[error("value too large")]
    Value,
    /// Expiry is missing where required, or out of range.
    #[error("expiry is invalid for this database")]
    Expiry,
    /// The delegation chain doesn't authorize the record.
    #[error("delegation: {0}")]
    Chain(#[from] ChainError),
    /// The contract's `access` program refuses the entry.
    #[error("access refused by the contract")]
    Access,
    /// The contract's `validity` program refuses the entry.
    #[error("invalid by the contract")]
    Validity,
    /// The void's signer may not void that certificate.
    #[error("not allowed to void this certificate")]
    VoidAuthority,
    /// The void's keep list is absent (a dependency still to arrive).
    #[error("the keep list of the void is missing")]
    KeepMissing,
    /// The void's keep list doesn't match its root and count, or is too long.
    #[error("keep list: {0}")]
    Keep(&'static str),
    /// The record lacks the proof of work the database requires.
    #[error("not enough proof of work")]
    Work,
    /// A field doesn't fit the op (values and `exp` on puts only, `target` on
    /// negations only).
    #[error("fields don't match the op")]
    Shape,
    /// A successor's entry is dated before the successor's genesis (design 0004 §8.2).
    #[error("dated before this database was created")]
    BeforeGenesis,
    /// The forward isn't signed by the owner or names an owner the genesis doesn't
    /// commit to.
    #[error("not allowed to forward this database")]
    ForwardAuthority,
}

impl Reject {
    /// True for a dependency that may still arrive (a certificate, a keep list): the
    /// record is pending, not refused.
    pub fn is_missing(&self) -> bool {
        matches!(
            self,
            Reject::Chain(ChainError::Missing(_)) | Reject::KeepMissing
        )
    }
}

/// A void that passed admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoidAccepted {
    /// The void id.
    pub id: Digest,
    /// The root of its authority: the top issuer of the voided certificate's chain, or
    /// the key of a key void.
    pub root: PublicKey,
    /// The certificates the signer's authority rests on (strictly above the link it
    /// issued), leaf first; empty when the signer is the chain root (design 0004 §5.3
    /// rule 5).
    pub authority: Vec<Digest>,
}

/// An entry that passed admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The entry id.
    pub id: Digest,
    /// The chain root: the key whose authority the entry was written under.
    pub owner: PublicKey,
}

/// The inputs of the contract's programs for an entry (design 0003 §5.2). `work` is
/// the number of leading zero bits of the entry id `id` (design 0004 §6).
pub fn entry_inputs(genesis: &Genesis, h: &Header, id: &Digest, chain_root: &PublicKey) -> Inputs {
    let mut i = Inputs::new();
    i.insert("work", V::Uint(work_bits(id) as u64));
    i.insert("kind", V::Bytes(b"entry".to_vec()));
    let op: &[u8] = match h.op {
        Op::Put => b"put",
        Op::Delete => b"delete",
        Op::Negate => b"negate",
    };
    i.insert("op", V::Bytes(op.to_vec()));
    i.insert(
        "path",
        V::List(h.path.0.iter().map(|c| V::Bytes(c.clone())).collect()),
    );
    match h.subspace {
        Subspace::Shared => {
            i.insert("shared", V::Bool(true));
        }
        Subspace::Owner(k) => {
            i.insert("shared", V::Bool(false));
            i.insert("subspaceOwner", V::Bytes(k.0.to_vec()));
        }
    }
    i.insert("signer", V::Bytes(h.signer.0.to_vec()));
    i.insert("chainRoot", V::Bytes(chain_root.0.to_vec()));
    i.insert("owner", V::Bytes(genesis.owner.0.to_vec()));
    i.insert("ts", V::Uint(h.ts));
    if let Some(exp) = h.exp {
        i.insert("exp", V::Uint(exp));
    }
    if h.op == Op::Put {
        i.insert("valueSize", V::Uint(h.value_size));
        i.insert("valueHash", V::Bytes(h.value_hash.0.to_vec()));
    }
    if let Some(t) = h.target {
        i.insert("target", V::Bytes(t.0.to_vec()));
    }
    i
}

/// Admission of an entry. `db` must be `genesis.id()`; callers cache it. `lookup`
/// resolves the certificates of the chain.
pub fn verify_entry(
    genesis: &Genesis,
    db: &Digest,
    entry: &SignedEntry,
    lookup: &dyn Fn(&Digest) -> Option<SignedCert>,
) -> Result<Accepted, Reject> {
    let h = &entry.header;
    if h.db != *db {
        return Err(Reject::WrongDatabase);
    }
    let id = h.id();
    h.signer.verify(&id, &entry.sig)?;
    h.path.check().map_err(|_| Reject::Path)?;
    if !h.shape_ok() {
        return Err(Reject::Shape);
    }
    // The floor rule: a successor's entries can't be backdated below its genesis.
    if genesis.predecessor.is_some() && h.ts < genesis.created_at {
        return Err(Reject::BeforeGenesis);
    }
    if h.op == Op::Put && h.value_size > genesis.limits.max_value {
        return Err(Reject::Value);
    }
    // Field shapes per op are enforced by decoding; here only the database's limits.
    match (h.op, genesis.limits.max_ttl, h.exp) {
        (_, _, Some(exp)) if exp <= h.ts => return Err(Reject::Expiry),
        (Op::Put, Some(ttl), exp) if !exp.is_some_and(|e| e <= h.ts.saturating_add(ttl)) => {
            return Err(Reject::Expiry);
        }
        _ => {}
    }
    let owner = authority(h, lookup)?;
    let inputs = entry_inputs(genesis, h, &id, &owner);
    if !logic::run(&genesis.contract.access, &inputs) {
        return Err(Reject::Access);
    }
    if !logic::run(&genesis.contract.validity, &inputs) {
        return Err(Reject::Validity);
    }
    Ok(Accepted { id, owner })
}

/// Admission of a void (design 0004 §5.2).
///
/// - A cert void carries the voided certificate's whole chain; every link is checked
///   (signature, database, `parent.subject == child.issuer`), and the signer must be
///   the issuer of one of its links.
/// - A key void is signed by its key (checked by its shape) and is total.
/// - A keep list must be given whenever the void has `keep`: canonically ordered,
///   distinct, within the database's limit, and matching `root` and `count`.
/// - A void whose authority root isn't the owner needs `voidWork` leading zero bits.
pub fn verify_void(
    genesis: &Genesis,
    db: &Digest,
    void: &SignedVoid,
    lookup: &dyn Fn(&Digest) -> Option<SignedCert>,
    keep: Option<&[Digest]>,
) -> Result<VoidAccepted, Reject> {
    let v = &void.void;
    if v.db != *db {
        return Err(Reject::WrongDatabase);
    }
    if !v.shape_ok() {
        return Err(Reject::VoidAuthority);
    }
    let id = v.id();
    v.signer.verify(&id, &void.sig)?;

    let (root, authority) = match v.target {
        VoidTarget::Key(k) => (k, Vec::new()),
        VoidTarget::Cert(target) => {
            let mut path = Vec::new();
            let mut signer_link = None;
            let mut child: Option<SignedCert> = None;
            let mut next = target;
            let root = loop {
                if path.len() == MAX_CHAIN {
                    return Err(Reject::Chain(ChainError::TooLong));
                }
                let c = lookup(&next).ok_or(Reject::Chain(ChainError::Missing(next)))?;
                c.cert
                    .issuer
                    .verify(&c.id(), &c.sig)
                    .map_err(|_| Reject::Chain(ChainError::BadSignature))?;
                if c.cert.db != *db {
                    return Err(Reject::WrongDatabase);
                }
                if let Some(ch) = &child
                    && ch.cert.issuer != c.cert.subject
                {
                    return Err(Reject::Chain(ChainError::Broken));
                }
                if signer_link.is_none() && c.cert.issuer == v.signer {
                    signer_link = Some(path.len());
                }
                path.push(next);
                match c.cert.parent {
                    None => break c.cert.issuer,
                    Some(parent) => {
                        next = parent;
                        child = Some(c);
                    }
                }
            };
            let link = signer_link.ok_or(Reject::VoidAuthority)?;
            (root, path[link + 1..].to_vec())
        }
    };

    if let Some(k) = &v.keep {
        let list = keep.ok_or(Reject::KeepMissing)?;
        if list.len() as u64 != k.count {
            return Err(Reject::Keep("count doesn't match"));
        }
        if k.count > genesis.limits.keep_limit() {
            return Err(Reject::Keep("longer than the database allows"));
        }
        if !list.windows(2).all(|w| w[0] < w[1]) {
            return Err(Reject::Keep("not in ascending order without repeats"));
        }
        if Trie::build(list.iter().map(|d| (Kind::Entry, *d))).root() != k.root {
            return Err(Reject::Keep("root doesn't match"));
        }
    }

    if let Some(bits) = genesis.limits.void_work
        && root != genesis.owner
        && (work_bits(&id) as u64) < bits
    {
        return Err(Reject::Work);
    }
    Ok(VoidAccepted {
        id,
        root,
        authority,
    })
}

/// Admission of a forward (design 0004 §8.1): signed by the database owner; if the
/// genesis commits to a next owner, the forward must name that owner.
pub fn verify_forward(
    genesis: &Genesis,
    db: &Digest,
    forward: &SignedForward,
) -> Result<Digest, Reject> {
    let f = &forward.forward;
    if f.db != *db {
        return Err(Reject::WrongDatabase);
    }
    let id = f.id();
    genesis.owner.verify(&id, &forward.sig)?;
    if let Some(next) = genesis.next_owner
        && owner_commitment(&f.owner) != next
    {
        return Err(Reject::ForwardAuthority);
    }
    Ok(id)
}

/// Checks a value against its header.
pub fn verify_value(h: &Header, value: &[u8]) -> bool {
    value.len() as u64 == h.value_size && value_hash(value) == h.value_hash
}

/// Local admission: should a replica hold back this entry until its clock passes?
/// Not a consensus rule: the entry is kept and admitted locally later.
pub fn deferred(h: &Header, now_ms: u64, ts_skew_ms: u64) -> bool {
    h.ts > now_ms.saturating_add(ts_skew_ms)
}

/// Has the put expired at `as_of`? (It stays in the ledger; it only stops counting
/// in the state.)
pub fn expired(h: &Header, as_of: u64) -> bool {
    h.exp.is_some_and(|exp| exp <= as_of)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{Area, Cert};
    use crate::entry::Path;
    use crate::genesis::Genesis;
    use crate::identity::SecretKey;
    use std::collections::HashMap;

    struct World {
        owner: SecretKey,
        device: SecretKey,
        genesis: Genesis,
        db: Digest,
        certs: HashMap<Digest, SignedCert>,
        device_cert: Digest,
    }

    fn world() -> World {
        let owner = SecretKey::from_seed([1; 32]);
        let device = SecretKey::from_seed([2; 32]);
        let mut genesis = Genesis::new(
            "t",
            owner.public(),
            crate::logic::presets::own_subspace(),
            1,
        );
        genesis.nonce = [0; 16];
        let db = genesis.id();
        let cert = Cert {
            issuer: owner.public(),
            subject: device.public(),
            parent: None,
            db,
            area: Area {
                subspace: Subspace::Owner(owner.public()),
                path_prefix: Path::default(),
                ops: vec![Op::Put, Op::Delete],
            },
            not_before: 0,
            not_after: 1_000,
            name: Some("laptop".into()),
            endpoint: None,
        }
        .sign(&owner);
        let device_cert = cert.id();
        World {
            owner,
            device,
            genesis,
            db,
            certs: HashMap::from([(device_cert, cert)]),
            device_cert,
        }
    }

    fn put(
        w: &World,
        signer: &SecretKey,
        subspace: Subspace,
        cert: Option<Digest>,
        ts: u64,
    ) -> SignedEntry {
        Header {
            db: w.db,
            subspace,
            path: Path::from_strs(["k"]),
            op: Op::Put,
            ts,
            exp: None,
            value_size: 1,
            value_hash: value_hash(b"x"),
            target: None,
            signer: signer.public(),
            cert,
            work: 0,
        }
        .sign(signer)
    }

    fn check(w: &World, e: &SignedEntry) -> Result<Accepted, Reject> {
        verify_entry(&w.genesis, &w.db, e, &|id| w.certs.get(id).cloned())
    }

    #[test]
    fn owner_and_delegated_device_may_write_the_owners_subspace() {
        let w = world();
        let own = Subspace::Owner(w.owner.public());
        assert_eq!(
            check(&w, &put(&w, &w.owner, own, None, 5)).unwrap().owner,
            w.owner.public()
        );
        assert_eq!(
            check(&w, &put(&w, &w.device, own, Some(w.device_cert), 5))
                .unwrap()
                .owner,
            w.owner.public()
        );
    }

    #[test]
    fn refusals() {
        let w = world();
        let own = Subspace::Owner(w.owner.public());
        // device without a certificate writing the owner's subspace
        assert_eq!(
            check(&w, &put(&w, &w.device, own, None, 5)),
            Err(Reject::Access)
        );
        // outside the certificate's window
        assert_eq!(
            check(&w, &put(&w, &w.device, own, Some(w.device_cert), 1_000)),
            Err(Reject::Chain(ChainError::NotCovered))
        );
        // the shared subspace is closed under own-subspace
        assert_eq!(
            check(&w, &put(&w, &w.owner, Subspace::Shared, None, 5)),
            Err(Reject::Access)
        );
        // wrong database
        let mut e = put(&w, &w.owner, own, None, 5);
        e.header.db = Digest::ZERO;
        let e = e.header.sign(&w.owner);
        assert_eq!(check(&w, &e), Err(Reject::WrongDatabase));
        // tampered header
        let mut e = put(&w, &w.owner, own, None, 5);
        e.header.ts = 6;
        assert!(matches!(check(&w, &e), Err(Reject::Signature(_))));
        // missing certificate
        let e = put(&w, &w.device, own, Some(Digest::ZERO), 5);
        assert_eq!(
            check(&w, &e),
            Err(Reject::Chain(ChainError::Missing(Digest::ZERO)))
        );
    }

    #[test]
    fn voids_need_the_issuer_or_an_ancestor() {
        use crate::cert::{Keep, Void, VoidTarget};
        let w = world();
        let lookup = |id: &Digest| w.certs.get(id).cloned();
        let check = |v: &SignedVoid, keep: Option<&[Digest]>| {
            verify_void(&w.genesis, &w.db, v, &lookup, keep)
        };
        let by_owner = Void::of_cert(w.db, w.device_cert, w.owner.public()).sign(&w.owner);
        let ok = check(&by_owner, None).unwrap();
        assert_eq!((ok.root, ok.authority.len()), (w.owner.public(), 0));
        // The subject never voids its own certificate.
        let by_device = Void::of_cert(w.db, w.device_cert, w.device.public()).sign(&w.device);
        assert_eq!(check(&by_device, None), Err(Reject::VoidAuthority));
        let unknown = Void::of_cert(w.db, Digest::ZERO, w.owner.public()).sign(&w.owner);
        assert!(check(&unknown, None).unwrap_err().is_missing());
        // A forged certificate in the chain is caught.
        let mut forged = w.certs[&w.device_cert].clone();
        forged.sig = w.device.sign(&forged.id());
        let forged_lookup = |_: &Digest| Some(forged.clone());
        assert_eq!(
            verify_void(&w.genesis, &w.db, &by_owner, &forged_lookup, None),
            Err(Reject::Chain(ChainError::BadSignature))
        );
        // A key void: only by its key, total.
        let kill = Void::of_key(w.db, w.device.public()).sign(&w.device);
        assert_eq!(check(&kill, None).unwrap().root, w.device.public());
        let mut not_own = Void::of_key(w.db, w.device.public());
        not_own.signer = w.owner.public();
        assert_eq!(
            check(&not_own.sign(&w.owner), None),
            Err(Reject::VoidAuthority)
        );
        // Keep lists: present, ordered, matching root and count.
        let mut ids = vec![Digest([3; 32]), Digest([1; 32]), Digest([2; 32])];
        ids.sort();
        let root = Trie::build(ids.iter().map(|d| (Kind::Entry, *d))).root();
        let keep_void = |count: u64, before: Option<u64>| {
            Void {
                keep: Some(Keep { root, count }),
                before,
                ..Void::of_cert(w.db, w.device_cert, w.owner.public())
            }
            .sign(&w.owner)
        };
        let v = keep_void(3, Some(500));
        assert!(check(&v, Some(&ids)).is_ok());
        assert_eq!(check(&v, None), Err(Reject::KeepMissing));
        assert!(check(&v, None).unwrap_err().is_missing());
        assert_eq!(
            check(&keep_void(2, None), Some(&ids)),
            Err(Reject::Keep("count doesn't match"))
        );
        let reversed: Vec<Digest> = ids.iter().rev().copied().collect();
        assert_eq!(
            check(&v, Some(&reversed)),
            Err(Reject::Keep("not in ascending order without repeats"))
        );
        assert_eq!(
            check(&v, Some(&ids[..2])),
            Err(Reject::Keep("count doesn't match"))
        );
        // A key void with keep is malformed.
        let bad = Void {
            target: VoidTarget::Key(w.device.public()),
            signer: w.device.public(),
            keep: Some(Keep { root, count: 3 }),
            ..Void::of_cert(w.db, w.device_cert, w.owner.public())
        };
        assert!(!bad.shape_ok());
        // Proof of work: needed unless the authority root is the owner.
        let mut g = w.genesis.clone();
        g.limits.void_work = Some(8);
        let gdb = g.id();
        let kill = Void::of_key(gdb, w.device.public());
        let plain = kill.clone().sign(&w.device);
        if work_bits(&plain.id()) < 8 {
            assert_eq!(
                verify_void(&g, &gdb, &plain, &lookup, None),
                Err(Reject::Work)
            );
        }
        let mut mined = kill;
        mined.mine(8);
        let mined = mined.sign(&w.device);
        assert!(verify_void(&g, &gdb, &mined, &lookup, None).is_ok());
    }

    #[test]
    fn forwards_need_the_owner_and_the_committed_next_owner() {
        use crate::forward::{Forward, owner_commitment};
        let w = world();
        let next = SecretKey::from_seed([9; 32]);
        let f = |owner: PublicKey| Forward {
            db: w.db,
            successor: Digest([5; 32]),
            owner,
            cut_root: Digest([6; 32]),
        };
        assert!(verify_forward(&w.genesis, &w.db, &f(next.public()).sign(&w.owner)).is_ok());
        assert!(matches!(
            verify_forward(&w.genesis, &w.db, &f(next.public()).sign(&w.device)),
            Err(Reject::Signature(_))
        ));
        let mut g = w.genesis.clone();
        g.next_owner = Some(owner_commitment(&next.public()));
        let gdb = g.id();
        let to = |owner: PublicKey| {
            Forward {
                db: gdb,
                ..f(owner)
            }
            .sign(&w.owner)
        };
        assert!(verify_forward(&g, &gdb, &to(next.public())).is_ok());
        assert_eq!(
            verify_forward(&g, &gdb, &to(w.device.public())),
            Err(Reject::ForwardAuthority)
        );
    }

    #[test]
    fn typed_shapes_and_the_successor_floor() {
        let w = world();
        let own = Subspace::Owner(w.owner.public());
        // A delete built in code with an expiry: decoding would refuse it, and so does
        // admission.
        let mut h = put(&w, &w.owner, own, None, 5).header;
        h.op = Op::Delete;
        h.value_size = 0;
        h.value_hash = Digest::ZERO;
        h.exp = Some(50);
        assert_eq!(check(&w, &h.clone().sign(&w.owner)), Err(Reject::Shape));
        h.exp = None;
        assert!(check(&w, &h.sign(&w.owner)).is_ok());
        // A successor refuses entries dated before its genesis.
        let mut g = w.genesis.clone();
        g.created_at = 100;
        g.predecessor = Some(crate::genesis::Predecessor {
            db: Digest([1; 32]),
            cut_root: Digest([2; 32]),
            cut_count: 0,
            as_of: 90,
            carry_root: None,
        });
        let gdb = g.id();
        let at = |ts| {
            let mut e = put(&w, &w.owner, own, None, ts).header;
            e.db = gdb;
            verify_entry(&g, &gdb, &e.sign(&w.owner), &|_| None)
        };
        assert_eq!(at(99), Err(Reject::BeforeGenesis));
        assert!(at(100).is_ok());
    }

    #[test]
    fn validity_program_and_negations() {
        let mut w = world();
        let own = Subspace::Owner(w.owner.public());
        // validity: values at most 0 bytes, so every put is invalid
        let mut m = crate::cbor::Map::new();
        let mut var = crate::cbor::Map::new();
        var.insert(
            "var",
            crate::cbor::Value::Array(vec![
                crate::cbor::Value::Text("valueSize".into()),
                crate::cbor::Value::Uint(0),
            ]),
        );
        m.insert(
            "==",
            crate::cbor::Value::Array(vec![
                crate::cbor::Value::Map(var),
                crate::cbor::Value::Uint(0),
            ]),
        );
        w.genesis.contract.validity = crate::cbor::Value::Map(m);
        w.db = w.genesis.id();
        let e = put(&w, &w.owner, own, None, 5);
        assert_eq!(check(&w, &e), Err(Reject::Validity));
        // a negation has no value: valid; the device's certificate lacks `negate`
        let neg = |signer: &SecretKey, cert| {
            Header {
                db: w.db,
                subspace: own,
                path: Path::from_strs(["k"]),
                op: Op::Negate,
                ts: 6,
                exp: None,
                value_size: 0,
                value_hash: Digest::ZERO,
                target: Some(e.id()),
                signer: signer.public(),
                cert,
                work: 0,
            }
            .sign(signer)
        };
        assert!(check(&w, &neg(&w.owner, None)).is_ok());
        let w2 = world();
        let n = Header {
            db: w2.db,
            ..neg(&w.device, Some(w2.device_cert)).header
        }
        .sign(&w2.device);
        assert_eq!(check(&w2, &n), Err(Reject::Chain(ChainError::NotCovered)));
    }

    #[test]
    fn verdict_does_not_depend_on_time_or_order() {
        let w = world();
        let own = Subspace::Owner(w.owner.public());
        let far_future = put(&w, &w.owner, own, None, u64::MAX / 2);
        assert!(
            check(&w, &far_future).is_ok(),
            "acceptance never looks at a clock"
        );
        assert!(
            deferred(&far_future.header, 1_000, 600_000),
            "local admission defers it"
        );
    }
}
