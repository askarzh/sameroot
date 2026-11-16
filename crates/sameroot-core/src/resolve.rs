//! Resolution: the state as a function of the ledger (design 0003 §5.3).
//!
//! `state(L, manifest, asOf)` runs one pipeline for every rule:
//!
//! 1. **Voids** (design 0004 §5.3): voids are effective unless a superior void
//!    without `before` targets a certificate their authority rests on; an entry
//!    covered by effective voids counts only if it is in the keep list of each.
//! 2. **Negations:** an entry is negated if an effective negation that may negate it
//!    targets it.
//! 3. **Expiry:** puts that expired at `asOf` have no effect.
//! 4. **The rule** picks the state per key.
//!
//! Everything is a function of the set of records, so replicas with the same ledger
//! and the same `asOf` compute the same state. Effects do not only shrink as records
//! arrive (voiding a negation restores its target), but the result never depends on
//! the order.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::cert::VoidTarget;
use crate::entry::{Header, Op, Path, Subspace};
use crate::genesis::{NegateRight, Resolution, Rule};
use crate::hash::Digest;
use crate::identity::PublicKey;

/// An admitted entry as resolution sees it.
#[derive(Clone, Debug)]
pub struct LedgerEntry {
    /// The entry id.
    pub id: Digest,
    /// Its header.
    pub header: Header,
    /// The chain root (the key whose authority it was written under).
    pub chain_root: PublicKey,
    /// The certificate ids of its chain.
    pub chain: Vec<Digest>,
}

/// An admitted void as resolution sees it.
#[derive(Clone, Debug)]
pub struct LedgerVoid {
    /// The void id.
    pub id: Digest,
    /// What it revokes.
    pub target: VoidTarget,
    /// The kept entry ids (`None`: a total void).
    pub keep: Option<HashSet<Digest>>,
    /// Covers only entries with `ts < before`.
    pub before: Option<u64>,
    /// The certificates its signer's authority rests on (`VoidAccepted::authority`).
    pub authority: Vec<Digest>,
}

impl LedgerVoid {
    /// A total void of a certificate, by the chain's root (tests, simulations).
    pub fn total(id: Digest, cert: Digest) -> LedgerVoid {
        LedgerVoid {
            id,
            target: VoidTarget::Cert(cert),
            keep: None,
            before: None,
            authority: Vec::new(),
        }
    }
}

/// The voids in effect: a void is disabled when an effective void without `before`
/// targets a certificate its authority rests on (rule 5). Superior voids have shorter
/// authority, so voids are decided in order of authority length.
fn effective_voids(voids: &[LedgerVoid]) -> Vec<&LedgerVoid> {
    let mut sorted: Vec<&LedgerVoid> = voids.iter().collect();
    sorted.sort_by_key(|v| (v.authority.len(), v.id));
    let mut disabled_certs: HashSet<Digest> = HashSet::new();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let len = sorted[i].authority.len();
        let mut j = i;
        let mut group = Vec::new();
        while j < sorted.len() && sorted[j].authority.len() == len {
            let v = sorted[j];
            if !v.authority.iter().any(|c| disabled_certs.contains(c)) {
                group.push(v);
            }
            j += 1;
        }
        for v in &group {
            if v.before.is_none()
                && let VoidTarget::Cert(c) = v.target
            {
                disabled_certs.insert(c);
            }
        }
        out.extend(group);
        i = j;
    }
    out
}

/// The state of one key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// The winning put.
    Value(Digest),
    /// The winning entry is this delete.
    Deleted(Digest),
    /// `collection`: the remaining puts, in `(ts, id)` order.
    Items(Vec<Digest>),
}

/// A key of the state.
pub type Key = (Subspace, Path);

/// The state: per key, what resolution decided. Keys without remaining entries are
/// absent.
pub type State = BTreeMap<Key, Resolved>;

fn may_negate(
    right: NegateRight,
    owner: &PublicKey,
    negation: &LedgerEntry,
    target: &LedgerEntry,
) -> bool {
    let author = negation.chain_root == target.chain_root;
    let by_owner = negation.chain_root == *owner;
    match right {
        NegateRight::Author => author,
        NegateRight::Owner => by_owner,
        NegateRight::Both => author || by_owner,
    }
}

/// Which entries are negated. Computed iteratively in dependency order (a negation
/// is decided before its target), so chains of any length are fine.
fn negated_set(
    entries: &HashMap<Digest, &LedgerEntry>,
    voided: &dyn Fn(&LedgerEntry) -> bool,
    right: NegateRight,
    owner: &PublicKey,
) -> HashSet<Digest> {
    // target → the (non-voided) negations naming it
    let mut negators: HashMap<Digest, Vec<Digest>> = HashMap::new();
    for e in entries.values() {
        if e.header.op == Op::Negate
            && !voided(e)
            && let Some(t) = e.header.target
            && entries.contains_key(&t)
        {
            negators.entry(t).or_default().push(e.id);
        }
    }
    let mut status: HashMap<Digest, bool> = HashMap::new(); // id → negated?
    for &start in negators.keys() {
        if status.contains_key(&start) {
            continue;
        }
        // Post-order DFS over "negated by" edges with an explicit stack.
        let mut stack = vec![(start, false)];
        let mut on_stack = HashSet::new();
        while let Some((id, expanded)) = stack.pop() {
            if status.contains_key(&id) {
                continue;
            }
            let ns = negators.get(&id).map(Vec::as_slice).unwrap_or(&[]);
            if !expanded {
                on_stack.insert(id);
                stack.push((id, true));
                for n in ns {
                    if !status.contains_key(n) && !on_stack.contains(n) {
                        stack.push((*n, false));
                    }
                }
                continue;
            }
            let target = entries[&id];
            let negated = ns.iter().any(|n| {
                // A negation still being decided would be a cycle, impossible with
                // hash ids; it counts as not effective.
                status.get(n) == Some(&false) && may_negate(right, owner, entries[n], target)
            });
            status.insert(id, negated);
            on_stack.remove(&id);
        }
    }
    status
        .into_iter()
        .filter_map(|(id, n)| n.then_some(id))
        .collect()
}

/// Computes the state of a ledger at `as_of`.
pub fn resolve(
    entries: &[LedgerEntry],
    voids: &[LedgerVoid],
    resolution: &Resolution,
    owner: &PublicKey,
    as_of: u64,
) -> State {
    let mut per_key: BTreeMap<Key, Vec<&LedgerEntry>> = BTreeMap::new();
    for e in counting_entries(entries, voids, resolution, owner, as_of) {
        per_key
            .entry((e.header.subspace, e.header.path.clone()))
            .or_default()
            .push(e);
    }
    state_of(per_key, resolution)
}

/// The entries that count at `as_of`: not expired, not voided, not negated (and no
/// negations themselves; no deletes in a collection). The state picks among them per
/// key; values of entries that don't count are dead, while superseded ones stay part
/// of the history.
pub fn counting(
    entries: &[LedgerEntry],
    voids: &[LedgerVoid],
    resolution: &Resolution,
    owner: &PublicKey,
    as_of: u64,
) -> HashSet<Digest> {
    counting_entries(entries, voids, resolution, owner, as_of)
        .into_iter()
        .map(|e| e.id)
        .collect()
}

fn counting_entries<'a>(
    entries: &'a [LedgerEntry],
    voids: &[LedgerVoid],
    resolution: &Resolution,
    owner: &PublicKey,
    as_of: u64,
) -> Vec<&'a LedgerEntry> {
    let by_id: HashMap<Digest, &LedgerEntry> = entries.iter().map(|e| (e.id, e)).collect();
    let mut by_cert: HashMap<Digest, Vec<&LedgerVoid>> = HashMap::new();
    let mut by_key: HashMap<PublicKey, Vec<&LedgerVoid>> = HashMap::new();
    for v in effective_voids(voids) {
        match v.target {
            VoidTarget::Cert(c) => by_cert.entry(c).or_default().push(v),
            VoidTarget::Key(k) => by_key.entry(k).or_default().push(v),
        }
    }
    // An entry counts only if every effective void covering it keeps it.
    let voided = |e: &LedgerEntry| {
        let by_chain = e.chain.iter().filter_map(|c| by_cert.get(c)).flatten();
        let by_signer = e
            .header
            .cert
            .is_none()
            .then(|| by_key.get(&e.header.signer))
            .flatten()
            .into_iter()
            .flatten();
        by_chain
            .chain(by_signer)
            .filter(|v| v.before.is_none_or(|b| e.header.ts < b))
            .any(|v| !v.keep.as_ref().is_some_and(|k| k.contains(&e.id)))
    };
    let negated = negated_set(&by_id, &voided, resolution.negate, owner);
    by_id
        .values()
        .copied()
        .filter(|e| {
            let h = &e.header;
            let counts = match h.op {
                Op::Put => !h.exp.is_some_and(|exp| exp <= as_of),
                Op::Delete => resolution.rule != Rule::Collection,
                Op::Negate => false,
            };
            counts && !voided(e) && !negated.contains(&e.id)
        })
        .collect()
}

fn state_of(per_key: BTreeMap<Key, Vec<&LedgerEntry>>, resolution: &Resolution) -> State {
    let mut state = State::new();
    for (key, mut list) in per_key {
        list.sort_by_key(|e| (e.header.ts, e.id));
        let pick = |e: &LedgerEntry| match e.header.op {
            Op::Put => Resolved::Value(e.id),
            _ => Resolved::Deleted(e.id),
        };
        let r = match resolution.rule {
            Rule::Lww => pick(list.last().expect("non-empty")),
            Rule::Earliest => pick(list.first().expect("non-empty")),
            Rule::Collection => Resolved::Items(list.iter().map(|e| e.id).collect()),
        };
        state.insert(key, r);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    struct W {
        owner: PublicKey,
        alice: PublicKey,
        bob: PublicKey,
        entries: Vec<LedgerEntry>,
    }

    impl W {
        fn new() -> W {
            W {
                owner: PublicKey([1; 32]),
                alice: PublicKey([2; 32]),
                bob: PublicKey([3; 32]),
                entries: Vec::new(),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn add(
            &mut self,
            root: PublicKey,
            op: Op,
            key: &str,
            ts: u64,
            exp: Option<u64>,
            target: Option<Digest>,
            chain: Vec<Digest>,
        ) -> Digest {
            let header = Header {
                db: Digest::ZERO,
                subspace: Subspace::Shared,
                path: Path::from_strs([key]),
                op,
                ts,
                exp,
                value_size: if op == Op::Put { 1 } else { 0 },
                value_hash: if op == Op::Put {
                    Digest([ts as u8; 32])
                } else {
                    Digest::ZERO
                },
                target,
                signer: root,
                cert: None,
                work: 0,
            };
            let id = header.id();
            self.entries.push(LedgerEntry {
                id,
                header,
                chain_root: root,
                chain,
            });
            id
        }

        fn put(&mut self, root: PublicKey, key: &str, ts: u64) -> Digest {
            self.add(root, Op::Put, key, ts, None, None, vec![])
        }

        fn negate(&mut self, root: PublicKey, target: Digest, ts: u64) -> Digest {
            self.add(root, Op::Negate, "n", ts, None, Some(target), vec![])
        }

        fn state(&self, rule: Rule, negate: NegateRight, voided: &[Digest], as_of: u64) -> State {
            let voids: Vec<LedgerVoid> = voided
                .iter()
                .map(|c| LedgerVoid::total(Digest::derive("void", &c.0), *c))
                .collect();
            self.with_voids(rule, negate, &voids, as_of)
        }

        fn with_voids(
            &self,
            rule: Rule,
            negate: NegateRight,
            voids: &[LedgerVoid],
            as_of: u64,
        ) -> State {
            resolve(
                &self.entries,
                voids,
                &Resolution { rule, negate },
                &self.owner,
                as_of,
            )
        }
    }

    fn key(k: &str) -> Key {
        (Subspace::Shared, Path::from_strs([k]))
    }

    #[test]
    fn rules() {
        let mut w = W::new();
        let a = w.put(w.alice, "k", 1);
        let b = w.put(w.bob, "k", 2);
        let s = w.state(Rule::Lww, NegateRight::Author, &[], 0);
        assert_eq!(s[&key("k")], Resolved::Value(b));
        let s = w.state(Rule::Earliest, NegateRight::Author, &[], 0);
        assert_eq!(s[&key("k")], Resolved::Value(a));
        let s = w.state(Rule::Collection, NegateRight::Author, &[], 0);
        assert_eq!(s[&key("k")], Resolved::Items(vec![a, b]));
        w.add(w.alice, Op::Delete, "k", 3, None, None, vec![]);
        assert!(matches!(
            w.state(Rule::Lww, NegateRight::Author, &[], 0)[&key("k")],
            Resolved::Deleted(_)
        ));
        assert_eq!(
            w.state(Rule::Collection, NegateRight::Author, &[], 0)[&key("k")],
            Resolved::Items(vec![a, b])
        );
    }

    #[test]
    fn negation_rights_and_chains() {
        let mut w = W::new();
        let p = w.put(w.alice, "k", 1);
        let by_bob = w.negate(w.bob, p, 2);
        let _ = by_bob;
        let k = key("k");
        assert_eq!(
            w.state(Rule::Lww, NegateRight::Author, &[], 0)[&k],
            Resolved::Value(p),
            "bob may not"
        );
        let n1 = w.negate(w.alice, p, 3);
        assert!(
            !w.state(Rule::Lww, NegateRight::Author, &[], 0)
                .contains_key(&k),
            "alice may"
        );
        // N1 negated by alice restores P...
        let n3 = w.negate(w.alice, n1, 4);
        assert_eq!(
            w.state(Rule::Lww, NegateRight::Author, &[], 0)[&k],
            Resolved::Value(p)
        );
        // ...unless another negation N2 of P stands.
        let n2 = w.negate(w.alice, p, 5);
        assert!(
            !w.state(Rule::Lww, NegateRight::Author, &[], 0)
                .contains_key(&k)
        );
        let _ = (n2, n3);
        // The owner may negate under `owner` and `both`, not under `author`.
        let mut v = W::new();
        let q = v.put(v.alice, "k", 1);
        v.negate(v.owner, q, 2);
        assert!(
            v.state(Rule::Lww, NegateRight::Author, &[], 0)
                .contains_key(&k)
        );
        assert!(
            !v.state(Rule::Lww, NegateRight::Owner, &[], 0)
                .contains_key(&k)
        );
        assert!(
            !v.state(Rule::Lww, NegateRight::Both, &[], 0)
                .contains_key(&k)
        );
    }

    #[test]
    fn voids_and_expiry() {
        let mut w = W::new();
        let cert = Digest([9; 32]);
        let old = w.put(w.alice, "k", 1);
        let voided = w.add(w.alice, Op::Put, "k", 2, None, None, vec![cert]);
        let k = key("k");
        assert_eq!(
            w.state(Rule::Lww, NegateRight::Author, &[], 0)[&k],
            Resolved::Value(voided)
        );
        assert_eq!(
            w.state(Rule::Lww, NegateRight::Author, &[cert], 0)[&k],
            Resolved::Value(old)
        );
        // A voided negation has no effect.
        let mut v = W::new();
        let p = v.put(v.alice, "k", 1);
        v.add(v.alice, Op::Negate, "n", 2, None, Some(p), vec![cert]);
        assert!(
            !v.state(Rule::Lww, NegateRight::Author, &[], 0)
                .contains_key(&k)
        );
        assert_eq!(
            v.state(Rule::Lww, NegateRight::Author, &[cert], 0)[&k],
            Resolved::Value(p)
        );
        // Expiry acts at `as_of` and can bring back an older put.
        let mut x = W::new();
        let lasting = x.put(x.alice, "k", 1);
        let short = x.add(x.alice, Op::Put, "k", 2, Some(100), None, vec![]);
        assert_eq!(
            x.state(Rule::Lww, NegateRight::Author, &[], 99)[&k],
            Resolved::Value(short)
        );
        assert_eq!(
            x.state(Rule::Lww, NegateRight::Author, &[], 100)[&k],
            Resolved::Value(lasting)
        );
    }

    /// Design 0004 §5.3: keep lists, `before`, key voids and subordinate voids.
    #[test]
    fn voids_with_keep_before_and_authority() {
        let mut w = W::new();
        let agent = Digest([7; 32]);
        let device = Digest([8; 32]);
        let honest = w.add(w.alice, Op::Put, "a", 10, None, None, vec![agent, device]);
        w.add(w.alice, Op::Put, "b", 11, None, None, vec![agent, device]);
        let later = w.add(w.alice, Op::Put, "c", 500, None, None, vec![agent, device]);
        let lww = |voids: &[LedgerVoid]| w.with_voids(Rule::Lww, NegateRight::Author, voids, 0);
        let keep = |ids: &[Digest]| Some(ids.iter().copied().collect::<HashSet<_>>());
        // Keep list: the honest entry stays, the forged one goes.
        let v = LedgerVoid {
            id: Digest([1; 32]),
            target: VoidTarget::Cert(agent),
            keep: keep(&[honest, later]),
            before: None,
            authority: vec![device],
        };
        let s = lww(std::slice::from_ref(&v));
        assert!(s.contains_key(&key("a")) && !s.contains_key(&key("b")));
        // `before`: only entries with ts < before are constrained.
        let v2 = LedgerVoid {
            keep: keep(&[honest]),
            before: Some(100),
            ..v.clone()
        };
        let s = lww(std::slice::from_ref(&v2));
        assert!(s.contains_key(&key("a")) && !s.contains_key(&key("b")));
        assert!(s.contains_key(&key("c")), "after the cutoff");
        // Two voids intersect.
        let v3 = LedgerVoid {
            id: Digest([2; 32]),
            keep: keep(&[later]),
            ..v.clone()
        };
        let s = lww(&[v.clone(), v3]);
        assert!(!s.contains_key(&key("a")) && s.contains_key(&key("c")));
        // Rule 5: a void without `before` of the device cert disables the device's
        // void of the agent cert, so the owner's keep list decides.
        let sabotage = LedgerVoid {
            id: Digest([3; 32]),
            target: VoidTarget::Cert(agent),
            keep: None,
            before: None,
            authority: vec![device],
        };
        assert!(lww(std::slice::from_ref(&sabotage)).is_empty());
        let by_owner = LedgerVoid {
            id: Digest([4; 32]),
            target: VoidTarget::Cert(device),
            keep: keep(&[honest, later]),
            before: None,
            authority: vec![],
        };
        let s = lww(&[sabotage.clone(), by_owner.clone()]);
        assert!(s.contains_key(&key("a")) && s.contains_key(&key("c")));
        assert!(!s.contains_key(&key("b")));
        // ...but with `before` the device's revocations stay in force.
        let rotation = LedgerVoid {
            before: Some(1_000),
            ..by_owner
        };
        assert!(lww(&[sabotage, rotation]).is_empty());
        // A key void covers that key's certless entries only.
        let mut k = W::new();
        let bare = k.put(k.bob, "x", 1);
        let delegated = k.add(k.bob, Op::Put, "y", 1, None, None, vec![agent]);
        let kill = LedgerVoid {
            id: Digest([5; 32]),
            target: VoidTarget::Key(k.bob),
            keep: None,
            before: None,
            authority: vec![],
        };
        let s = k.with_voids(Rule::Lww, NegateRight::Author, &[kill], 0);
        assert!(!s.contains_key(&key("x")));
        let _ = (bare, delegated);
    }

    #[test]
    fn long_negation_chain_is_iterative() {
        let mut w = W::new();
        let p = w.put(w.alice, "k", 1);
        let mut last = p;
        for i in 0..100_000u64 {
            last = w.negate(w.alice, last, 2 + i);
        }
        // 100,000 negations: the last one stands, so the one before is negated, and
        // so on down the chain; P is negated by an even-length chain → restored.
        let s = w.state(Rule::Lww, NegateRight::Author, &[], 0);
        assert_eq!(s.get(&key("k")), Some(&Resolved::Value(p)));
    }

    #[test]
    fn order_of_input_does_not_matter() {
        let mut w = W::new();
        let p = w.put(w.alice, "k", 1);
        let n = w.negate(w.alice, p, 2);
        w.negate(w.alice, n, 3);
        w.put(w.bob, "j", 4);
        let a = w.state(Rule::Lww, NegateRight::Author, &[], 0);
        w.entries.reverse();
        assert_eq!(a, w.state(Rule::Lww, NegateRight::Author, &[], 0));
    }
}
