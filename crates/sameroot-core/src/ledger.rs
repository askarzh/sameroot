//! The ledger tree (design 0003 §4): a 16-ary sparse trie keyed by record id, each
//! node hashed as a binary Merkle tree over its 16 slots.
//!
//! The shape is a function of the set of records alone: a node exists at nibble path
//! `p` if `p` is the root or at least two records have ids starting with `p`; slot
//! `i` of that node is empty, holds the one record whose id starts with `p‖i`, or
//! refers to the node at `p‖i`. So any arrival order gives the same nodes and root.

use std::collections::HashMap;

use crate::cbor::{self, Map, Value};
use crate::fields::{Fields, FormatError};
use crate::hash::Digest;

/// Contexts of the ledger hashes.
pub mod context {
    /// A record slot.
    pub const LEAF: &str = "sameroot 1 ledger leaf";
    /// An inner pair of the binary tree inside a node.
    pub const PAIR: &str = "sameroot 1 ledger pair";
    /// A node.
    pub const NODE: &str = "sameroot 1 ledger node";
    /// A subject of the reference index (design 0004 §4.1).
    pub const REF_SUBJECT: &str = "sameroot 1 ref subject";
    /// A slot of the reference index.
    pub const REF_LEAF: &str = "sameroot 1 ref leaf";
    /// The ledger commitment over the record root and the reference root.
    pub const COMMITMENT: &str = "sameroot 1 ledger commitment";
}

/// Ids have 64 nibbles; no node is deeper.
pub const MAX_DEPTH: usize = 64;

/// The kind of a ledger record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// A signed entry.
    Entry = 0,
    /// A certificate or key void.
    Void = 1,
    /// A succession forward (design 0004 §8.1).
    Forward = 2,
}

impl Kind {
    /// The kind with this wire code.
    pub fn from_code(n: u64) -> Option<Kind> {
        match n {
            0 => Some(Kind::Entry),
            1 => Some(Kind::Void),
            2 => Some(Kind::Forward),
            _ => None,
        }
    }
}

/// One slot of a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// No record under this slot.
    Empty,
    /// Exactly one record.
    Record(Kind, Digest),
    /// Two or more: the hash of the node one level down.
    Child(Digest),
}

/// The `d`-th nibble of an id (high nibble first).
pub fn nibble(id: &Digest, d: usize) -> u8 {
    let b = id.0[d / 2];
    if d.is_multiple_of(2) {
        b >> 4
    } else {
        b & 0x0f
    }
}

/// True if `id` starts with the nibble path `p`.
pub fn has_prefix(id: &Digest, p: &[u8]) -> bool {
    p.len() <= MAX_DEPTH && p.iter().enumerate().all(|(d, n)| nibble(id, d) == *n)
}

/// The hash of a record slot.
pub fn leaf_hash(kind: Kind, id: &Digest) -> Digest {
    let mut b = Vec::with_capacity(33);
    b.push(kind as u8);
    b.extend_from_slice(&id.0);
    Digest::derive(context::LEAF, &b)
}

pub(crate) fn pair(a: &Digest, b: &Digest) -> Digest {
    if *a == Digest::ZERO && *b == Digest::ZERO {
        return Digest::ZERO;
    }
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&a.0);
    buf[32..].copy_from_slice(&b.0);
    Digest::derive(context::PAIR, &buf)
}

fn slot_hash(s: &Slot) -> Digest {
    match s {
        Slot::Empty => Digest::ZERO,
        Slot::Record(k, id) => leaf_hash(*k, id),
        Slot::Child(h) => *h,
    }
}

/// The 4 levels of the binary tree over 16 slot hashes, bottom first.
pub(crate) fn binary_levels(slots: &[Digest; 16]) -> Vec<Vec<Digest>> {
    let mut levels = vec![slots.to_vec()];
    while levels.last().map(Vec::len) != Some(1) {
        let prev = levels.last().expect("non-empty");
        levels.push(prev.chunks(2).map(|c| pair(&c[0], &c[1])).collect());
    }
    levels
}

pub(crate) fn node_hash_from_root(depth: usize, binary_root: &Digest) -> Digest {
    let mut b = Vec::with_capacity(33);
    b.push(depth as u8);
    b.extend_from_slice(&binary_root.0);
    Digest::derive(context::NODE, &b)
}

/// A node of the ledger tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Its depth (the length of its nibble path).
    pub depth: usize,
    /// The 16 slots.
    pub slots: [Slot; 16],
}

impl Node {
    fn empty(depth: usize) -> Node {
        Node {
            depth,
            slots: [Slot::Empty; 16],
        }
    }

    fn slot_hashes(&self) -> [Digest; 16] {
        let mut out = [Digest::ZERO; 16];
        for (o, s) in out.iter_mut().zip(&self.slots) {
            *o = slot_hash(s);
        }
        out
    }

    /// The node hash.
    pub fn hash(&self) -> Digest {
        let levels = binary_levels(&self.slot_hashes());
        node_hash_from_root(self.depth, &levels[4][0])
    }

    /// Wire form `{ "v": 1, "d": depth, "o": occupied, "r": record slots, "s": […] }`.
    pub fn encode(&self) -> Vec<u8> {
        let (mut o, mut r) = (0u64, 0u64);
        let mut s = Vec::new();
        for (i, slot) in self.slots.iter().enumerate() {
            match slot {
                Slot::Empty => {}
                Slot::Record(k, id) => {
                    o |= 1 << i;
                    r |= 1 << i;
                    s.push(Value::Array(vec![
                        Value::Uint(*k as u64),
                        Value::Bytes(id.0.to_vec()),
                    ]));
                }
                Slot::Child(h) => {
                    o |= 1 << i;
                    s.push(Value::Bytes(h.0.to_vec()));
                }
            }
        }
        let mut m = Map::new();
        m.insert("v", Value::Uint(1))
            .insert("d", Value::Uint(self.depth as u64))
            .insert("o", Value::Uint(o))
            .insert("r", Value::Uint(r))
            .insert("s", Value::Array(s));
        cbor::encode(&Value::Map(m))
    }

    /// Decodes a node received for nibble path `path`, with every receiver check
    /// of design 0003 §4.3 except the hash (compare [`Node::hash`] with the expected
    /// slot hash where one is known).
    pub fn decode_at(bytes: &[u8], path: &[u8]) -> Result<Node, FormatError> {
        let bad = |why: &str| FormatError::Invalid(format!("ledger node: {why}"));
        if path.len() >= MAX_DEPTH {
            return Err(bad("too deep"));
        }
        let value = cbor::decode(bytes)?;
        let f = Fields::new("ledger node", &value, &["v", "d", "o", "r", "s"])?;
        f.version(1)?;
        if f.uint("d")? != path.len() as u64 {
            return Err(bad("depth doesn't match the path"));
        }
        let (o, r) = (f.uint("o")?, f.uint("r")?);
        if o >> 16 != 0 || r & !o != 0 {
            return Err(bad("bitmaps"));
        }
        let s = f.array("s")?;
        if s.len() != o.count_ones() as usize {
            return Err(bad("slot count"));
        }
        let mut node = Node::empty(path.len());
        let mut items = s.iter();
        for i in 0..16usize {
            if o & (1 << i) == 0 {
                continue;
            }
            let item = items.next().expect("counted");
            node.slots[i] = if r & (1 << i) != 0 {
                let Value::Array(pair) = item else {
                    return Err(bad("record slot"));
                };
                let [Value::Uint(k), Value::Bytes(id)] = pair.as_slice() else {
                    return Err(bad("record slot"));
                };
                let kind = Kind::from_code(*k).ok_or_else(|| bad("kind"))?;
                let id = Digest(id.as_slice().try_into().map_err(|_| bad("id"))?);
                let mut p = path.to_vec();
                p.push(i as u8);
                if !has_prefix(&id, &p) {
                    return Err(bad("record outside its slot"));
                }
                Slot::Record(kind, id)
            } else {
                let Value::Bytes(h) = item else {
                    return Err(bad("child slot"));
                };
                Slot::Child(Digest(
                    h.as_slice().try_into().map_err(|_| bad("child hash"))?,
                ))
            };
        }
        // Canonical shape: a non-root node holds two or more records, so it has two
        // occupied slots or a single child.
        if !path.is_empty() {
            let occupied = o.count_ones();
            let single_child = occupied == 1 && r == 0;
            if occupied < 2 && !single_child {
                return Err(bad("non-root node with fewer than two records"));
            }
        }
        if cbor::encode(&value) != bytes {
            return Err(bad("not canonical"));
        }
        Ok(node)
    }
}

/// The root of a 16-ary sparse trie (the shape of §4.3) over `leaves`: distinct keys,
/// each with the hash of its slot, sorted by key. With `leaf_hash` slots this is the
/// ledger root; the reference index (design 0004 §4.1) uses it with its own slots.
pub fn sparse_root(leaves: &[(Digest, Digest)]) -> Digest {
    node_root(leaves, 0)
}

fn node_root(items: &[(Digest, Digest)], depth: usize) -> Digest {
    let mut slots = [Digest::ZERO; 16];
    let mut start = 0;
    while start < items.len() {
        let n = nibble(&items[start].0, depth);
        let mut end = start + 1;
        while end < items.len() && nibble(&items[end].0, depth) == n {
            end += 1;
        }
        slots[n as usize] = if end - start == 1 {
            items[start].1
        } else {
            node_root(&items[start..end], depth + 1)
        };
        start = end;
    }
    let levels = binary_levels(&slots);
    node_hash_from_root(depth, &levels[levels.len() - 1][0])
}

/// The terminal of a proof path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    /// The slot is empty.
    Empty,
    /// The slot holds this record.
    Record(Kind, Digest),
}

/// A path from the root to one slot: per level, the 4 sibling hashes inside the
/// node (bottom first), then what the slot holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Sibling hashes per level, root level first.
    pub levels: Vec<[Digest; 4]>,
    /// The slot at the end of the path.
    pub terminal: Terminal,
}

impl Proof {
    /// Recomputes the root this proof leads to for `id`'s path.
    fn root_for(&self, id: &Digest) -> Option<Digest> {
        if self.levels.is_empty() || self.levels.len() > MAX_DEPTH {
            return None;
        }
        let mut h = match self.terminal {
            Terminal::Empty => Digest::ZERO,
            Terminal::Record(k, rid) => leaf_hash(k, &rid),
        };
        for depth in (0..self.levels.len()).rev() {
            let mut index = nibble(id, depth) as usize;
            for sib in &self.levels[depth] {
                h = if index.is_multiple_of(2) {
                    pair(&h, sib)
                } else {
                    pair(sib, &h)
                };
                index /= 2;
            }
            h = node_hash_from_root(depth, &h);
        }
        Some(h)
    }

    /// Does this proof show that record `(kind, id)` is in the ledger with `root`?
    pub fn proves_inclusion(&self, root: &Digest, kind: Kind, id: &Digest) -> bool {
        self.terminal == Terminal::Record(kind, *id) && self.root_for(id) == Some(*root)
    }

    /// Does this proof show that no record with `id` is in the ledger with `root`?
    pub fn proves_absence(&self, root: &Digest, id: &Digest) -> bool {
        // An id has 64 nibbles: a longer path can't be one (and would index past it).
        if self.levels.is_empty() || self.levels.len() > MAX_DEPTH {
            return false;
        }
        let terminal_ok = match self.terminal {
            Terminal::Empty => true,
            // Another record in the slot `id` would occupy: it shares the path.
            Terminal::Record(_, other) => {
                other != *id && has_prefix(&other, &path_of(id, self.levels.len()))
            }
        };
        terminal_ok && self.root_for(id) == Some(*root)
    }
}

fn path_of(id: &Digest, len: usize) -> Vec<u8> {
    (0..len).map(|d| nibble(id, d)).collect()
}

/// The ledger tree of one database: nodes by nibble path.
#[derive(Clone, Debug)]
pub struct Trie {
    nodes: HashMap<Vec<u8>, Node>,
    hashes: HashMap<Vec<u8>, Digest>,
    count: usize,
}

impl Default for Trie {
    fn default() -> Self {
        Trie::new()
    }
}

impl Trie {
    /// The empty ledger.
    pub fn new() -> Trie {
        let root = Node::empty(0);
        let h = root.hash();
        Trie {
            nodes: HashMap::from([(Vec::new(), root)]),
            hashes: HashMap::from([(Vec::new(), h)]),
            count: 0,
        }
    }

    /// Builds the trie of a set of records (any order).
    pub fn build(records: impl IntoIterator<Item = (Kind, Digest)>) -> Trie {
        let mut t = Trie::new();
        for (k, id) in records {
            t.insert(k, id);
        }
        t
    }

    /// The root hash.
    pub fn root(&self) -> Digest {
        self.hashes[&Vec::new()]
    }

    /// Number of records.
    pub fn count(&self) -> usize {
        self.count
    }

    /// The node at a nibble path, if one exists.
    pub fn node(&self, path: &[u8]) -> Option<&Node> {
        self.nodes.get(path)
    }

    /// The hash of the node at a nibble path.
    pub fn node_hash(&self, path: &[u8]) -> Option<Digest> {
        self.hashes.get(path).copied()
    }

    /// Every node, by path (for persistence).
    pub fn nodes(&self) -> impl Iterator<Item = (&Vec<u8>, &Node)> {
        self.nodes.iter()
    }

    /// Restores a trie from persisted nodes (trusted local data) and its count.
    pub fn from_nodes(nodes: HashMap<Vec<u8>, Node>, count: usize) -> Trie {
        let hashes = nodes.iter().map(|(p, n)| (p.clone(), n.hash())).collect();
        Trie {
            nodes,
            hashes,
            count,
        }
    }

    /// Is the record in the ledger?
    pub fn contains(&self, id: &Digest) -> bool {
        let mut path = Vec::new();
        loop {
            let Some(node) = self.nodes.get(&path) else {
                return false;
            };
            match node.slots[nibble(id, path.len()) as usize] {
                Slot::Empty => return false,
                Slot::Record(_, r) => return r == *id,
                Slot::Child(_) => path.push(nibble(id, path.len())),
            }
        }
    }

    /// Adds a record. Returns the paths of the nodes that changed (deepest first),
    /// or an empty list if the record was already present.
    pub fn insert(&mut self, kind: Kind, id: Digest) -> Vec<Vec<u8>> {
        let mut path = Vec::new();
        let deepest = loop {
            let i = nibble(&id, path.len()) as usize;
            let node = self.nodes.get_mut(&path).expect("nodes on the path exist");
            match node.slots[i] {
                Slot::Empty => {
                    node.slots[i] = Slot::Record(kind, id);
                    break path;
                }
                Slot::Record(_, other) if other == id => return Vec::new(),
                Slot::Record(other_kind, other) => {
                    node.slots[i] = Slot::Child(Digest::ZERO); // rehashed below
                    let mut p = path.clone();
                    p.push(i as u8);
                    loop {
                        let d = p.len();
                        let (a, b) = (nibble(&id, d) as usize, nibble(&other, d) as usize);
                        let mut n = Node::empty(d);
                        if a == b {
                            n.slots[a] = Slot::Child(Digest::ZERO);
                            self.nodes.insert(p.clone(), n);
                            p.push(a as u8);
                        } else {
                            n.slots[a] = Slot::Record(kind, id);
                            n.slots[b] = Slot::Record(other_kind, other);
                            self.nodes.insert(p.clone(), n);
                            break;
                        }
                    }
                    break p;
                }
                Slot::Child(_) => path.push(i as u8),
            }
        };
        self.count += 1;
        let mut changed = Vec::with_capacity(deepest.len() + 1);
        for len in (0..=deepest.len()).rev() {
            let p = deepest[..len].to_vec();
            let h = self.nodes[&p].hash();
            self.hashes.insert(p.clone(), h);
            if len > 0 {
                let parent = self
                    .nodes
                    .get_mut(&deepest[..len - 1])
                    .expect("parent exists");
                parent.slots[deepest[len - 1] as usize] = Slot::Child(h);
            }
            changed.push(p);
        }
        changed
    }

    /// The proof of `id`'s slot: inclusion if it is present, absence otherwise.
    pub fn prove(&self, id: &Digest) -> Proof {
        let mut levels = Vec::new();
        let mut path = Vec::new();
        loop {
            let node = &self.nodes[&path];
            let i = nibble(id, path.len()) as usize;
            let bin = binary_levels(&node.slot_hashes());
            let mut sib = [Digest::ZERO; 4];
            let mut index = i;
            for (level, s) in sib.iter_mut().enumerate() {
                *s = bin[level][index ^ 1];
                index /= 2;
            }
            levels.push(sib);
            match node.slots[i] {
                Slot::Empty => {
                    return Proof {
                        levels,
                        terminal: Terminal::Empty,
                    };
                }
                Slot::Record(k, r) => {
                    return Proof {
                        levels,
                        terminal: Terminal::Record(k, r),
                    };
                }
                Slot::Child(_) => path.push(i as u8),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> Digest {
        Digest::derive("test id", &n.to_be_bytes())
    }

    fn with_prefix(prefix: &[u8], n: u64) -> Digest {
        let mut d = id(n);
        for (i, nb) in prefix.iter().enumerate() {
            let b = &mut d.0[i / 2];
            *b = if i % 2 == 0 {
                (*b & 0x0f) | (nb << 4)
            } else {
                (*b & 0xf0) | nb
            };
        }
        d
    }

    #[test]
    fn same_set_same_tree_in_any_order() {
        let mut ids: Vec<Digest> = (0..2_000).map(id).collect();
        // Records sharing long prefixes, the case revision 1 got wrong.
        ids.push(with_prefix(&[0xa, 0xb, 0x0], 1));
        ids.push(with_prefix(&[0xa, 0xb, 0x1], 2));
        ids.push(with_prefix(&[3; 20], 3));
        ids.push(with_prefix(&[3; 20], 4));
        let a = Trie::build(ids.iter().map(|i| (Kind::Entry, *i)));
        let mut rev = ids.clone();
        rev.reverse();
        let b = Trie::build(rev.iter().map(|i| (Kind::Entry, *i)));
        let mut shuffled = ids.clone();
        shuffled.sort_by_key(|d| d.0[7]);
        let c = Trie::build(shuffled.iter().map(|i| (Kind::Entry, *i)));
        assert_eq!(a.root(), b.root());
        assert_eq!(a.root(), c.root());
        assert_eq!(a.count(), ids.len());
        let mut pa: Vec<_> = a.nodes().map(|(p, n)| (p.clone(), n.hash())).collect();
        let mut pb: Vec<_> = b.nodes().map(|(p, n)| (p.clone(), n.hash())).collect();
        pa.sort();
        pb.sort();
        assert_eq!(pa, pb, "the same nodes at every path");
        // Duplicates change nothing.
        let mut d = a.clone();
        assert!(d.insert(Kind::Entry, ids[5]).is_empty());
        assert_eq!(d.root(), a.root());
    }

    #[test]
    fn kinds_change_the_root() {
        let a = Trie::build([(Kind::Entry, id(1))]);
        let b = Trie::build([(Kind::Void, id(1))]);
        assert_ne!(a.root(), b.root());
        assert_ne!(Trie::new().root(), a.root());
    }

    #[test]
    fn nodes_roundtrip_and_receiver_checks() {
        let t = Trie::build((0..300).map(|n| (Kind::Entry, id(n))).chain([
            (Kind::Entry, with_prefix(&[3; 20], 3)),
            (Kind::Void, with_prefix(&[3; 20], 4)),
        ]));
        for (p, n) in t.nodes() {
            let bytes = n.encode();
            assert_eq!(&Node::decode_at(&bytes, p).unwrap(), n, "path {p:?}");
            assert_eq!(n.hash(), t.node_hash(p).unwrap());
            // Presented at the wrong path: refused.
            let mut other = p.clone();
            other.push(0);
            assert!(Node::decode_at(&bytes, &other).is_err());
        }
        // A single-slot node exists (records sharing 20 nibbles) and is accepted.
        assert!(
            t.node(&[3; 19])
                .is_some_and(|n| n.slots.iter().filter(|s| **s != Slot::Empty).count() == 1)
        );
        // A non-root node with a single record slot is not canonical.
        let mut lonely = Node::empty(1);
        lonely.slots[0] = Slot::Record(Kind::Entry, with_prefix(&[5, 0], 9));
        assert!(Node::decode_at(&lonely.encode(), &[5]).is_err());
        // A record outside its slot.
        let mut wrong = Node::empty(1);
        wrong.slots[0] = Slot::Record(Kind::Entry, with_prefix(&[5, 1], 9));
        wrong.slots[1] = Slot::Record(Kind::Entry, with_prefix(&[5, 1], 8));
        assert!(Node::decode_at(&wrong.encode(), &[5]).is_err());
    }

    #[test]
    fn proof_depth_is_bounded() {
        let t = Trie::build((0..5u64).map(|i| (Kind::Entry, id(i))));
        let mut p = t.prove(&id(100));
        p.levels = vec![[Digest::ZERO; 4]; MAX_DEPTH + 1];
        p.terminal = Terminal::Record(Kind::Entry, id(1));
        assert!(!p.proves_absence(&t.root(), &id(100)), "no panic, no proof");
        p.levels.clear();
        assert!(!p.proves_absence(&t.root(), &id(100)));
        assert!(!p.proves_inclusion(&t.root(), Kind::Entry, &id(1)));
    }

    #[test]
    fn proofs() {
        let ids: Vec<Digest> = (0..5_000)
            .map(id)
            .chain([with_prefix(&[3; 20], 3), with_prefix(&[3; 20], 4)])
            .collect();
        let t = Trie::build(ids.iter().map(|i| (Kind::Entry, *i)));
        let root = t.root();
        for i in ids.iter().step_by(97).chain([&ids[5_000], &ids[5_001]]) {
            let p = t.prove(i);
            assert!(p.proves_inclusion(&root, Kind::Entry, i));
            assert!(!p.proves_inclusion(&root, Kind::Void, i));
            assert!(!p.proves_absence(&root, i));
            assert!(
                !p.proves_inclusion(&Trie::new().root(), Kind::Entry, i),
                "wrong root"
            );
            let mut tampered = p.clone();
            tampered.levels[0][0].0[0] ^= 1;
            assert!(!tampered.proves_inclusion(&root, Kind::Entry, i));
        }
        for n in 10_000..10_050 {
            let missing = id(n);
            let p = t.prove(&missing);
            assert!(p.proves_absence(&root, &missing));
            assert!(!p.proves_inclusion(&root, Kind::Entry, &missing));
        }
        // An absence proof through the single-slot nodes.
        let near = with_prefix(&[3; 20], 77);
        assert!(t.prove(&near).proves_absence(&root, &near));
        // A record's own proof is not an absence proof for another id on another path.
        let p = t.prove(&ids[0]);
        assert!(!p.proves_absence(&root, &ids[1]));
    }

    #[test]
    fn insert_reports_changed_paths() {
        let mut t = Trie::new();
        assert_eq!(
            t.insert(Kind::Entry, with_prefix(&[1, 2], 1)),
            vec![Vec::<u8>::new()]
        );
        let changed = t.insert(Kind::Entry, with_prefix(&[1, 2], 2));
        assert_eq!(
            changed.first().map(Vec::len),
            Some(2),
            "split down to the shared prefix"
        );
        assert_eq!(changed.last(), Some(&Vec::new()));
    }
}
