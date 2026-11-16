//! The Sameroot replication protocol, version 5 (design 0003 §7, design 0004).
//!
//! One session replicates one database's ledger over any bidirectional byte
//! stream; this crate knows nothing about iroh. Values are not its business beyond
//! the small ones that ride inline: the node keeps values in a blob store (the
//! [`Values`] trait) and fetches the rest by hash on its own, with iroh-blobs.
//!
//! 1. `hello` both ways: protocol version, a nonce, the database, whether the sender
//!    still needs the genesis, and its clock.
//! 2. `root` both ways: the ledger root and record count; again when the root
//!    changes, at most once per second.
//! 3. A side whose root differs from the peer's **pulls**: `getNodes` by nibble path
//!    from the root down. Each received node is compared slot by slot with its own
//!    node at the same path: equal hashes are skipped, a record it lacks is wanted,
//!    any other child is walked. Nodes are addressed by path and the ledger only
//!    grows, so there are no stale walks: a moved tree just shows more.
//! 4. `want` → `records`, each with the certificates of its chain; the store admits
//!    them. A put's value up to [`INLINE_VALUE`] travels inside its record; for a
//!    larger one (or one the sender lacks) the session reports
//!    [`Event::MissingValue`], and the node fetches it by hash from any peer that
//!    holds it (design 0003 §3, §7.1.6). Version 3 also carried values in
//!    `getValues` → `values`; version 4 leaves that to the blob protocol.
//! 5. Each side pulls at most once per `(own root, peer root)` pair; a pull that runs
//!    out of budget ends incomplete and the next pull starts from the root again.
//! 6. **Push:** a node sends fresh records (its own writes, and records it just
//!    admitted from another peer) to its sessions at once, as an unrequested
//!    `records` frame. That is half a round trip instead of a walk; the walk remains
//!    the way to catch up on everything else.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sameroot_core::cbor::{self, Map, Value};
use sameroot_core::ledger::{Kind, MAX_DEPTH, Node, Slot};
use sameroot_core::{Digest, Op, Reject, SignedCert, SignedForward, SignedGenesis, now_ms};
use sameroot_store::{Outcome, Record, Store};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// Protocol version (3: the ledger trie; 4: values beyond inline ones leave the
/// protocol for the blob store; 5: design 0004 records: voids with keep lists, key
/// voids, forwards).
pub const PROTOCOL_VERSION: u64 = 5;
/// Largest frame accepted.
pub const MAX_FRAME: usize = 16 << 20;
/// Paths per `getNodes` request.
pub const NODES_PER_REQUEST: usize = 64;
/// Ids per `want` request.
pub const IDS_PER_REQUEST: usize = 1024;
/// Largest response frame we build; responses are split to stay under it.
pub const RESPONSE_BUDGET: usize = 8 << 20;
/// Most nodes walked in one pull.
pub const MAX_NODES_PER_PULL: usize = 1_000_000;
/// Cap on per-session id sets (negative cache, wanted, queue).
pub const MAX_SESSION_IDS: usize = 100_000;
/// Most encoded bytes waiting for the writer; a peer that requests more than it
/// reads is dropped instead of growing our memory.
pub const MAX_OUTBOX: usize = 256 << 20;
/// Values up to this size travel inline with their record (no second round trip);
/// larger ones are fetched from the blob store of a peer.
pub const INLINE_VALUE: u64 = 64 * 1024;
/// Minimum time between two `root` messages.
pub const ROOT_INTERVAL: Duration = Duration::from_millis(100);
/// Period of the session's housekeeping (deferred entries, retries).
pub const TICK: Duration = Duration::from_secs(1);
/// How long a closing session may flush what it queued for the peer.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Ticks between asking again for records that arrived without a dependency.
pub const RETRY_TICKS: u64 = 5;
/// Nodes per pull whose hash may differ from their parent's slot before the pull
/// stops.
pub const MAX_MISMATCHES: usize = 16;
/// Most forwards a stub hands out (more than one is already a visible fork).
pub const MAX_STUB_FORWARDS: usize = 16;

/// The node's values by plain BLAKE3 (design 0003 §3). A session reads them to send
/// small values inline and stores the inline values it receives; everything else
/// about values (serving them, fetching large ones) is the node's.
pub trait Values: Clone + Send + Sync + 'static {
    /// The value with this hash, if held in full.
    fn get(&self, hash: Digest) -> impl Future<Output = std::io::Result<Option<Vec<u8>>>> + Send;
    /// True if the value with this hash is held in full.
    fn has(&self, hash: Digest) -> impl Future<Output = std::io::Result<bool>> + Send;
    /// Stores a value; the caller has checked it against its signed hash.
    fn put(&self, value: Vec<u8>) -> impl Future<Output = std::io::Result<()>> + Send;
}

/// Values in memory, for tests, simulations and benchmarks.
#[derive(Clone, Default)]
pub struct MemValues(Arc<Mutex<HashMap<Digest, Vec<u8>>>>);

impl MemValues {
    /// An empty value store.
    pub fn new() -> MemValues {
        MemValues::default()
    }

    /// Stores a value now; returns its hash.
    pub fn insert(&self, value: &[u8]) -> Digest {
        let h = sameroot_core::value_hash(value);
        self.map().insert(h, value.to_vec());
        h
    }

    /// True if the value with this hash is held.
    pub fn contains(&self, hash: &Digest) -> bool {
        self.map().contains_key(hash)
    }

    /// The value with this hash, if held.
    pub fn value(&self, hash: &Digest) -> Option<Vec<u8>> {
        self.map().get(hash).cloned()
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<Digest, Vec<u8>>> {
        self.0.lock().expect("values mutex poisoned")
    }
}

impl Values for MemValues {
    async fn get(&self, hash: Digest) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.value(&hash))
    }

    async fn has(&self, hash: Digest) -> std::io::Result<bool> {
        Ok(self.contains(&hash))
    }

    async fn put(&self, value: Vec<u8>) -> std::io::Result<()> {
        self.insert(&value);
        Ok(())
    }
}

/// Session errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The stream failed or closed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The peer sent something outside the protocol.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] sameroot_store::Error),
    /// The peer doesn't serve this database.
    #[error("peer refused: {0}")]
    Refused(String),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// What a session reports to its node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The database's genesis arrived and was stored.
    Joined(Digest),
    /// A record was admitted into the ledger through this session.
    Added {
        /// Database.
        db: Digest,
        /// Record id.
        id: Digest,
    },
    /// Both sides have the same root.
    InSync(Digest),
    /// A put was admitted through this session without its value (too large to
    /// travel inline, or the sender lacks it): fetch it by hash.
    MissingValue {
        /// Database.
        db: Digest,
        /// The value's hash (plain BLAKE3, as for iroh-blobs).
        hash: Digest,
        /// Its size as the signed record states it: fetch nothing larger.
        size: u64,
    },
}

enum Control {
    Resync,
    Push(Vec<Digest>),
}

/// Handle to a running session.
#[derive(Clone)]
pub struct Session {
    alive: Arc<AtomicBool>,
    control: mpsc::UnboundedSender<Control>,
}

impl Session {
    /// Sends the current root again.
    pub fn resync(&self) -> bool {
        self.is_open() && self.control.send(Control::Resync).is_ok()
    }

    /// Sends these records (with their chains) to the peer now, then the root:
    /// call after a local write, or after admitting records from another peer.
    pub fn push(&self, ids: Vec<Digest>) -> bool {
        self.is_open() && self.control.send(Control::Push(ids)).is_ok()
    }

    /// True while the session is running.
    pub fn is_open(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

fn protocol(msg: &str) -> Error {
    Error::Protocol(msg.to_owned())
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Value> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(protocol("frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    cbor::decode(&buf).map_err(|e| Error::Protocol(format!("frame: {e}")))
}

fn msg(t: &str) -> Map {
    let mut m = Map::new();
    m.insert("t", Value::Text(t.to_owned()));
    m
}

fn get<'a>(m: &'a Map, k: &str) -> Result<&'a Value> {
    m.get(k)
        .ok_or_else(|| Error::Protocol(format!("missing {k}")))
}

fn uint(m: &Map, k: &str) -> Result<u64> {
    match get(m, k)? {
        Value::Uint(n) => Ok(*n),
        _ => Err(Error::Protocol(format!("{k}: not an integer"))),
    }
}

fn bytes<'a>(m: &'a Map, k: &str) -> Result<&'a [u8]> {
    match get(m, k)? {
        Value::Bytes(b) => Ok(b),
        _ => Err(Error::Protocol(format!("{k}: not bytes"))),
    }
}

fn digest_of(b: &[u8]) -> Result<Digest> {
    Ok(Digest(b.try_into().map_err(|_| protocol("bad digest"))?))
}

fn array<'a>(m: &'a Map, k: &str) -> Result<&'a [Value]> {
    match get(m, k)? {
        Value::Array(a) => Ok(a),
        _ => Err(Error::Protocol(format!("{k}: not an array"))),
    }
}

fn ids_of(m: &Map, k: &str) -> Result<Vec<Digest>> {
    let ids = array(m, k)?;
    if ids.len() > IDS_PER_REQUEST {
        return Err(protocol("too many ids"));
    }
    ids.iter()
        .map(|v| match v {
            Value::Bytes(b) => digest_of(b),
            _ => Err(protocol("id")),
        })
        .collect()
}

fn ids_value(ids: &[Digest]) -> Value {
    Value::Array(ids.iter().map(|d| Value::Bytes(d.0.to_vec())).collect())
}

fn path_ok(p: &[u8]) -> bool {
    p.len() < MAX_DEPTH && p.iter().all(|n| *n < 16)
}

/// Splits `items` into frames of type `t` under [`RESPONSE_BUDGET`]; the last frame
/// carries `done: true`. An item larger than the budget travels alone.
fn split_frames(t: &str, field: &str, items: Vec<Value>) -> Vec<Value> {
    let mut frames = Vec::new();
    let mut current = Vec::new();
    let mut size = 0;
    for item in items {
        let n = cbor::encode(&item).len();
        if !current.is_empty() && size + n > RESPONSE_BUDGET {
            frames.push(std::mem::take(&mut current));
            size = 0;
        }
        size += n;
        current.push(item);
    }
    frames.push(current);
    let last = frames.len() - 1;
    frames
        .into_iter()
        .enumerate()
        .map(|(i, items)| {
            let mut m = msg(t);
            m.insert(field, Value::Array(items))
                .insert("done", Value::Bool(i == last));
            Value::Map(m)
        })
        .collect()
}

fn records_frame(items: Vec<Value>, done: bool) -> Value {
    let mut m = msg("records");
    m.insert("records", Value::Array(items))
        .insert("done", Value::Bool(done));
    Value::Map(m)
}

fn is_done(m: &Map) -> bool {
    !matches!(m.get("done"), Some(Value::Bool(false)))
}

struct State {
    store: Arc<Mutex<Store>>,
    db: Digest,
    /// Record ids refused for good in this session (the negative cache).
    refused: HashSet<Digest>,
    /// The peer's last root.
    peer_root: Option<Digest>,
    /// The (own root, peer root) pair the last pull was started for.
    pulled_for: Option<(Digest, Digest)>,
    /// Paths requested and not yet answered.
    pending: HashSet<Vec<u8>>,
    /// The hash each requested node must have: the peer's root for the root, its
    /// parent's slot for the rest (design 0003 §4.3).
    expected: HashMap<Vec<u8>, Digest>,
    /// Nodes of this pull whose hash didn't match.
    mismatched: usize,
    /// Outstanding `getNodes` batches, oldest first.
    batches: VecDeque<Vec<Vec<u8>>>,
    /// Paths still to request.
    queue: Vec<Vec<u8>>,
    /// Nodes walked in the current pull.
    walked: usize,
    /// The current pull ran out of budget.
    incomplete: bool,
    /// Records that arrived without a dependency (a certificate, a keep list): asked
    /// for again every [`RETRY_TICKS`] ticks, with their dependencies.
    retry: HashSet<Digest>,
    /// Record ids currently asked for.
    wanted: HashSet<Digest>,
    /// When the last `root` went out, and whether a newer one is due.
    root_sent: Option<Instant>,
    root_dirty: bool,
}

impl State {
    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().expect("store mutex poisoned")
    }

    /// The peer serves only the stub of a retired database: admit its forwards
    /// (after its genesis, if this side lacks it), then the session ends.
    async fn take_stub(
        &mut self,
        forwards: &[Value],
        have_genesis: bool,
        events: &mpsc::UnboundedSender<Event>,
        in_rx: &mut mpsc::Receiver<Result<Value>>,
    ) -> Result<()> {
        if !have_genesis {
            let f = in_rx
                .recv()
                .await
                .ok_or_else(|| protocol("closed before the genesis"))??;
            let Value::Map(m) = f else {
                return Err(protocol("frame is not a map"));
            };
            let g = SignedGenesis::decode(bytes(&m, "g")?)
                .map_err(|e| Error::Protocol(format!("genesis: {e}")))?;
            if g.id() != self.db {
                return Err(protocol("genesis of another database"));
            }
            self.lock().add_database(&g)?;
            let _ = events.send(Event::Joined(self.db));
        }
        for f in forwards.iter().take(MAX_STUB_FORWARDS) {
            let Value::Bytes(b) = f else {
                return Err(protocol("forward"));
            };
            let f =
                SignedForward::decode(b).map_err(|e| Error::Protocol(format!("forward: {e}")))?;
            if f.forward.db != self.db {
                return Err(protocol("forward of another database"));
            }
            match self.lock().insert_forward(&f) {
                Ok(Outcome::Added) => {
                    let _ = events.send(Event::Added {
                        db: self.db,
                        id: f.id(),
                    });
                }
                Ok(_) => {}
                Err(sameroot_store::Error::Rejected(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn root_msg(&mut self) -> Result<Value> {
        let (count, root) = self.lock().root(&self.db)?;
        self.root_sent = Some(Instant::now());
        self.root_dirty = false;
        let mut m = msg("root");
        m.insert("hash", Value::Bytes(root.0.to_vec()))
            .insert("count", Value::Uint(count as u64));
        Ok(Value::Map(m))
    }

    /// The root message if one may go out now; otherwise marks it due.
    fn root_if_due(&mut self) -> Result<Option<Value>> {
        if self.root_sent.is_some_and(|t| t.elapsed() < ROOT_INTERVAL) {
            self.root_dirty = true;
            return Ok(None);
        }
        self.root_msg().map(Some)
    }

    fn pulling(&self) -> bool {
        !self.pending.is_empty() || !self.queue.is_empty()
    }

    fn start_pull(&mut self) -> Result<bool> {
        if self.pulling() {
            return Ok(false);
        }
        let Some(peer) = self.peer_root else {
            return Ok(false);
        };
        let (_, mine) = self.lock().root(&self.db)?;
        if mine == peer || (self.pulled_for == Some((mine, peer)) && !self.incomplete) {
            return Ok(false);
        }
        self.pulled_for = Some((mine, peer));
        self.walked = 0;
        self.incomplete = false;
        self.queue = vec![Vec::new()];
        self.expected.clear();
        self.expected.insert(Vec::new(), peer);
        self.mismatched = 0;
        Ok(true)
    }

    fn pull_request(&mut self) -> Result<Option<Value>> {
        if self.start_pull()? {
            Ok(self.next_request())
        } else {
            Ok(None)
        }
    }

    fn next_request(&mut self) -> Option<Value> {
        if self.queue.is_empty() {
            return None;
        }
        let n = self.queue.len().min(NODES_PER_REQUEST);
        let batch: Vec<Vec<u8>> = self.queue.drain(..n).collect();
        for p in &batch {
            self.pending.insert(p.clone());
        }
        let mut m = msg("getNodes");
        m.insert(
            "paths",
            Value::Array(batch.iter().map(|p| Value::Bytes(p.clone())).collect()),
        );
        self.batches.push_back(batch);
        Some(Value::Map(m))
    }

    /// Answers `getNodes` from the current tree, split into frames.
    fn nodes_msgs(&self, paths: &[Vec<u8>]) -> Result<Vec<Value>> {
        let store = self.lock();
        let mut items = Vec::new();
        for p in paths {
            let mut item = Map::new();
            item.insert("p", Value::Bytes(p.clone()))
                .insert_opt("n", store.node(&self.db, p)?.map(Value::Bytes));
            items.push(Value::Map(item));
        }
        Ok(split_frames("nodes", "nodes", items))
    }

    /// Compares received nodes with ours: queues differing children and returns the
    /// record ids to want. `done` closes the oldest request batch.
    fn walk(&mut self, list: &[Value], done: bool) -> Result<Vec<Digest>> {
        let mut want = Vec::new();
        for item in list {
            let Value::Map(m) = item else {
                return Err(protocol("node item"));
            };
            let path = bytes(m, "p")?.to_vec();
            if !self.pending.remove(&path) {
                continue; // not (or no longer) requested
            }
            let Some(Value::Bytes(nb)) = m.get("n") else {
                continue;
            }; // no node there
            let node =
                Node::decode_at(nb, &path).map_err(|e| Error::Protocol(format!("node: {e}")))?;
            // A node that doesn't hash to what its parent (or the root) promised: the
            // peer's tree moved since, or the peer is lying. Not walked; a few such
            // nodes end the pull, and the next root starts a fresh one.
            if let Some(h) = self.expected.remove(&path)
                && node.hash() != h
            {
                self.mismatched += 1;
                self.incomplete = true;
                if self.mismatched > MAX_MISMATCHES {
                    self.queue.clear();
                }
                continue;
            }
            self.walked += 1;
            let mine = self.lock().local_node(&self.db, &path)?;
            for (i, slot) in node.slots.iter().enumerate() {
                let own = mine.as_ref().map(|n| n.slots[i]);
                match slot {
                    Slot::Empty => {}
                    Slot::Record(_, id) => {
                        if own == Some(*slot)
                            || self.refused.contains(id)
                            || self.wanted.contains(id)
                        {
                            continue;
                        }
                        if self.lock().record(&self.db, id)?.is_none()
                            && self.wanted.len() < MAX_SESSION_IDS
                        {
                            self.wanted.insert(*id);
                            want.push(*id);
                        }
                    }
                    Slot::Child(h) => {
                        if own == Some(Slot::Child(*h)) {
                            continue; // the whole subtree is equal
                        }
                        let mut child = path.clone();
                        child.push(i as u8);
                        if self.walked + self.queue.len() + self.pending.len() >= MAX_NODES_PER_PULL
                            || self.queue.len() >= MAX_SESSION_IDS
                        {
                            self.incomplete = true;
                        } else {
                            self.expected.insert(child.clone(), *h);
                            self.queue.push(child);
                        }
                    }
                }
            }
        }
        if done && let Some(batch) = self.batches.pop_front() {
            for p in batch {
                self.pending.remove(&p);
            }
        }
        Ok(want)
    }

    /// Answers `want` with records of this database, their chains, and small values
    /// inline.
    async fn records_msgs<V: Values>(
        &self,
        values: &V,
        ids: &[Digest],
        send: &(dyn Fn(Value) -> Result<()> + Sync),
    ) -> Result<()> {
        // Built and sent a frame at a time, each record read on its own, so memory is
        // bounded by one frame plus the outbox cap, whatever the peer asks for; repeated
        // ids are answered once.
        let mut seen = HashSet::new();
        let mut items = Vec::new();
        let mut size = 0;
        for id in ids.iter().filter(|id| seen.insert(**id)) {
            let found = {
                let store = self.lock();
                match store.record(&self.db, id)? {
                    None => None,
                    Some(r) => {
                        let chain: Vec<Value> = store
                            .dependencies(&r)?
                            .iter()
                            .map(|c| Value::Bytes(c.encode()))
                            .collect();
                        // A void's keep list travels with it (design 0004 §5.4).
                        let keep: Option<Vec<u8>> = match &r {
                            Record::Void(_) => store
                                .keep_list(id)?
                                .map(|ids| ids.iter().flat_map(|d| d.0).collect()),
                            _ => None,
                        };
                        Some((r, chain, keep))
                    }
                }
            };
            let Some((r, chain, keep)) = found else {
                continue;
            };
            let inline = match &r {
                Record::Entry(e)
                    if e.header.op == Op::Put && e.header.value_size <= INLINE_VALUE =>
                {
                    values.get(e.header.value_hash).await?
                }
                _ => None,
            };
            let mut m = Map::new();
            m.insert("k", Value::Uint(r.kind() as u64))
                .insert("r", Value::Bytes(r.encode()))
                .insert_opt("v", inline.map(Value::Bytes))
                .insert_opt("kl", keep.map(Value::Bytes))
                .insert("c", Value::Array(chain));
            let item = Value::Map(m);
            let n = cbor::encode(&item).len();
            if !items.is_empty() && size + n > RESPONSE_BUDGET {
                send(records_frame(std::mem::take(&mut items), false))?;
                size = 0;
            }
            size += n;
            items.push(item);
        }
        send(records_frame(items, true))
    }

    /// Admits received records and stores their inline values; returns the ids added
    /// and the value hashes of added puts that are still missing.
    async fn accept<V: Values>(
        &mut self,
        values: &V,
        list: &[Value],
    ) -> Result<(Vec<Digest>, Vec<(Digest, u64)>)> {
        let mut added = Vec::new();
        let mut missing = Vec::new();
        let now = now_ms();
        // Decoded first; admitted together, in one store transaction; values after.
        let mut decoded = Vec::with_capacity(list.len());
        for v in list {
            let Value::Map(m) = v else {
                return Err(protocol("record"));
            };
            let kind = Kind::from_code(uint(m, "k")?).ok_or_else(|| protocol("record kind"))?;
            let record = Record::decode(kind, bytes(m, "r")?)
                .map_err(|e| Error::Protocol(format!("record: {e}")))?;
            let id = record.id();
            self.wanted.remove(&id);
            let certs: Vec<SignedCert> = array(m, "c")?
                .iter()
                .filter_map(|c| match c {
                    Value::Bytes(b) => SignedCert::decode(b).ok(),
                    _ => None,
                })
                .take(sameroot_core::cert::MAX_CHAIN)
                .collect();
            let keep: Option<Vec<Digest>> = match m.get("kl") {
                Some(Value::Bytes(b)) if b.len() % 32 == 0 => Some(
                    b.chunks(32)
                        .map(|c| Digest(c.try_into().expect("32 bytes")))
                        .collect(),
                ),
                Some(_) => return Err(protocol("keep list")),
                None => None,
            };
            decoded.push((m, record, id, certs, keep));
        }
        let outcomes = {
            let store = self.lock();
            store.batch(|store| {
                decoded
                    .iter()
                    .map(|(_, record, _, certs, keep)| match record {
                        Record::Entry(e) if e.header.db == self.db => {
                            store.insert_entry(e, certs, now)
                        }
                        Record::Void(x) if x.void.db == self.db => {
                            store.insert_void(x, certs, keep.as_deref())
                        }
                        Record::Forward(f) if f.forward.db == self.db => store.insert_forward(f),
                        _ => Err(sameroot_store::Error::Rejected(Reject::WrongDatabase)),
                    })
                    .collect::<Vec<_>>()
            })?
        };
        for ((m, record, id, _, _), outcome) in decoded.into_iter().zip(outcomes) {
            // A deferred entry keeps its inline value too: it counts once its time comes.
            if let (
                Ok(o @ (Outcome::Added | Outcome::Duplicate | Outcome::Deferred)),
                Record::Entry(e),
            ) = (&outcome, &record)
                && e.header.op == Op::Put
                && !values.has(e.header.value_hash).await?
            {
                // An inline value is kept if it matches the signed hash and size.
                match m.get("v") {
                    Some(Value::Bytes(v)) if sameroot_core::verify_value(&e.header, v) => {
                        values.put(v.clone()).await?;
                    }
                    // A duplicate was reported when it was added.
                    _ if *o == Outcome::Added => {
                        missing.push((e.header.value_hash, e.header.value_size))
                    }
                    _ => {}
                }
            }
            match outcome {
                Ok(Outcome::Added) => added.push(id),
                Ok(_) => {}
                // A missing certificate or keep list may arrive from another peer or a
                // later pull.
                Err(sameroot_store::Error::Rejected(r)) if r.is_missing() => {
                    if self.retry.len() < MAX_SESSION_IDS {
                        self.retry.insert(id);
                    }
                }
                Err(sameroot_store::Error::Rejected(_)) => {
                    if self.refused.len() < MAX_SESSION_IDS {
                        self.refused.insert(id);
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok((added, missing))
    }
}

/// Encoded frames for the writer task, with the bytes still queued.
struct Outbox {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
}

impl Outbox {
    fn send(&self, v: &Value) -> Result<()> {
        let bytes = cbor::encode(v);
        if self.queued.fetch_add(bytes.len(), Ordering::SeqCst) + bytes.len() > MAX_OUTBOX {
            return Err(protocol("peer is not reading its responses"));
        }
        self.tx
            .send(bytes)
            .map_err(|_| Error::Io(std::io::ErrorKind::BrokenPipe.into()))
    }
}

/// Runs a session on `stream` for database `db` until the stream closes.
/// Hands a [`Session`] to `ready` at once and reports progress on `events`.
pub async fn run<S, V>(
    stream: S,
    store: Arc<Mutex<Store>>,
    values: V,
    db: Digest,
    events: mpsc::UnboundedSender<Event>,
    ready: tokio::sync::oneshot::Sender<Session>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    V: Values,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let queued = Arc::new(AtomicUsize::new(0));
    let outbox = Outbox {
        tx: out_tx,
        queued: queued.clone(),
    };
    let (control_tx, mut control_rx) = mpsc::unbounded_channel::<Control>();
    let alive = Arc::new(AtomicBool::new(true));
    let _ = ready.send(Session {
        alive: alive.clone(),
        control: control_tx,
    });

    // The writer runs until told to stop, so retained Session handles can't keep it
    // (and the connection) alive after the session ends.
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let writer_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                v = out_rx.recv() => match v {
                    Some(v) => {
                        let failed = write_frame(&mut writer, &v).await.is_err();
                        queued.fetch_sub(v.len(), Ordering::SeqCst);
                        if failed { break }
                    }
                    None => break,
                },
                _ = &mut stop_rx => {
                    while let Ok(v) = out_rx.try_recv() {
                        if write_frame(&mut writer, &v).await.is_err() { break }
                    }
                    break;
                }
            }
        }
        let _ = writer.shutdown().await;
    });
    // Frames are read by a task of their own: a read is never cancelled midway, so
    // timers and resyncs can't desynchronise the stream.
    let (in_tx, mut in_rx) = mpsc::channel::<Result<Value>>(16);
    let reader_task = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut reader).await;
            let end = frame.is_err();
            if in_tx.send(frame).await.is_err() || end {
                break;
            }
        }
    });

    let result = session(
        &store,
        &values,
        db,
        &events,
        &outbox,
        &mut in_rx,
        &mut control_rx,
    )
    .await;
    drop(outbox);

    alive.store(false, Ordering::SeqCst);
    let _ = stop_tx.send(());
    // A peer that stopped reading must not keep the writer (and its queue) alive:
    // flushing gets a deadline, then the writer is cut off.
    let mut writer_task = writer_task;
    if tokio::time::timeout(SHUTDOWN_GRACE, &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
    }
    reader_task.abort();
    result
}

async fn session<V: Values>(
    store: &Arc<Mutex<Store>>,
    values: &V,
    db: Digest,
    events: &mpsc::UnboundedSender<Event>,
    outbox: &Outbox,
    in_rx: &mut mpsc::Receiver<Result<Value>>,
    control_rx: &mut mpsc::UnboundedReceiver<Control>,
) -> Result<()> {
    let send = |v: Value| outbox.send(&v);
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).expect("random source");
    let (have_genesis, stub) = {
        let s = store.lock().expect("store");
        let have = s.genesis(&db)?.is_some();
        // A retired database is only its stub: it hands out its forwards and ends
        // the session (design 0004 §8.3 step 4).
        let stub = if s.retired(&db)?.is_some() {
            s.forwards(&db)?
        } else {
            Vec::new()
        };
        (have, stub)
    };
    let mut hello = msg("hello");
    hello
        .insert("v", Value::Uint(PROTOCOL_VERSION))
        .insert("nonce", Value::Bytes(nonce.to_vec()))
        .insert("db", Value::Bytes(db.0.to_vec()))
        .insert("needGenesis", Value::Bool(!have_genesis))
        .insert("clock", Value::Uint(now_ms()));
    if !stub.is_empty() {
        hello.insert(
            "forwards",
            Value::Array(stub.iter().map(|f| Value::Bytes(f.encode())).collect()),
        );
    }
    send(Value::Map(hello))?;

    let first = in_rx
        .recv()
        .await
        .ok_or_else(|| protocol("closed before hello"))??;
    let Value::Map(peer) = first else {
        return Err(protocol("hello"));
    };
    match get(&peer, "t")? {
        Value::Text(t) if t == "hello" => {}
        Value::Text(t) if t == "refuse" => {
            return Err(Error::Refused("database not served".into()));
        }
        _ => return Err(protocol("expected hello")),
    }
    if uint(&peer, "v")? != PROTOCOL_VERSION {
        return Err(protocol("protocol version mismatch"));
    }
    if digest_of(bytes(&peer, "db")?)? != db {
        send(Value::Map(msg("refuse")))?;
        return Err(Error::Refused("different database".into()));
    }
    let peer_needs_genesis = matches!(get(&peer, "needGenesis")?, Value::Bool(true));
    let mut st = State {
        store: store.clone(),
        db,
        refused: HashSet::new(),
        retry: HashSet::new(),
        peer_root: None,
        pulled_for: None,
        pending: HashSet::new(),
        expected: HashMap::new(),
        mismatched: 0,
        batches: VecDeque::new(),
        queue: Vec::new(),
        walked: 0,
        incomplete: false,
        wanted: HashSet::new(),
        root_sent: None,
        root_dirty: false,
    };

    if peer_needs_genesis {
        match st.lock().genesis(&db)? {
            Some(g) => {
                let mut m = msg("genesis");
                m.insert("g", Value::Bytes(g.encode()));
                send(Value::Map(m))?;
            }
            None => return Err(Error::Refused("neither side has the genesis".into())),
        }
    }
    if !stub.is_empty() {
        return Ok(());
    }
    if let Some(Value::Array(fs)) = peer.get("forwards") {
        return st.take_stub(fs, have_genesis, events, in_rx).await;
    }
    let mut ready_to_sync = have_genesis;
    let mut in_sync_at: Option<Digest> = None;
    if ready_to_sync {
        send(st.root_msg()?)?;
    }

    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ticks: u64 = 0;
    loop {
        // A coalesced root goes out when its window ends.
        let flush_at = st
            .root_dirty
            .then(|| {
                st.root_sent
                    .map(|t| tokio::time::Instant::from_std(t + ROOT_INTERVAL))
            })
            .flatten();
        let frame = tokio::select! {
            f = in_rx.recv() => match f {
                Some(f) => f,
                None => return Ok(()),
            },
            Some(c) = control_rx.recv() => {
                if !ready_to_sync {
                    continue;
                }
                if let Control::Push(ids) = c {
                    st.records_msgs(values, &ids, &send).await?;
                }
                if let Some(r) = st.root_if_due()? { send(r)?; }
                continue;
            }
            _ = async { tokio::time::sleep_until(flush_at.expect("guarded")).await }, if flush_at.is_some() => {
                if let Some(r) = st.root_if_due()? { send(r)?; }
                continue;
            }
            _ = tick.tick() => {
                ticks += 1;
                // Every RETRY_TICKS: ask again for records that came without a
                // dependency; the peer sends them with their chains and keep lists.
                if ready_to_sync && ticks.is_multiple_of(RETRY_TICKS) && !st.retry.is_empty() {
                    let ids: Vec<Digest> = st.retry.drain().collect();
                    for chunk in ids.chunks(IDS_PER_REQUEST) {
                        let mut w = msg("want");
                        w.insert("ids", ids_value(chunk));
                        send(Value::Map(w))?;
                    }
                }
                // Every 10 s: admit deferred entries whose time has come, and tell the
                // node, which sends them on to its other sessions.
                if ready_to_sync && ticks.is_multiple_of(10) {
                    let due = st.lock().admit_due(&db, now_ms())?;
                    if !due.is_empty() {
                        for id in due {
                            let _ = events.send(Event::Added { db, id });
                        }
                        if let Some(r) = st.root_if_due()? { send(r)?; }
                        if let Some(r) = st.pull_request()? { send(r)?; }
                    }
                }
                // Caught up: the root equals the peer's last one. Reported once per
                // root, also when the peer has no reason to send its root again.
                if ready_to_sync && let Some(peer) = st.peer_root {
                    let (_, mine) = st.lock().root(&db)?;
                    if mine == peer && in_sync_at != Some(mine) {
                        in_sync_at = Some(mine);
                        let _ = events.send(Event::InSync(db));
                    }
                }
                continue;
            }
        };
        let Value::Map(m) = (match frame {
            Ok(v) => v,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }) else {
            return Err(protocol("frame is not a map"));
        };
        let t = match get(&m, "t")? {
            Value::Text(t) => t.clone(),
            _ => return Err(protocol("type")),
        };
        match t.as_str() {
            "genesis" => {
                let g = SignedGenesis::decode(bytes(&m, "g")?)
                    .map_err(|e| Error::Protocol(format!("genesis: {e}")))?;
                if g.id() != db {
                    return Err(protocol("genesis of another database"));
                }
                st.lock().add_database(&g)?;
                let _ = events.send(Event::Joined(db));
                ready_to_sync = true;
                send(st.root_msg()?)?;
                if let Some(r) = st.pull_request()? {
                    send(r)?;
                }
            }
            "root" => {
                st.peer_root = Some(digest_of(bytes(&m, "hash")?)?);
                if !ready_to_sync {
                    continue;
                }
                let (_, mine) = st.lock().root(&db)?;
                if Some(mine) == st.peer_root {
                    let _ = events.send(Event::InSync(db));
                } else if let Some(r) = st.pull_request()? {
                    send(r)?;
                }
            }
            "getRoot" => send(st.root_msg()?)?,
            "getNodes" => {
                let paths: Vec<Vec<u8>> = array(&m, "paths")?
                    .iter()
                    .map(|v| match v {
                        Value::Bytes(b) if path_ok(b) => Ok(b.clone()),
                        _ => Err(protocol("path")),
                    })
                    .collect::<Result<_>>()?;
                if paths.len() > NODES_PER_REQUEST {
                    return Err(protocol("too many paths"));
                }
                for f in st.nodes_msgs(&paths)? {
                    send(f)?;
                }
            }
            "nodes" => {
                let done = is_done(&m);
                let want = st.walk(array(&m, "nodes")?, done)?;
                for chunk in want.chunks(IDS_PER_REQUEST) {
                    let mut w = msg("want");
                    w.insert("ids", ids_value(chunk));
                    send(Value::Map(w))?;
                }
                if done && st.batches.is_empty() {
                    match st.next_request() {
                        Some(r) => send(r)?,
                        None => {
                            // This pull is done (or ran out of budget): if the roots
                            // still differ, the next pull starts from the root.
                            if let Some(r) = st.pull_request()? {
                                send(r)?;
                            }
                        }
                    }
                }
            }
            "want" => {
                let ids = ids_of(&m, "ids")?;
                st.records_msgs(values, &ids, &send).await?;
            }
            "records" => {
                let (added, missing) = st.accept(values, array(&m, "records")?).await?;
                for id in &added {
                    let _ = events.send(Event::Added { db, id: *id });
                }
                for (hash, size) in missing {
                    let _ = events.send(Event::MissingValue { db, hash, size });
                }
                if !added.is_empty() {
                    if let Some(r) = st.root_if_due()? {
                        send(r)?;
                    }
                    if let Some(r) = st.pull_request()? {
                        send(r)?;
                    }
                }
            }
            "refuse" => return Err(Error::Refused("peer refused".into())),
            other => return Err(Error::Protocol(format!("unknown message {other}"))),
        }
    }
}
