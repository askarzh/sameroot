//! `samerootd` — the Sameroot node (`docs/design/0001-architecture.md` §4, §12, §14).
//!
//! The node:
//! - one iroh endpoint with a persisted key and two protocols on it: the ledger
//!   (ALPN `sameroot/sync/1`) and values (iroh-blobs);
//! - every bidirectional ledger stream starts with the 32-byte database id, then
//!   runs a `sameroot-sync` session; a node syncs only databases it holds;
//! - values live in an iroh-blobs store by their plain BLAKE3 `valueHash` and are
//!   served to anyone who asks by hash (design 0003 §3: the platform is open,
//!   applications encrypt). Small values also ride inline with their records; a
//!   put admitted without its value is fetched from the database's peers, verified
//!   while it streams, and resumed after a break; a sweep retries what is missing;
//! - writes are signed by the device key, under a delegation certificate when
//!   one is installed for the database;
//! - the local RPC on an owner-only Unix socket (`sameroot-rpc`);
//! - peers from invites are redialled while disconnected.
//!
//! State lives in `$SAMEROOT_HOME` (default `~/.sameroot`): `device.key`,
//! `endpoint.key` (raw 32-byte keys, mode 0600 — an encrypted keystore comes
//! later), `store.redb` (the ledger), `blobs/` (the values), `peers`, `writecerts`,
//! and the socket `samerootd.sock`.
//!
//! `SAMEROOT_RELAY` picks the relays (comma-separated URLs), or `none` for direct
//! connections only (tests, local networks).

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_blobs::api::downloader::Downloader;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::store::fs::options::Options as BlobOptions;
use iroh_blobs::store::{GcConfig, ProtectCb, ProtectOutcome};
use iroh_blobs::{BlobsProtocol, Hash};
use sameroot_core::cbor::{Map, Value};
use sameroot_core::ledger::{Kind, Trie};
use sameroot_core::resolve::Resolved;
use sameroot_core::succession;
use sameroot_core::{
    Area, Cert, Digest, Header, Keep, Op, Path, PublicKey, SecretKey, SignedCert, SignedEntry,
    SignedForward, SignedGenesis, SignedVoid, Subspace, Void, VoidTarget, now_ms, value_hash,
};
use sameroot_rpc::{Fields, Invite, err, ok};
use sameroot_store::{Outcome, Store};
use sameroot_sync::{Event, Session, Values};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};

const ALPN: &[u8] = b"sameroot/sync/1";

/// A value a ledger references: its hash and the size its record states.
type WantedValue = (Digest, u64);
const REDIAL: Duration = Duration::from_secs(15);
/// How often the node looks for values it should hold and doesn't.
const VALUE_SWEEP: Duration = Duration::from_secs(10);
/// A fetch that takes longer is dropped; the next one resumes where it stopped.
const FETCH_TIMEOUT: Duration = Duration::from_secs(600);
/// How long the size probe of a value (its last chunk) may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a succeeded database stays read-only before it may be collected
/// (design 0004 §8.3 step 3).
const GRACE: u64 = 14 * 24 * 3600 * 1000;
/// How often the blob store looks for values no database references any more
/// (`SAMEROOT_BLOB_GC_SECS` overrides it).
const BLOB_GC: Duration = Duration::from_secs(3600);

/// How long a node waits for a successor to catch up with a peer before following
/// it anyway.
const FOLLOW_WAIT: Duration = Duration::from_secs(120);

/// How long an agent's certificate lasts.
const AGENT_LIFETIME: u64 = 30 * 24 * 3600 * 1000;
/// An agent's certificate is renewed when it has less than this left.
const AGENT_RENEW: u64 = 7 * 24 * 3600 * 1000;

/// An entry with when this node first saw it.
type Seen = (SignedEntry, Option<u64>);

/// A signer of writes: the device, or an agent of it.
struct Writer {
    key: SecretKey,
    subspace: Subspace,
    /// The signer's certificate chain, leaf first (empty when the device writes its
    /// own subspace).
    chain: Vec<SignedCert>,
}

/// A keep list as concatenated 32-byte ids.
fn keep_ids(bytes: Option<&[u8]>) -> Result<Option<Vec<Digest>>, String> {
    match bytes {
        None => Ok(None),
        Some(b) if b.len() % 32 == 0 => Ok(Some(
            b.as_chunks::<32>().0.iter().map(|c| Digest(*c)).collect(),
        )),
        Some(_) => Err("bad keep list".into()),
    }
}

/// Most keys in one `list` page.
const LIST_LIMIT: usize = 1_000;
/// About the most value bytes in one `list` page (the RPC frame is 32 MiB).
const LIST_BUDGET: u64 = 16 << 20;
/// How long a new stream may take to name its database.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Most sync sessions at once.
const MAX_SESSIONS: usize = 256;
/// Most value fetches at once.
const MAX_FETCHES: usize = 8;
/// The longest wait before trying a value again.
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

fn log(msg: impl AsRef<str>) {
    eprintln!("[samerootd] {}", msg.as_ref());
}

fn home() -> PathBuf {
    std::env::var_os("SAMEROOT_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".sameroot"))
}

/// Loads a 32-byte key, or creates one if the file doesn't exist. Any other read
/// error is an error: a key is never replaced because it couldn't be read. A new key
/// is created owner-only from the start and synced before use.
fn load_or_create_key(path: &FsPath) -> std::io::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) => {
            return bytes.try_into().map_err(|_| {
                std::io::Error::other(format!("{} is not a 32-byte key", path.display()))
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(std::io::Error::other(format!(
                "{} can't be read: {e}",
                path.display()
            )));
        }
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(&seed)?;
    f.sync_all()?;
    Ok(seed)
}

/// Replaces the key at `path` with a new one, created as [`load_or_create_key`] does.
fn replace_key(path: &FsPath) -> std::io::Result<[u8; 32]> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    load_or_create_key(path)
}

/// A line-oriented `key value` file (peers, write certificates).
fn read_pairs(path: &FsPath) -> Vec<(String, String)> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(a, b)| (a.to_owned(), b.to_owned())))
        .collect()
}

fn add_pair(path: &FsPath, key: &str, value: &str, unique_key: bool) -> std::io::Result<()> {
    let mut pairs = read_pairs(path);
    if unique_key {
        pairs.retain(|(k, _)| k != key);
    }
    if !pairs.iter().any(|(k, v)| k == key && v == value) {
        pairs.push((key.to_owned(), value.to_owned()));
    }
    let body: String = pairs.iter().map(|(k, v)| format!("{k} {v}\n")).collect();
    // Written aside, synced, then renamed over the old file: a crash leaves either
    // the old or the new file, never a truncated one.
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

fn hash(d: &Digest) -> Hash {
    Hash::from_bytes(d.0)
}

/// Removes every line of `key` from a pair file.
fn remove_pairs(path: &FsPath, key: &str) -> std::io::Result<()> {
    let pairs: Vec<_> = read_pairs(path)
        .into_iter()
        .filter(|(k, _)| k != key)
        .collect();
    let body: String = pairs.iter().map(|(k, v)| format!("{k} {v}\n")).collect();
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// What the blob store's garbage collection must keep: every value an admitted put
/// of any database references, and the values being written now. It runs only once
/// some database was retired; before that nothing is collected at all. On any error
/// the run is skipped.
fn protect(
    store: Arc<Mutex<Store>>,
    writing: Arc<Mutex<HashSet<Digest>>>,
    held: Arc<Mutex<HashSet<Digest>>>,
) -> ProtectCb {
    Arc::new(move |live: &mut HashSet<Hash>| {
        let (store, writing, held) = (store.clone(), writing.clone(), held.clone());
        Box::pin(async move {
            let s = store.lock().expect("store mutex");
            let Ok(dbs) = s.databases() else {
                return ProtectOutcome::Abort;
            };
            let mut retired = false;
            for db in &dbs {
                match s.retired(db) {
                    Ok(r) => retired |= r.is_some(),
                    Err(_) => return ProtectOutcome::Abort,
                }
            }
            if !retired {
                return ProtectOutcome::Abort;
            }
            let now = now_ms();
            for db in &dbs {
                match s.live_values(db, now) {
                    Ok(v) => live.extend(v.iter().map(|(h, _)| hash(h))),
                    Err(_) => return ProtectOutcome::Abort,
                }
            }
            live.extend(writing.lock().expect("writing").iter().map(hash));
            // What the sweep remembers as held may be collected now.
            held.lock().expect("held").clear();
            ProtectOutcome::Continue
        })
    })
}

/// A late entry of a succeeded database (design 0004 §8.3 step 3).
struct Late {
    entry: SignedEntry,
    /// Written by this device or one of its agents.
    own: bool,
    /// Already re-submitted (or found superseded) in the successor.
    done: bool,
    /// The agent that wrote it, if one did.
    agent: Option<String>,
}

/// The node's values: an iroh-blobs store keyed by `valueHash` (plain BLAKE3, the
/// same hash). Its garbage collection removes only values no database references
/// any more, and runs only once a database was retired ([`protect`]).
#[derive(Clone)]
struct BlobValues(FsStore);

impl Values for BlobValues {
    async fn get(&self, h: Digest) -> std::io::Result<Option<Vec<u8>>> {
        if !self.has(h).await? {
            return Ok(None);
        }
        match self.0.get_bytes(hash(&h)).await {
            Ok(b) => Ok(Some(b.to_vec())),
            Err(e) => Err(std::io::Error::other(e.to_string())),
        }
    }

    async fn has(&self, h: Digest) -> std::io::Result<bool> {
        self.0
            .has(hash(&h))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    async fn put(&self, value: Vec<u8>) -> std::io::Result<()> {
        self.0
            .add_bytes(value)
            .temp_tag()
            .await
            .map(drop)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

struct Node {
    home: PathBuf,
    store: Arc<Mutex<Store>>,
    values: BlobValues,
    downloader: Downloader,
    device: SecretKey,
    endpoint: Endpoint,
    sessions: Mutex<Vec<(Digest, EndpointId, Session)>>,
    events: mpsc::UnboundedSender<Event>,
    /// Value hashes being fetched now.
    fetching: Mutex<HashSet<Digest>>,
    /// Value hashes known to be held, so the sweep doesn't ask the blob store again.
    held: Arc<Mutex<HashSet<Digest>>>,
    /// Values written now, between the blob store and the ledger: kept from the
    /// blob store's garbage collection.
    writing: Arc<Mutex<HashSet<Digest>>>,
    /// Databases succeeded by another (a forward was seen): parent → the pinned
    /// successor. They take no more writes.
    pinned: Mutex<HashMap<Digest, Digest>>,
    /// Parents whose successor is here and matches its forward: reads and writes
    /// go to the successor.
    followed: Mutex<HashMap<Digest, Digest>>,
    /// Successors already reported as not matching their forward.
    warned: Mutex<HashSet<Digest>>,
    /// Databases that matched a peer's root at least once (or were published here).
    synced: Mutex<HashSet<Digest>>,
    /// When each parent was pinned, for the follow wait.
    pinned_at: Mutex<HashMap<Digest, Instant>>,
    /// Values whose blob has another size than their record states: never fetched.
    wrong_size: Mutex<HashSet<(Digest, u64)>>,
    /// Values not found yet: how many tries, and when the next may start.
    backoff: Mutex<HashMap<Digest, (u32, Instant)>>,
    /// Slots for value fetches running at once.
    fetch_slots: tokio::sync::Semaphore,
}

impl Node {
    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().expect("store mutex")
    }

    /// The peers this node has a session with for `db`.
    fn peers(&self, db: &Digest) -> Vec<EndpointId> {
        let mut sessions = self.sessions.lock().expect("sessions");
        sessions.retain(|(_, _, s)| s.is_open());
        let mut seen = HashSet::new();
        sessions
            .iter()
            .filter(|(d, p, _)| d == db && seen.insert(*p))
            .map(|(_, p, _)| *p)
            .collect()
    }

    /// Fetches a value of `db` by hash from the database's peers, unless it is
    /// already held, on its way, or known to be of the wrong size. Failures stay
    /// quiet: the sweep tries again, and iroh-blobs resumes a partial value instead
    /// of starting over.
    ///
    /// `size` is what the signed record states. The blob's real size is learned
    /// first, verified, from its last chunk; a blob of any other size is never
    /// downloaded, so a record can't make every node fetch more than `maxValue`.
    fn fetch(self: &Arc<Self>, db: Digest, h: Digest, size: u64) {
        if self.held.lock().expect("held").contains(&h)
            || self
                .wrong_size
                .lock()
                .expect("wrong size")
                .contains(&(h, size))
            || self
                .backoff
                .lock()
                .expect("backoff")
                .get(&h)
                .is_some_and(|(_, at)| Instant::now() < *at)
            || !self.fetching.lock().expect("fetching").insert(h)
        {
            return;
        }
        let node = self.clone();
        tokio::spawn(async move {
            // A bounded number at once; the rest wait their turn.
            let _permit = node.fetch_slots.acquire().await;
            let peers = node.peers(&db);
            if !peers.is_empty() && !node.values.has(h).await.unwrap_or(false) {
                let t = Instant::now();
                let real = node.blob_size(&h, peers.clone()).await;
                if real.is_some_and(|r| r != size) {
                    log(format!(
                        "value {} is {} bytes, its record says {size}: not fetched",
                        &h.to_hex()[..12],
                        real.unwrap_or_default()
                    ));
                    node.wrong_size
                        .lock()
                        .expect("wrong size")
                        .insert((h, size));
                    node.fetching.lock().expect("fetching").remove(&h);
                    return;
                }
                let download = node.downloader.download(hash(&h), peers);
                if real == Some(size)
                    && let Ok(Ok(())) = tokio::time::timeout(FETCH_TIMEOUT, download).await
                    && let Ok(iroh_blobs::api::blobs::BlobStatus::Complete { size }) =
                        node.values.0.status(hash(&h)).await
                    && size > sameroot_sync::INLINE_VALUE
                {
                    log(format!(
                        "value {} ({size} bytes) fetched in {:.1?}",
                        &h.to_hex()[..12],
                        t.elapsed()
                    ));
                }
            }
            if node.values.has(h).await.unwrap_or(false) {
                node.held.lock().expect("held").insert(h);
                node.backoff.lock().expect("backoff").remove(&h);
            } else {
                // Not there yet: wait 10 s, 20 s, 40 s … up to an hour before the next
                // try, so values nobody holds don't cost a fetch on every sweep.
                let mut b = node.backoff.lock().expect("backoff");
                let tries = b.get(&h).map_or(0, |(n, _)| *n) + 1;
                let wait = (VALUE_SWEEP * 2u32.saturating_pow(tries.min(16))).min(MAX_BACKOFF);
                b.insert(h, (tries, Instant::now() + wait));
            }
            node.fetching.lock().expect("fetching").remove(&h);
        });
    }

    /// The verified size of a blob, learned by fetching only its last chunk: in
    /// BLAKE3 verified streaming the last chunk proves the size.
    async fn blob_size(&self, h: &Digest, peers: Vec<EndpointId>) -> Option<u64> {
        use iroh_blobs::api::blobs::BlobStatus;
        use iroh_blobs::protocol::{ChunkRanges, ChunkRangesExt, GetRequest};
        let probe = GetRequest::blob_ranges(hash(h), ChunkRanges::last_chunk());
        let _ = tokio::time::timeout(PROBE_TIMEOUT, self.downloader.download(probe, peers)).await;
        match self.values.0.status(hash(h)).await.ok()? {
            BlobStatus::Complete { size } => Some(size),
            BlobStatus::Partial { size } => size,
            BlobStatus::NotFound => None,
        }
    }

    /// Fetches every value the ledgers reference and this node lacks.
    async fn sweep_values(self: &Arc<Self>) -> Result<(), String> {
        for (db, wanted) in self.wanted_values()? {
            for (h, size) in wanted {
                if self.values.has(h).await.map_err(|e| e.to_string())? {
                    self.held.lock().expect("held").insert(h);
                } else {
                    self.fetch(db, h, size);
                }
            }
        }
        Ok(())
    }

    /// Per database, the values of its puts that count (hash, signed size) not yet known to be
    /// held, leaving out those known to be of the wrong size.
    fn wanted_values(&self) -> Result<Vec<(Digest, Vec<WantedValue>)>, String> {
        let store = self.store();
        let held = self.held.lock().expect("held");
        let wrong = self.wrong_size.lock().expect("wrong size");
        let mut out = Vec::new();
        for db in store.databases().map_err(|e| e.to_string())? {
            let values = store
                .live_values(&db, now_ms())
                .map_err(|e| e.to_string())?;
            out.push((
                db,
                values
                    .into_iter()
                    .filter(|v| !held.contains(&v.0) && !wrong.contains(v))
                    .collect(),
            ));
        }
        Ok(out)
    }

    /// The values of these entries that this node holds, each matching the size its
    /// record states.
    async fn values_of(&self, entries: &[SignedEntry]) -> HashMap<Digest, Vec<u8>> {
        let mut out = HashMap::new();
        for e in entries.iter().filter(|e| e.header.op == Op::Put) {
            let h = e.header.value_hash;
            if let Ok(Some(v)) = self.values.get(h).await
                && v.len() as u64 == e.header.value_size
            {
                out.insert(h, v);
            }
        }
        out
    }

    fn resync(&self, db: &Digest) {
        let mut sessions = self.sessions.lock().expect("sessions");
        sessions.retain(|(_, _, s)| s.is_open());
        for (d, _, s) in sessions.iter() {
            if d == db {
                s.resync();
            }
        }
    }

    /// Sends fresh records to every session of `db` at once (and the root after).
    fn push(&self, db: &Digest, ids: Vec<Digest>) {
        let mut sessions = self.sessions.lock().expect("sessions");
        sessions.retain(|(_, _, s)| s.is_open());
        for (d, _, s) in sessions.iter() {
            if d == db {
                s.push(ids.clone());
            }
        }
    }

    fn session_count(&self) -> usize {
        let mut sessions = self.sessions.lock().expect("sessions");
        sessions.retain(|(_, _, s)| s.is_open());
        sessions.len()
    }

    fn connected(&self, db: &Digest, peer: &EndpointId) -> bool {
        let mut sessions = self.sessions.lock().expect("sessions");
        sessions.retain(|(_, _, s)| s.is_open());
        sessions.iter().any(|(d, p, _)| d == db && p == peer)
    }

    /// Starts a sync session on a stream; `keep` (the connection) lives as long.
    fn spawn_session<S, K>(self: &Arc<Self>, db: Digest, peer: EndpointId, stream: S, keep: K)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
        K: Send + 'static,
    {
        let (ready_tx, ready_rx) = oneshot::channel();
        let node = self.clone();
        tokio::spawn(async move {
            let _keep = keep;
            match sameroot_sync::run(
                stream,
                node.store.clone(),
                node.values.clone(),
                db,
                node.events.clone(),
                ready_tx,
            )
            .await
            {
                Ok(()) => log(format!("session with {} ended", peer.fmt_short())),
                Err(e) => log(format!("session with {}: {e}", peer.fmt_short())),
            }
        });
        let node = self.clone();
        tokio::spawn(async move {
            if let Ok(session) = ready_rx.await {
                node.sessions
                    .lock()
                    .expect("sessions")
                    .push((db, peer, session));
            }
        });
    }

    async fn dial(self: &Arc<Self>, db: Digest, invite: &Invite) -> Result<(), String> {
        let id: EndpointId = invite
            .endpoint
            .parse()
            .map_err(|e| format!("endpoint id: {e}"))?;
        if self.connected(&db, &id) {
            return Ok(());
        }
        let mut addr = EndpointAddr::new(id);
        if let Some(r) = &invite.relay {
            addr = addr.with_relay_url(r.parse().map_err(|e| format!("relay url: {e}"))?);
        }
        for a in &invite.addrs {
            if let Ok(sa) = a.parse() {
                addr = addr.with_ip_addr(sa);
            }
        }
        let conn = self
            .endpoint
            .connect(addr, ALPN)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;
        send.write_all(&db.0)
            .await
            .map_err(|e| format!("write: {e}"))?;
        log(format!(
            "connected to {} for {}",
            id.fmt_short(),
            &db.to_hex()[..12]
        ));
        self.spawn_session(db, id, tokio::io::join(recv, send), conn);
        Ok(())
    }

    /// Serves a ledger connection: one session per stream, until it closes.
    async fn serve_connection(self: Arc<Self>, conn: Connection) {
        let peer = conn.remote_id();
        loop {
            let (send, mut recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut db = [0u8; 32];
            // A peer that opens a stream and says nothing doesn't hold it.
            match tokio::time::timeout(HELLO_TIMEOUT, recv.read_exact(&mut db)).await {
                Ok(Ok(_)) => {}
                _ => continue,
            }
            let db = Digest(db);
            let known = self.store().genesis(&db).ok().flatten().is_some();
            if !known {
                log(format!(
                    "{} asked for an unknown database",
                    peer.fmt_short()
                ));
                continue; // dropping the streams refuses
            }
            // One session per database and peer, and a cap on all of them: each
            // session may queue up to the outbox cap, and every push fans out to all.
            if self.connected(&db, &peer) {
                continue;
            }
            if self.session_count() >= MAX_SESSIONS {
                log(format!(
                    "{} refused: {MAX_SESSIONS} sessions open",
                    peer.fmt_short()
                ));
                continue;
            }
            log(format!("{} syncs {}", peer.fmt_short(), &db.to_hex()[..12]));
            self.spawn_session(db, peer, tokio::io::join(recv, send), conn.clone());
        }
    }

    /// The database a request names, or the one this node holds; followed to its
    /// successor unless the request says `exact`.
    fn resolve_db(&self, req: &Map) -> Result<Digest, String> {
        let db = self.resolve_db_exact(req)?;
        if req.flag("exact") == Some(true) {
            return Ok(db);
        }
        Ok(self.current(db))
    }

    /// The origin of `db`'s succession chain: the first database, found by following
    /// each genesis's `predecessor`. Applications bind what they seal to it, so values
    /// carried by a succession stay readable (`None` when a link isn't held here).
    fn origin(&self, db: &Digest) -> Option<Digest> {
        let mut d = *db;
        for _ in 0..64 {
            let g = self.store().genesis(&d).ok().flatten()?;
            match g.genesis.predecessor {
                None => return Some(d),
                Some(p) => d = p.db,
            }
        }
        None
    }

    /// `db`, or the successor it was followed to (and so on).
    fn current(&self, mut db: Digest) -> Digest {
        let followed = self.followed.lock().expect("followed");
        for _ in 0..16 {
            match followed.get(&db) {
                Some(next) => db = *next,
                None => break,
            }
        }
        db
    }

    /// The database a request names; without a name, the one database this node
    /// holds that wasn't succeeded.
    fn resolve_db_exact(&self, req: &Map) -> Result<Digest, String> {
        let mut dbs = self.store().databases().map_err(|e| e.to_string())?;
        if req.text("db").is_none_or(str::is_empty) {
            let followed = self.followed.lock().expect("followed");
            dbs.retain(|d| !followed.contains_key(d));
        }
        match req.text("db") {
            None | Some("") => match dbs.as_slice() {
                [one] => Ok(*one),
                [] => Err(
                    "no database yet: create one with `sameroot owner create-db` or join one"
                        .into(),
                ),
                _ => Err("several databases: pass --db".into()),
            },
            Some(prefix) => {
                let found: Vec<_> = dbs
                    .iter()
                    .filter(|d| d.to_hex().starts_with(prefix))
                    .collect();
                match found.as_slice() {
                    [one] => Ok(**one),
                    [] => Err(format!("unknown database {prefix}")),
                    _ => Err(format!("ambiguous database prefix {prefix}")),
                }
            }
        }
    }

    /// The subspace and certificate this node writes with in `db`.
    /// The subspace and certificate this node writes with in `db`. A certificate that
    /// was installed and is now missing is an error, not a silent fall back to the
    /// device's own subspace, which would make the database look empty.
    fn write_identity(&self, db: &Digest) -> Result<(Subspace, Option<SignedCert>), String> {
        let certs = read_pairs(&self.home.join("writecerts"));
        let Some((_, id)) = certs.iter().find(|(d, _)| *d == db.to_hex()) else {
            // A successor of a database this node wrote under a certificate: without
            // its own certificate there, the writes would land in the device's own
            // subspace, where nobody looks.
            let parent = self
                .followed
                .lock()
                .expect("followed")
                .iter()
                .find(|(_, c)| *c == db)
                .map(|(p, _)| *p);
            if let Some(p) = parent
                && self.parent_was_delegated(&p)
            {
                return Err(format!(
                    "no certificate for this device in {} (the successor of {}) yet: it \
                     comes with the owner's grants, or by `sameroot owner delegate {} {}` \
                     and `sameroot cert add`",
                    &db.to_hex()[..12],
                    &p.to_hex()[..12],
                    db.to_hex(),
                    self.device.public().to_hex()
                ));
            }
            return Ok((Subspace::Owner(self.device.public()), None));
        };
        let cert = Digest::from_hex(id)
            .and_then(|id| self.store().cert(&id).ok().flatten())
            .ok_or_else(|| {
                format!(
                    "the certificate this node writes with in {} ({id}) is missing: \
                     install it again with `sameroot cert add`",
                    &db.to_hex()[..12]
                )
            })?;
        Ok((cert.cert.area.subspace, Some(cert)))
    }

    /// Did this node write `db` under a certificate? (Its line in `writecerts` goes
    /// when the database is collected; the record of it stays in `delegated`.)
    fn parent_was_delegated(&self, db: &Digest) -> bool {
        let hex = db.to_hex();
        read_pairs(&self.home.join("writecerts"))
            .iter()
            .chain(read_pairs(&self.home.join("delegated")).iter())
            .any(|(d, _)| *d == hex)
    }

    fn install_cert(&self, cert: &SignedCert) -> Result<bool, String> {
        self.store().add_cert(cert).map_err(|e| e.to_string())?;
        if cert.cert.subject == self.device.public() {
            add_pair(
                &self.home.join("writecerts"),
                &cert.cert.db.to_hex(),
                &cert.id().to_hex(),
                true,
            )
            .map_err(|e| e.to_string())?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn write(
        &self,
        db: Digest,
        path: Path,
        op: Op,
        value: Option<&[u8]>,
        agent: Option<&str>,
    ) -> Result<SignedEntry, String> {
        self.write_entry(db, path, op, value, None, agent, None)
            .await
    }

    /// Who signs a write: the device, or one of its agents with a key and a
    /// certificate of its own (design 0004 §3: one key per agent, so one agent can
    /// be revoked alone). The agent's certificate is issued by the device, within the
    /// device's own area, for 30 days, and renewed a week before it ends.
    ///
    /// An agent key holds at most one certificate in a database, so a void of that
    /// certificate covers the key. A new certificate comes with a new key when the
    /// old key has a certificate there that is still valid or is voided. A voided
    /// certificate is not used again.
    fn writer(&self, db: &Digest, agent: Option<&str>) -> Result<Writer, String> {
        let (subspace, device_cert) = self.write_identity(db)?;
        if let Some(c) = &device_cert
            && c.cert.not_after <= now_ms()
        {
            return Err(format!(
                "the certificate this node writes with in {} expired: renew it with \
                 `sameroot owner delegate` and `sameroot cert add`",
                &db.to_hex()[..12]
            ));
        }
        let Some(name) = agent else {
            return Ok(Writer {
                key: SecretKey::from_seed(self.device.seed()),
                subspace,
                chain: device_cert.into_iter().collect(),
            });
        };
        if name.is_empty()
            || name.len() > 32
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(format!("bad agent name {name:?}: use a-z, 0-9, - and _"));
        }
        let dir = self.home.join("agents");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let key_path = dir.join(format!("{name}.key"));
        let mut key =
            SecretKey::from_seed(load_or_create_key(&key_path).map_err(|e| e.to_string())?);
        let now = now_ms();
        let void_targets = self.store().void_targets(db).map_err(|e| e.to_string())?;
        let is_voided = |c: &SignedCert| void_targets.contains(&VoidTarget::Cert(c.id()));
        let slot = format!("{}/{name}", db.to_hex());
        let parent = device_cert.as_ref().map(|c| c.id());
        let (area, not_after) = match &device_cert {
            Some(d) => (
                d.cert.area.clone(),
                d.cert.not_after.min(now.saturating_add(AGENT_LIFETIME)),
            ),
            None => (
                Area {
                    subspace: Subspace::Owner(self.device.public()),
                    path_prefix: Path::default(),
                    ops: vec![Op::Put, Op::Delete, Op::Negate],
                },
                now.saturating_add(AGENT_LIFETIME),
            ),
        };
        let current = read_pairs(&self.home.join("agentcerts"))
            .into_iter()
            .find(|(k, _)| *k == slot)
            .and_then(|(_, id)| Digest::from_hex(&id))
            .and_then(|id| self.store().cert(&id).ok().flatten())
            .filter(|c| {
                let lasts_past_renewal = c.cert.not_after > now.saturating_add(AGENT_RENEW);
                let renewal_cannot_extend_it = c.cert.not_after >= not_after;
                c.cert.subject == key.public()
                    && c.cert.parent == parent
                    && c.cert.area == area
                    && (lasts_past_renewal || renewal_cannot_extend_it)
                    && !is_voided(c)
            });
        let cert = match current {
            Some(c) => c,
            None => {
                let key_holds_a_certificate = self
                    .store()
                    .certs(db)
                    .map_err(|e| e.to_string())?
                    .iter()
                    .any(|c| {
                        c.cert.subject == key.public() && (c.cert.not_after > now || is_voided(c))
                    });
                if key_holds_a_certificate {
                    key = SecretKey::from_seed(replace_key(&key_path).map_err(|e| e.to_string())?);
                    log(format!("agent {name}: new key"));
                }
                let c = Cert {
                    issuer: self.device.public(),
                    subject: key.public(),
                    parent,
                    db: *db,
                    area,
                    not_before: now.saturating_sub(5 * 60 * 1000),
                    not_after,
                    name: Some(format!("agent {name}")),
                    endpoint: None,
                }
                .sign(&self.device);
                self.store().add_cert(&c).map_err(|e| e.to_string())?;
                add_pair(&self.home.join("agentcerts"), &slot, &c.id().to_hex(), true)
                    .map_err(|e| e.to_string())?;
                log(format!(
                    "agent {name} in {}: certificate {}",
                    &db.to_hex()[..12],
                    &c.id().to_hex()[..12]
                ));
                c
            }
        };
        let mut chain = vec![cert];
        chain.extend(device_cert);
        Ok(Writer {
            key,
            subspace,
            chain,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_entry(
        &self,
        db: Digest,
        path: Path,
        op: Op,
        value: Option<&[u8]>,
        target: Option<Digest>,
        agent: Option<&str>,
        at: Option<u64>,
    ) -> Result<SignedEntry, String> {
        if let Some(next) = self.pinned.lock().expect("pinned").get(&db) {
            return Err(format!(
                "database {} was succeeded by {}: it takes no more writes",
                &db.to_hex()[..12],
                &next.to_hex()[..12]
            ));
        }
        let w = self.writer(&db, agent)?;
        let (subspace, cert) = (w.subspace, w.chain.first().cloned());
        let genesis = self
            .store()
            .genesis(&db)
            .map_err(|e| e.to_string())?
            .ok_or("unknown database")?;
        let now = now_ms();
        let current_ts = {
            let store = self.store();
            let winner = match store
                .get(&db, &subspace, &path, now)
                .map_err(|e| e.to_string())?
            {
                Some(Resolved::Value(id) | Resolved::Deleted(id)) => Some(id),
                Some(Resolved::Items(ids)) => ids.last().copied(),
                None => None,
            };
            winner
                .and_then(|id| store.entry(&db, &id).ok().flatten())
                .map(|e| e.header.ts)
        };
        // After the current winner, but never past the skew this node accepts, or the
        // write would be deferred by its own store. `at` keeps a given time (a late
        // write resubmitted) when it is still the newest and not in the future.
        let horizon = now.saturating_add(genesis.genesis.limits.ts_skew);
        let ts = match (at, current_ts) {
            (Some(t), cur) if t <= horizon && cur.is_none_or(|c| c < t) => t,
            (_, Some(cur)) if cur < horizon => now.max(cur + 1),
            _ => now,
        };
        let header = Header {
            db,
            subspace,
            path,
            op,
            ts,
            exp: genesis
                .genesis
                .limits
                .max_ttl
                .filter(|_| op == Op::Put)
                .map(|ttl| ts + ttl),
            value_size: value.map_or(0, |v| v.len() as u64),
            value_hash: value.map_or(Digest::ZERO, value_hash),
            target,
            signer: w.key.public(),
            cert: cert.as_ref().map(|c| c.id()),
            work: 0,
        };
        let entry = header.sign(&w.key);
        // The value first, committed: a peer that gets the record can fetch the value
        // at once, and a crash can't leave the ledger pointing at a lost value (the
        // blob store batches its commits; values fetched from peers come back with
        // the sweep, but this node's own values exist nowhere else yet).
        if let Some(v) = value {
            self.writing
                .lock()
                .expect("writing")
                .insert(entry.header.value_hash);
            self.values
                .put(v.to_vec())
                .await
                .map_err(|e| e.to_string())?;
            self.values.0.sync_db().await.map_err(|e| e.to_string())?;
            self.held
                .lock()
                .expect("held")
                .insert(entry.header.value_hash);
        }
        let admitted = self.store().insert_entry(&entry, &w.chain, now);
        if value.is_some() {
            self.writing
                .lock()
                .expect("writing")
                .remove(&entry.header.value_hash);
        }
        match admitted.map_err(|e| e.to_string())? {
            Outcome::Deferred => {
                return Err("the write is dated ahead of this node's clock: deferred".into());
            }
            Outcome::Added | Outcome::Duplicate => {}
        }
        self.push(&db, vec![entry.id()]);
        Ok(entry)
    }

    /// Admits deferred entries whose time has come, in every database, and sends them
    /// to the peers: sessions do it too, but only while one is open.
    fn admit_due(&self) {
        let Ok(dbs) = self.store().databases() else {
            return;
        };
        for db in dbs {
            match self.store().admit_due(&db, now_ms()) {
                Ok(ids) if !ids.is_empty() => self.push(&db, ids),
                Ok(_) => {}
                Err(e) => log(format!("deferred entries of {}: {e}", &db.to_hex()[..12])),
            }
        }
    }

    /// Successions (design 0004 §8.3), for every database.
    async fn check_successions(self: &Arc<Self>) {
        let dbs = match self.store().databases() {
            Ok(d) => d,
            Err(e) => return log(format!("successions: {e}")),
        };
        for db in dbs {
            if let Err(e) = self.check_succession(db).await {
                log(format!("succession of {}: {e}", &db.to_hex()[..12]));
            }
        }
    }

    /// One database's succession:
    /// - pins the successor its forward names (the first seen; several are a fork,
    ///   reported) and stops writing to it;
    /// - asks the parent's peers for the successor;
    /// - once the successor's genesis is here and matches the forward, follows it;
    /// - installs this device's certificate in the successor from its grants, if it
    ///   wrote the parent under one.
    async fn check_succession(self: &Arc<Self>, db: Digest) -> Result<(), String> {
        let forwards = self.store().forwards(&db).map_err(|e| e.to_string())?;
        if forwards.is_empty() {
            return Ok(());
        }
        let peers_file = self.home.join("peers");
        let pinned = self.pinned.lock().expect("pinned").get(&db).copied();
        let child = match pinned {
            Some(c) => c,
            None => {
                let mut sorted = forwards.clone();
                sorted.sort_by_key(|f| f.id());
                let child = sorted[0].forward.successor;
                let distinct: HashSet<Digest> =
                    forwards.iter().map(|f| f.forward.successor).collect();
                if distinct.len() > 1 {
                    log(format!(
                        "warning: {} has {} successors (a fork); following {}",
                        &db.to_hex()[..12],
                        distinct.len(),
                        &child.to_hex()[..12]
                    ));
                }
                add_pair(
                    &self.home.join("successors"),
                    &db.to_hex(),
                    &child.to_hex(),
                    true,
                )
                .map_err(|e| e.to_string())?;
                self.pinned.lock().expect("pinned").insert(db, child);
                self.pinned_at
                    .lock()
                    .expect("pinned at")
                    .insert(db, Instant::now());
                log(format!(
                    "{} is succeeded by {}: no more writes there",
                    &db.to_hex()[..12],
                    &child.to_hex()[..12]
                ));
                // The successor is found where the parent was.
                for (k, inv) in read_pairs(&peers_file) {
                    if k != db.to_hex() {
                        continue;
                    }
                    if let Ok(mut i) = Invite::parse(&inv) {
                        i.db = child.to_hex();
                        add_pair(&peers_file, &i.db, &i.render(), false)
                            .map_err(|e| e.to_string())?;
                    }
                }
                child
            }
        };
        let genesis = self.store().genesis(&child).map_err(|e| e.to_string())?;
        let Some(genesis) = genesis else {
            for (k, inv) in read_pairs(&peers_file) {
                if k == child.to_hex()
                    && let Ok(i) = Invite::parse(&inv)
                {
                    let _ = self.dial(child, &i).await;
                }
            }
            return Ok(());
        };
        let Some(fwd) = forwards.iter().find(|f| f.forward.successor == child) else {
            return Ok(());
        };
        if !succession::follows(&fwd.forward, &genesis) {
            if self.warned.lock().expect("warned").insert(db) {
                log(format!(
                    "warning: the genesis of {} doesn't match the forward of {}; not followed",
                    &child.to_hex()[..12],
                    &db.to_hex()[..12]
                ));
            }
            return Ok(());
        }
        let had = self.parent_was_delegated(&db);
        if had {
            add_pair(&self.home.join("delegated"), &db.to_hex(), "yes", true)
                .map_err(|e| e.to_string())?;
        }
        let has = read_pairs(&self.home.join("writecerts"))
            .iter()
            .any(|(d, _)| *d == child.to_hex());
        let followed = self.followed.lock().expect("followed").contains_key(&db);
        if followed {
            if had && !has {
                self.install_grant(&child, &genesis).await?;
            }
            return Ok(());
        }
        // Until the successor is ready, requests keep going to the parent, which holds
        // the whole state: ready means this device's certificate is in (when it wrote
        // the parent under one) and the successor caught up with a peer once, or the
        // wait ran out.
        if had && !has && !self.install_grant(&child, &genesis).await? {
            return Ok(());
        }
        let synced = self.synced.lock().expect("synced").contains(&child);
        let waited = self
            .pinned_at
            .lock()
            .expect("pinned at")
            .get(&db)
            .is_some_and(|t| t.elapsed() > FOLLOW_WAIT);
        if !synced && !waited {
            return Ok(());
        }
        self.followed.lock().expect("followed").insert(db, child);
        add_pair(
            &self.home.join("followed"),
            &db.to_hex(),
            &child.to_hex(),
            true,
        )
        .map_err(|e| e.to_string())?;
        log(format!(
            "following {} → {}",
            &db.to_hex()[..12],
            &child.to_hex()[..12]
        ));
        // The parent is read-only now: no more dialing it. Peers still on it reach
        // this node and learn the forward.
        remove_pairs(&peers_file, &db.to_hex()).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Installs this device's certificate in `db` from the grants its owner
    /// published there (`.grants/<cert id>`), if one is there yet.
    async fn install_grant(&self, db: &Digest, g: &SignedGenesis) -> Result<bool, String> {
        let prefix = Path::from_strs([succession::GRANTS]);
        let owner = Subspace::Owner(g.genesis.owner);
        let grants: Vec<SignedEntry> = {
            let store = self.store();
            let state = store.state(db, now_ms()).map_err(|e| e.to_string())?;
            state
                .iter()
                .filter(|((s, p), _)| *s == owner && p.starts_with(&prefix))
                .filter_map(|(_, r)| match r {
                    Resolved::Value(id) => store.entry(db, id).ok().flatten(),
                    _ => None,
                })
                .collect()
        };
        for e in grants {
            let Ok(Some(v)) = self.values.get(e.header.value_hash).await else {
                continue;
            };
            let Ok(c) = SignedCert::decode(&v) else {
                continue;
            };
            if c.cert.subject == self.device.public()
                && c.cert.db == *db
                && c.cert.issuer == g.genesis.owner
                && g.genesis.owner.verify(&c.cert.id(), &c.sig).is_ok()
            {
                self.install_cert(&c)?;
                log(format!(
                    "installed this device's certificate in {} from its grants",
                    &db.to_hex()[..12]
                ));
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A succeeded database named by the request, or the one this node holds.
    fn late_parent(&self, req: &Map) -> Result<Digest, String> {
        if req.text("db").is_some_and(|d| !d.is_empty()) {
            return self.resolve_db_exact(req);
        }
        let pinned: Vec<Digest> = self
            .pinned
            .lock()
            .expect("pinned")
            .keys()
            .copied()
            .collect();
        let open: Vec<Digest> = pinned
            .into_iter()
            .filter(|d| self.store().retired(d).ok().flatten().is_none())
            .collect();
        match open.as_slice() {
            [one] => Ok(*one),
            [] => Err("no succeeded database here".into()),
            _ => Err("several succeeded databases: pass --db".into()),
        }
    }

    /// The late entries of a succeeded database: admitted after this node saw the
    /// forward, or dated after the cut.
    fn late_entries(&self, db: &Digest) -> Result<Vec<Late>, String> {
        let child = *self
            .pinned
            .lock()
            .expect("pinned")
            .get(db)
            .ok_or("this database wasn't succeeded")?;
        let store = self.store();
        let forwards = store.forwards(db).map_err(|e| e.to_string())?;
        let fwd = forwards
            .iter()
            .find(|f| f.forward.successor == child)
            .ok_or("no forward")?;
        let seen_forward = store
            .first_seen(db, &fwd.id())
            .map_err(|e| e.to_string())?
            .unwrap_or(0);
        let as_of = store
            .genesis(&child)
            .map_err(|e| e.to_string())?
            .and_then(|g| g.genesis.predecessor.map(|p| p.as_of));
        let slot = format!("{}/", db.to_hex());
        let agents: HashMap<Digest, String> = read_pairs(&self.home.join("agentcerts"))
            .into_iter()
            .filter_map(|(k, id)| {
                let name = k.strip_prefix(&slot)?.to_owned();
                Some((Digest::from_hex(&id)?, name))
            })
            .collect();
        let done: HashSet<String> = read_pairs(&self.home.join("late-done"))
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let me = self.device.public();
        Ok(store
            .entries_seen(db)
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|(e, seen)| {
                seen.is_some_and(|t| t > seen_forward) || as_of.is_some_and(|a| e.header.ts > a)
            })
            .map(|(entry, _)| {
                let agent = entry.header.cert.and_then(|c| agents.get(&c).cloned());
                Late {
                    own: entry.header.signer == me || agent.is_some(),
                    done: done.contains(&entry.id().to_hex()),
                    agent,
                    entry,
                }
            })
            .collect())
    }

    /// Writes this device's late entries of `db` anew in its successor, as fresh
    /// entries (never a replay of the old ones), oldest first and keeping their
    /// times. Skipped: entries that no longer count in the parent (superseded,
    /// negated, voided), keys where the successor has one as new or newer, and
    /// negations (their targets are the parent's). Returns `(written, skipped)`.
    async fn resubmit_late(&self, db: &Digest) -> Result<(u64, u64), String> {
        let child = *self
            .followed
            .lock()
            .expect("followed")
            .get(db)
            .ok_or("the successor isn't here yet")?;
        let mut late: Vec<Late> = self
            .late_entries(db)?
            .into_iter()
            .filter(|l| l.own && !l.done)
            .collect();
        late.sort_by_key(|l| (l.entry.header.ts, l.entry.id()));
        // What still counts in the parent: a late write that lost there (superseded,
        // negated, or voided, e.g. a revoked agent's) isn't carried on.
        let (counts, child_created) = {
            let store = self.store();
            let counts: HashSet<Digest> = store
                .state(db, now_ms())
                .map_err(|e| e.to_string())?
                .values()
                .flat_map(|r| match r {
                    Resolved::Value(id) | Resolved::Deleted(id) => vec![*id],
                    Resolved::Items(ids) => ids.clone(),
                })
                .collect();
            let created = store
                .genesis(&child)
                .map_err(|e| e.to_string())?
                .ok_or("the successor's genesis is missing")?
                .genesis
                .created_at;
            (counts, created)
        };
        let (subspace, _) = self.write_identity(&child)?;
        let (mut written, mut skipped) = (0, 0);
        for l in late {
            let h = &l.entry.header;
            // Its own time, unless that falls before the successor (the floor rule).
            let at = (h.ts >= child_created).then_some(h.ts);
            let newer = !counts.contains(&l.entry.id()) || {
                let store = self.store();
                match store
                    .get(&child, &subspace, &h.path, now_ms())
                    .map_err(|e| e.to_string())?
                {
                    Some(Resolved::Value(id) | Resolved::Deleted(id)) => store
                        .entry(&child, &id)
                        .ok()
                        .flatten()
                        .is_some_and(|w| w.header.ts >= h.ts),
                    _ => false,
                }
            };
            let outcome = match h.op {
                Op::Negate => None,
                _ if newer => None,
                Op::Put => match self.values.get(h.value_hash).await {
                    Ok(Some(v)) => Some(
                        self.write_entry(
                            child,
                            h.path.clone(),
                            Op::Put,
                            Some(&v),
                            None,
                            l.agent.as_deref(),
                            at,
                        )
                        .await?,
                    ),
                    // The value isn't here (yet): try again later.
                    _ => continue,
                },
                Op::Delete => Some(
                    self.write_entry(
                        child,
                        h.path.clone(),
                        Op::Delete,
                        None,
                        None,
                        l.agent.as_deref(),
                        at,
                    )
                    .await?,
                ),
            };
            let mark = match &outcome {
                Some(e) => {
                    written += 1;
                    e.id().to_hex()
                }
                None => {
                    skipped += 1;
                    "skipped".to_owned()
                }
            };
            add_pair(
                &self.home.join("late-done"),
                &l.entry.id().to_hex(),
                &mark,
                true,
            )
            .map_err(|e| e.to_string())?;
        }
        Ok((written, skipped))
    }

    /// What a void of `cert` would keep and drop: entries under it are kept when this
    /// node first saw them before `keep_before` (or before it kept track at all).
    fn void_plan(
        &self,
        db: &Digest,
        cert: &Digest,
        keep_before: u64,
    ) -> Result<(Vec<Digest>, Vec<Seen>), String> {
        let under = self
            .store()
            .entries_under(db, cert)
            .map_err(|e| e.to_string())?;
        let mut keep = Vec::new();
        let mut dropped = Vec::new();
        for (e, seen) in under {
            if seen.is_none_or(|t| t < keep_before) {
                keep.push(e.id());
            } else {
                dropped.push((e, seen));
            }
        }
        keep.sort();
        Ok((keep, dropped))
    }

    /// Admits a void with its keep list and sends it to the database's peers.
    fn add_void(&self, void: &SignedVoid, keep: Option<&[Digest]>) -> Result<Digest, String> {
        let db = void.void.db;
        self.store()
            .insert_void(void, &[], keep)
            .map_err(|e| e.to_string())?;
        self.push(&db, vec![void.id()]);
        Ok(void.id())
    }

    /// The subspace a `list` request is about: `None` for `all: true`, otherwise the
    /// named one (`subspace`: a key in hex, or `shared`) or the node's write identity.
    fn list_subspace(&self, db: &Digest, req: &Map) -> Result<Option<Subspace>, String> {
        if req.flag("all") == Some(true) {
            return Ok(None);
        }
        Ok(Some(match req.text("subspace") {
            Some("shared") => Subspace::Shared,
            Some(h) => Subspace::Owner(PublicKey::from_hex(h).ok_or("bad subspace")?),
            None => self.write_identity(db)?.0,
        }))
    }

    fn entry_map(e: &SignedEntry, value: Option<Vec<u8>>) -> Value {
        let mut m = Map::new();
        m.insert(
            "subspace",
            Value::Text(match e.header.subspace {
                Subspace::Owner(k) => k.to_hex(),
                Subspace::Shared => "shared".into(),
            }),
        )
        .insert("path", Value::Text(e.header.path.display()))
        .insert("ts", Value::Uint(e.header.ts))
        .insert("signer", Value::Text(e.header.signer.to_hex()))
        .insert("deleted", Value::Bool(e.header.op == Op::Delete))
        .insert("id", Value::Text(e.id().to_hex()))
        .insert_opt("value", value.map(Value::Bytes));
        Value::Map(m)
    }

    async fn handle(self: &Arc<Self>, req: Map) -> Map {
        match self.handle_inner(req).await {
            Ok(m) => m,
            Err(e) => err(e),
        }
    }

    async fn handle_inner(self: &Arc<Self>, req: Map) -> Result<Map, String> {
        let op = req.text("op").unwrap_or("").to_owned();
        let mut out = ok();
        match op.as_str() {
            "status" => {
                let addr = self.endpoint.addr();
                out.insert("device", Value::Text(self.device.public().to_hex()))
                    .insert("endpoint", Value::Text(self.endpoint.id().to_string()))
                    .insert(
                        "relay",
                        Value::Array(
                            addr.relay_urls()
                                .map(|u| Value::Text(u.to_string()))
                                .collect(),
                        ),
                    )
                    .insert(
                        "addrs",
                        Value::Array(
                            addr.ip_addrs()
                                .map(|a| Value::Text(a.to_string()))
                                .collect(),
                        ),
                    );
                let mut dbs = Vec::new();
                // Collect first: a `for` keeps the mutex guard of its iterator expression
                // alive for the whole loop, and the body locks the store again.
                let databases = self.store().databases().map_err(|e| e.to_string())?;
                let wanted: HashMap<Digest, Vec<WantedValue>> =
                    self.wanted_values()?.into_iter().collect();
                for db in databases {
                    let g = self
                        .store()
                        .genesis(&db)
                        .map_err(|e| e.to_string())?
                        .ok_or("genesis")?;
                    let (count, state) = self.store().root(&db).map_err(|e| e.to_string())?;
                    let ledger_root = self.store().ledger_root(&db).map_err(|e| e.to_string())?;
                    let peers = {
                        let mut s = self.sessions.lock().expect("sessions");
                        s.retain(|(_, _, x)| x.is_open());
                        s.iter()
                            .filter(|(d, _, _)| *d == db)
                            .map(|(_, p, _)| Value::Text(p.fmt_short().to_string()))
                            .collect()
                    };
                    let retired = self.store().retired(&db).map_err(|e| e.to_string())?;
                    let successor = self.pinned.lock().expect("pinned").get(&db).copied();
                    let followed = self.followed.lock().expect("followed").contains_key(&db);
                    let late = match (successor, retired) {
                        (Some(_), None) => self
                            .late_entries(&db)
                            .map(|l| l.iter().filter(|l| l.own && !l.done).count() as u64)
                            .ok(),
                        _ => None,
                    };
                    let (identity, write_error) = match self.write_identity(&db) {
                        Ok(i) => (i, None),
                        Err(_) if retired.is_some() => {
                            ((Subspace::Owner(self.device.public()), None), None)
                        }
                        Err(e) => ((Subspace::Owner(self.device.public()), None), Some(e)),
                    };
                    let (subspace, cert) = identity;
                    // Values the ledger references and this node doesn't hold yet.
                    let mut missing = 0u64;
                    // Values whose blob has another size than their record states.
                    let wrong_size = {
                        let wrong = self.wrong_size.lock().expect("wrong size");
                        self.store()
                            .live_values(&db, now_ms())
                            .map_err(|e| e.to_string())?
                            .iter()
                            .filter(|v| wrong.contains(v))
                            .count() as u64
                    };
                    for (h, _) in wanted.get(&db).into_iter().flatten().copied() {
                        if self.values.has(h).await.map_err(|e| e.to_string())? {
                            self.held.lock().expect("held").insert(h);
                        } else {
                            missing += 1;
                        }
                    }
                    let mut m = Map::new();
                    m.insert("id", Value::Text(db.to_hex()))
                        .insert("name", Value::Text(g.genesis.name.clone()))
                        .insert("owner", Value::Text(g.genesis.owner.to_hex()))
                        .insert("records", Value::Uint(count as u64))
                        .insert("state", Value::Text(state.to_hex()))
                        .insert("ledgerRoot", Value::Text(ledger_root.to_hex()))
                        .insert("valuesMissing", Value::Uint(missing))
                        .insert("valuesWrongSize", Value::Uint(wrong_size))
                        .insert("peers", Value::Array(peers))
                        .insert(
                            "writesAs",
                            Value::Text(match subspace {
                                Subspace::Owner(k) => k.to_hex(),
                                Subspace::Shared => "shared".into(),
                            }),
                        )
                        .insert("delegated", Value::Bool(cert.is_some()))
                        .insert_opt("writeError", write_error.map(Value::Text))
                        .insert_opt("successor", successor.map(|s| Value::Text(s.to_hex())))
                        .insert("followed", Value::Bool(followed))
                        .insert_opt("origin", self.origin(&db).map(|o| Value::Text(o.to_hex())))
                        .insert_opt("retired", retired.map(Value::Uint))
                        .insert_opt("late", late.map(Value::Uint));
                    dbs.push(Value::Map(m));
                }
                out.insert("databases", Value::Array(dbs));
            }
            "db.add" => {
                let g = SignedGenesis::decode(req.bytes("genesis").ok_or("genesis missing")?)
                    .map_err(|e| e.to_string())?;
                let id = self.store().add_database(&g).map_err(|e| e.to_string())?;
                if let Some(c) = req.bytes("cert") {
                    let cert = SignedCert::decode(c).map_err(|e| e.to_string())?;
                    self.install_cert(&cert)?;
                }
                log(format!(
                    "database {} ({}) added",
                    &id.to_hex()[..12],
                    g.genesis.name
                ));
                out.insert("db", Value::Text(id.to_hex()));
            }
            "cert.add" => {
                let cert = SignedCert::decode(req.bytes("cert").ok_or("cert missing")?)
                    .map_err(|e| e.to_string())?;
                let mine = self.install_cert(&cert)?;
                out.insert("forThisNode", Value::Bool(mine))
                    .insert("db", Value::Text(cert.cert.db.to_hex()));
                self.resync(&cert.cert.db);
            }
            "invite" => {
                let db = self.resolve_db(&req)?;
                let addr = self.endpoint.addr();
                let invite = Invite {
                    db: db.to_hex(),
                    endpoint: self.endpoint.id().to_string(),
                    relay: addr.relay_urls().next().map(|u| u.to_string()),
                    addrs: addr.ip_addrs().map(|a| a.to_string()).collect(),
                };
                out.insert("invite", Value::Text(invite.render()));
            }
            "join" => {
                let invite = Invite::parse(req.text("invite").ok_or("invite missing")?)?;
                let db = Digest::from_hex(&invite.db).ok_or("invite: bad database id")?;
                add_pair(
                    &self.home.join("peers"),
                    &invite.db,
                    &invite.render(),
                    false,
                )
                .map_err(|e| e.to_string())?;
                self.dial(db, &invite).await?;
                out.insert("db", Value::Text(invite.db.clone()));
            }
            "negate" => {
                let db = self.resolve_db(&req)?;
                let target = Digest::from_hex(req.text("target").ok_or("target missing")?)
                    .ok_or("bad target id")?;
                let path = self
                    .store()
                    .entry(&db, &target)
                    .map_err(|e| e.to_string())?
                    .ok_or("no such entry in this database")?
                    .header
                    .path;
                let entry = self
                    .write_entry(
                        db,
                        path,
                        Op::Negate,
                        None,
                        Some(target),
                        req.text("agent"),
                        None,
                    )
                    .await?;
                out.insert("entry", Self::entry_map(&entry, None));
            }
            "put" | "del" => {
                let db = self.resolve_db(&req)?;
                let path =
                    Path::parse(req.text("path").ok_or("path missing")?).ok_or("bad path")?;
                let entry = if op == "put" {
                    self.write(
                        db,
                        path,
                        Op::Put,
                        Some(req.bytes("value").ok_or("value missing")?),
                        req.text("agent"),
                    )
                    .await?
                } else {
                    self.write(db, path, Op::Delete, None, req.text("agent"))
                        .await?
                };
                out.insert("entry", Self::entry_map(&entry, None));
            }
            "get" => {
                let db = self.resolve_db(&req)?;
                let path =
                    Path::parse(req.text("path").ok_or("path missing")?).ok_or("bad path")?;
                let subspace = match req.text("subspace") {
                    Some("shared") => Subspace::Shared,
                    Some(h) => Subspace::Owner(PublicKey::from_hex(h).ok_or("bad subspace")?),
                    None => self.write_identity(&db)?.0,
                };
                let found = {
                    let store = self.store();
                    let r = store
                        .get(&db, &subspace, &path, now_ms())
                        .map_err(|e| e.to_string())?;
                    let id = match r {
                        Some(Resolved::Value(id) | Resolved::Deleted(id)) => Some(id),
                        Some(Resolved::Items(ids)) => ids.last().copied(),
                        None => None,
                    };
                    id.and_then(|id| store.entry(&db, &id).ok().flatten())
                };
                match found {
                    Some(e) => {
                        let v = self.values_of(std::slice::from_ref(&e)).await;
                        let v = v.get(&e.header.value_hash).cloned();
                        out.insert("entry", Self::entry_map(&e, v));
                    }
                    None => {
                        out.insert("entry", Value::Null);
                    }
                }
            }
            "list" => {
                let db = self.resolve_db(&req)?;
                let prefix = match req.text("prefix") {
                    None => Path::default(),
                    Some(p) => Path::parse(p).ok_or("bad prefix")?,
                };
                // One subspace: the node's own unless the caller names one or asks for
                // all. In an open-write database anyone may write their own subspace, so
                // listing every subspace by default would mix strangers' entries into
                // this node's data.
                let only = self.list_subspace(&db, &req)?;
                // A page at a time: `offset` keys skipped, at most `limit` keys and
                // about LIST_BUDGET bytes of values; `next` says where the next page
                // starts. Offsets move if keys are added meanwhile.
                let offset = req.uint("offset").unwrap_or(0) as usize;
                let limit = req
                    .uint("limit")
                    .map_or(LIST_LIMIT, |l| (l as usize).clamp(1, LIST_LIMIT));
                // The entries under the store lock, then their values without it.
                let mut next = None;
                let entries = {
                    let store = self.store();
                    let state = store.state(&db, now_ms()).map_err(|e| e.to_string())?;
                    let mut out = Vec::new();
                    // Paths under a dot (`.grants`) are the database's own bookkeeping:
                    // listed only when the prefix asks for them.
                    let system = prefix.0.first().is_some_and(|c| c.starts_with(b"."));
                    let keys = state.into_iter().filter(|((subspace, path), _)| {
                        path.starts_with(&prefix)
                            && only.is_none_or(|o| o == *subspace)
                            && (system || !path.0.first().is_some_and(|c| c.starts_with(b".")))
                    });
                    let mut bytes = 0u64;
                    for (taken, ((_, _), r)) in keys.skip(offset).enumerate() {
                        if taken == limit || bytes > LIST_BUDGET {
                            next = Some(offset + taken);
                            break;
                        }
                        let ids = match r {
                            Resolved::Value(id) | Resolved::Deleted(id) => vec![id],
                            Resolved::Items(ids) => ids,
                        };
                        for id in ids {
                            if let Some(e) = store.entry(&db, &id).map_err(|e| e.to_string())? {
                                bytes += e.header.value_size;
                                out.push(e);
                            }
                        }
                    }
                    out
                };
                let values = self.values_of(&entries).await;
                let entries = entries
                    .iter()
                    .map(|e| {
                        let v = (e.header.op == Op::Put)
                            .then(|| values.get(&e.header.value_hash).cloned())
                            .flatten();
                        Self::entry_map(e, v)
                    })
                    .collect();
                out.insert("entries", Value::Array(entries))
                    .insert_opt("next", next.map(|n| Value::Uint(n as u64)));
            }
            "certs" => {
                let db = self.resolve_db(&req)?;
                let certs = self.store().certs(&db).map_err(|e| e.to_string())?;
                let list = certs
                    .iter()
                    .map(|c| {
                        let mut m = Map::new();
                        m.insert("id", Value::Text(c.id().to_hex()))
                            .insert("issuer", Value::Text(c.cert.issuer.to_hex()))
                            .insert("subject", Value::Text(c.cert.subject.to_hex()))
                            .insert_opt("parent", c.cert.parent.map(|p| Value::Text(p.to_hex())))
                            .insert_opt("name", c.cert.name.clone().map(Value::Text))
                            .insert("notAfter", Value::Uint(c.cert.not_after));
                        Value::Map(m)
                    })
                    .collect();
                out.insert("db", Value::Text(db.to_hex()))
                    .insert("certs", Value::Array(list));
            }
            "void.plan" => {
                let db = self.resolve_db(&req)?;
                let cert = Digest::from_hex(req.text("cert").ok_or("cert missing")?)
                    .ok_or("bad cert id")?;
                let keep_before = req.uint("keepBefore").unwrap_or_else(now_ms);
                let (keep, dropped) = self.void_plan(&db, &cert, keep_before)?;
                out.insert("db", Value::Text(db.to_hex()))
                    .insert(
                        "keep",
                        Value::Bytes(keep.iter().flat_map(|d| d.0).collect()),
                    )
                    .insert(
                        "dropped",
                        Value::Array(
                            dropped
                                .iter()
                                .map(|(e, seen)| {
                                    let mut m = Map::new();
                                    m.insert("id", Value::Text(e.id().to_hex()))
                                        .insert("path", Value::Text(e.header.path.display()))
                                        .insert("ts", Value::Uint(e.header.ts))
                                        .insert_opt("firstSeen", seen.map(Value::Uint));
                                    Value::Map(m)
                                })
                                .collect(),
                        ),
                    );
            }
            "void.add" => {
                let void = SignedVoid::decode(req.bytes("void").ok_or("void missing")?)
                    .map_err(|e| e.to_string())?;
                let keep = keep_ids(req.bytes("keep"))?;
                let id = self.add_void(&void, keep.as_deref())?;
                out.insert("id", Value::Text(id.to_hex()));
            }
            "void.sign" => {
                // Signed by this node's device key: for certificates the device issued
                // (its agents'), or ones further down its chain.
                let db = self.resolve_db(&req)?;
                let cert = Digest::from_hex(req.text("cert").ok_or("cert missing")?)
                    .ok_or("bad cert id")?;
                let mut void = Void::of_cert(db, cert, self.device.public());
                let keep = if req.flag("total") == Some(true) {
                    None
                } else {
                    let keep_before = req.uint("keepBefore").unwrap_or_else(now_ms);
                    let (keep, _) = self.void_plan(&db, &cert, keep_before)?;
                    void.keep = Some(Keep {
                        root: Trie::build(keep.iter().map(|d| (Kind::Entry, *d))).root(),
                        count: keep.len() as u64,
                    });
                    void.before = req.uint("before");
                    Some(keep)
                };
                let genesis = self
                    .store()
                    .genesis(&db)
                    .map_err(|e| e.to_string())?
                    .ok_or("unknown database")?;
                if let Some(bits) = genesis.genesis.limits.void_work
                    && genesis.genesis.owner != self.device.public()
                {
                    void.mine(bits.min(32) as u32);
                }
                let signed = void.sign(&self.device);
                let id = self.add_void(&signed, keep.as_deref())?;
                out.insert("id", Value::Text(id.to_hex()))
                    .insert("kept", Value::Uint(keep.map_or(0, |k| k.len() as u64)));
            }
            "succession.cut" => {
                // What the owner's tool needs to plan a succession (design 0004 §8.3
                // step 1): the cut, the owner's state at it, the device grants.
                let db = self.resolve_db_exact(&req)?;
                let now = now_ms();
                let grants_prefix = Path::from_strs([succession::GRANTS]);
                let (g, count, root, carried, others, grant_values, voided, mut certs) = {
                    let store = self.store();
                    let g = store
                        .genesis(&db)
                        .map_err(|e| e.to_string())?
                        .ok_or("unknown database")?;
                    let owner = Subspace::Owner(g.genesis.owner);
                    let (count, _) = store.root(&db).map_err(|e| e.to_string())?;
                    let root = store.ledger_root(&db).map_err(|e| e.to_string())?;
                    let state = store.state(&db, now).map_err(|e| e.to_string())?;
                    let mut carried = Vec::new();
                    let mut others = 0u64;
                    // The grants of this database: the device certificates of a previous
                    // succession. They aren't carried as values (the child gets its own
                    // grants); their certificates join the devices below.
                    let mut grant_values = Vec::new();
                    for ((subspace, path), r) in &state {
                        if *subspace == owner && path.starts_with(&grants_prefix) {
                            if let Resolved::Value(id) = r
                                && let Some(e) = store.entry(&db, id).map_err(|e| e.to_string())?
                            {
                                grant_values.push(e.header.value_hash);
                            }
                            continue;
                        }
                        let ids = match r {
                            _ if *subspace != owner => {
                                others += 1;
                                continue;
                            }
                            Resolved::Value(id) => vec![*id],
                            Resolved::Items(ids) => ids.clone(),
                            Resolved::Deleted(_) => continue,
                        };
                        for id in ids {
                            let e = store
                                .entry(&db, &id)
                                .map_err(|e| e.to_string())?
                                .ok_or("entry missing")?;
                            let mut m = Map::new();
                            m.insert(
                                "path",
                                Value::Array(
                                    path.0.iter().map(|c| Value::Bytes(c.clone())).collect(),
                                ),
                            )
                            .insert("hash", Value::Bytes(e.header.value_hash.0.to_vec()))
                            .insert("size", Value::Uint(e.header.value_size))
                            .insert_opt("exp", e.header.exp.map(Value::Uint));
                            carried.push(Value::Map(m));
                        }
                    }
                    let voided = store.void_targets(&db).map_err(|e| e.to_string())?;
                    let certs = store.certs(&db).map_err(|e| e.to_string())?;
                    (g, count, root, carried, others, grant_values, voided, certs)
                };
                for h in grant_values {
                    if let Ok(Some(v)) = self.values.get(h).await
                        && let Ok(c) = SignedCert::decode(&v)
                        && c.cert.db == db
                        && g.genesis.owner.verify(&c.cert.id(), &c.sig).is_ok()
                    {
                        certs.push(c);
                    }
                }
                let mut seen = HashSet::new();
                let devices: Vec<Value> = certs
                    .into_iter()
                    .filter(|c| {
                        seen.insert(c.id())
                            && c.cert.issuer == g.genesis.owner
                            && c.cert.parent.is_none()
                            && c.cert.not_after > now
                            && !voided.iter().any(|t| match t {
                                VoidTarget::Cert(id) => *id == c.id(),
                                VoidTarget::Key(k) => *k == c.cert.subject,
                            })
                    })
                    .map(|c| Value::Bytes(c.encode()))
                    .collect();
                out.insert("db", Value::Text(db.to_hex()))
                    .insert("genesis", Value::Bytes(g.encode()))
                    .insert("cutRoot", Value::Bytes(root.0.to_vec()))
                    .insert("cutCount", Value::Uint(count as u64))
                    .insert("asOf", Value::Uint(now))
                    .insert("state", Value::Array(carried))
                    .insert("devices", Value::Array(devices))
                    .insert("otherKeys", Value::Uint(others));
            }
            "entries.add" => {
                // Entries signed elsewhere (the owner's tool), with values they need.
                let values: Vec<Vec<u8>> = req
                    .list("values")
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|v| match v {
                        Value::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .collect();
                let entries: Vec<SignedEntry> = req
                    .list("entries")
                    .ok_or("entries missing")?
                    .iter()
                    .map(|v| match v {
                        Value::Bytes(b) => SignedEntry::decode(b).map_err(|e| e.to_string()),
                        _ => Err("an entry must be bytes".to_owned()),
                    })
                    .collect::<Result<_, _>>()?;
                let hashes: Vec<Digest> = values.iter().map(|v| value_hash(v)).collect();
                self.writing
                    .lock()
                    .expect("writing")
                    .extend(hashes.iter().copied());
                for v in values {
                    self.values.put(v).await.map_err(|e| e.to_string())?;
                }
                self.values.0.sync_db().await.map_err(|e| e.to_string())?;
                let now = now_ms();
                let mut added: HashMap<Digest, Vec<Digest>> = HashMap::new();
                let mut failed = None;
                for e in &entries {
                    let db = e.header.db;
                    if self.pinned.lock().expect("pinned").contains_key(&db) {
                        failed = Some(format!("{} takes no more writes", &db.to_hex()[..12]));
                        break;
                    }
                    match self.store().insert_entry(e, &[], now) {
                        Ok(Outcome::Added) => added.entry(db).or_default().push(e.id()),
                        Ok(_) => {}
                        Err(err) => {
                            failed = Some(err.to_string());
                            break;
                        }
                    }
                }
                {
                    let mut w = self.writing.lock().expect("writing");
                    for h in &hashes {
                        w.remove(h);
                    }
                }
                let count: usize = added.values().map(Vec::len).sum();
                for (db, ids) in added {
                    self.push(&db, ids);
                }
                if let Some(f) = failed {
                    return Err(format!("after {count} entries: {f}"));
                }
                out.insert("added", Value::Uint(count as u64));
            }
            "forward.add" => {
                let f = SignedForward::decode(req.bytes("forward").ok_or("forward missing")?)
                    .map_err(|e| e.to_string())?;
                let db = f.forward.db;
                self.store().insert_forward(&f).map_err(|e| e.to_string())?;
                // Published from here: this node holds the whole successor.
                self.synced
                    .lock()
                    .expect("synced")
                    .insert(f.forward.successor);
                self.push(&db, vec![f.id()]);
                self.check_succession(db).await?;
                out.insert("id", Value::Text(f.id().to_hex()))
                    .insert("successor", Value::Text(f.forward.successor.to_hex()));
            }
            "late" => {
                let db = self.late_parent(&req)?;
                let late = self.late_entries(&db)?;
                out.insert("db", Value::Text(db.to_hex())).insert(
                    "entries",
                    Value::Array(
                        late.iter()
                            .map(|l| {
                                let h = &l.entry.header;
                                let mut m = Map::new();
                                m.insert("id", Value::Text(l.entry.id().to_hex()))
                                    .insert("path", Value::Text(h.path.display()))
                                    .insert(
                                        "op",
                                        Value::Text(
                                            match h.op {
                                                Op::Put => "put",
                                                Op::Delete => "del",
                                                Op::Negate => "negate",
                                            }
                                            .into(),
                                        ),
                                    )
                                    .insert("ts", Value::Uint(h.ts))
                                    .insert("own", Value::Bool(l.own))
                                    .insert("done", Value::Bool(l.done))
                                    .insert_opt("agent", l.agent.clone().map(Value::Text));
                                Value::Map(m)
                            })
                            .collect(),
                    ),
                );
            }
            "late.resubmit" => {
                let db = self.late_parent(&req)?;
                let (written, skipped) = self.resubmit_late(&db).await?;
                out.insert("written", Value::Uint(written))
                    .insert("skipped", Value::Uint(skipped));
            }
            "gc" => {
                // Design 0004 §8.3 step 4. Named explicitly: it deletes records.
                if req.text("db").is_none_or(str::is_empty) {
                    return Err("name the database to collect".into());
                }
                let db = self.resolve_db_exact(&req)?;
                let child =
                    *self.followed.lock().expect("followed").get(&db).ok_or(
                        "only a database whose successor this node follows can be collected",
                    )?;
                let now = now_ms();
                let since = {
                    let store = self.store();
                    let fwd = store
                        .forwards(&db)
                        .map_err(|e| e.to_string())?
                        .into_iter()
                        .find(|f| f.forward.successor == child)
                        .ok_or("no forward")?;
                    store
                        .first_seen(&db, &fwd.id())
                        .map_err(|e| e.to_string())?
                        .unwrap_or(0)
                };
                let until = since.saturating_add(GRACE);
                if now < until && req.flag("force") != Some(true) {
                    return Err(format!(
                        "{} is read-only until {until} (ms; {} days after the forward): \
                         late writes may still arrive. Pass force to collect now",
                        &db.to_hex()[..12],
                        GRACE / (24 * 3600 * 1000)
                    ));
                }
                let removed = self.store().retire(&db, now).map_err(|e| e.to_string())?;
                for file in ["peers", "writecerts"] {
                    remove_pairs(&self.home.join(file), &db.to_hex()).map_err(|e| e.to_string())?;
                }
                log(format!(
                    "{} collected: {removed} records deleted, its stub kept",
                    &db.to_hex()[..12]
                ));
                out.insert("removed", Value::Uint(removed))
                    .insert("successor", Value::Text(child.to_hex()));
            }
            "value.has" => {
                let h =
                    Digest::from_hex(req.text("hash").ok_or("hash missing")?).ok_or("bad hash")?;
                out.insert(
                    "has",
                    Value::Bool(self.values.has(h).await.map_err(|e| e.to_string())?),
                );
            }
            other => return Err(format!("unknown op {other:?}")),
        }
        Ok(out)
    }
}

/// The ledger protocol on the router.
#[derive(Clone)]
struct SyncProtocol(Arc<Node>);

impl std::fmt::Debug for SyncProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncProtocol")
    }
}

impl ProtocolHandler for SyncProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.0.clone().serve_connection(conn).await;
        Ok(())
    }
}

/// Moves the values of a schema 3 store into the blob store, then drops its table.
async fn migrate_values(
    store: &Mutex<Store>,
    values: &BlobValues,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut after = None;
    let mut moved = 0usize;
    loop {
        let page = store
            .lock()
            .expect("store mutex")
            .legacy_values(after.as_ref(), 256)?;
        let Some((last, _)) = page.last() else {
            break;
        };
        after = Some(*last);
        for (_, v) in page {
            values.put(v).await?;
            moved += 1;
        }
    }
    // Committed before the old table goes.
    values.0.sync_db().await?;
    if store.lock().expect("store mutex").drop_legacy_values()? {
        log(format!("moved {moved} value(s) into the blob store"));
    }
    Ok(())
}

async fn serve_rpc(node: Arc<Node>, socket: PathBuf) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let node = node.clone();
        tokio::spawn(async move {
            while let Ok(Some(req)) = sameroot_rpc::read_request(&mut stream).await {
                let resp = node.handle(req).await;
                if sameroot_rpc::write_response(&mut stream, &resp)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = home();
    std::fs::create_dir_all(&home)?;
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
    let device = SecretKey::from_seed(load_or_create_key(&home.join("device.key"))?);
    let endpoint_key =
        iroh::SecretKey::from_bytes(&load_or_create_key(&home.join("endpoint.key"))?);
    let store = Arc::new(Mutex::new(Store::open(home.join("store.redb"))?));
    let held: Arc<Mutex<HashSet<Digest>>> = Arc::default();
    let writing: Arc<Mutex<HashSet<Digest>>> = Arc::default();
    let blobs = {
        let root = home.join("blobs");
        let mut opts = BlobOptions::new(&root);
        opts.gc = Some(GcConfig {
            interval: std::env::var("SAMEROOT_BLOB_GC_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .map_or(BLOB_GC, Duration::from_secs),
            add_protected: Some(protect(store.clone(), writing.clone(), held.clone())),
        });
        FsStore::load_with_opts(root.join("blobs.db"), opts).await?
    };
    let values = BlobValues(blobs.clone());
    migrate_values(&store, &values).await?;

    // Networks that allow only HTTPS: trust the operating system's certificate
    // store (corporate roots included) and honour HTTPS_PROXY/HTTP_PROXY, so the
    // relay connection — a WebSocket over 443 — gets through (design §12, §19.7).
    let relays = std::env::var("SAMEROOT_RELAY").ok();
    let direct_only = relays.as_deref() == Some("none");
    let builder = if direct_only {
        // No relays and no address lookup: peers are reached by their addresses.
        log("relays: none (direct connections only)");
        Endpoint::builder(presets::Minimal).relay_mode(iroh::RelayMode::Disabled)
    } else {
        Endpoint::builder(presets::N0)
    };
    let mut builder = builder
        .secret_key(endpoint_key)
        .ca_tls_config(iroh::tls::CaTlsConfig::system())
        .proxy_from_env();
    // Our own relays instead of n0's: SAMEROOT_RELAY=https://relay.example.org[,…]
    if let Some(relays) = relays.filter(|_| !direct_only) {
        let urls = relays
            .split(',')
            .map(|u| u.trim().parse::<iroh::RelayUrl>())
            .collect::<Result<Vec<_>, _>>()?;
        log(format!("relays: {relays}"));
        builder = builder.relay_mode(iroh::RelayMode::Custom(urls.into_iter().collect()));
    }
    let endpoint = builder.bind().await?;
    if !direct_only
        && tokio::time::timeout(Duration::from_secs(10), endpoint.online())
            .await
            .is_err()
    {
        log("no home relay after 10 s; continuing with direct addresses only");
    }
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let node = Arc::new(Node {
        home: home.clone(),
        store,
        values,
        downloader: Downloader::new(&blobs, &endpoint),
        device,
        endpoint,
        sessions: Mutex::new(Vec::new()),
        events: events_tx,
        fetching: Mutex::new(HashSet::new()),
        held,
        writing,
        pinned: Mutex::new(
            read_pairs(&home.join("successors"))
                .into_iter()
                .filter_map(|(k, v)| Some((Digest::from_hex(&k)?, Digest::from_hex(&v)?)))
                .collect(),
        ),
        // Followed before a restart: followed at once, with no wait.
        followed: Mutex::new(
            read_pairs(&home.join("followed"))
                .into_iter()
                .filter_map(|(k, v)| Some((Digest::from_hex(&k)?, Digest::from_hex(&v)?)))
                .collect(),
        ),
        warned: Mutex::new(HashSet::new()),
        synced: Mutex::new(HashSet::new()),
        pinned_at: Mutex::new(
            read_pairs(&home.join("successors"))
                .into_iter()
                .filter_map(|(k, _)| Some((Digest::from_hex(&k)?, Instant::now())))
                .collect(),
        ),
        wrong_size: Mutex::new(HashSet::new()),
        backoff: Mutex::new(HashMap::new()),
        fetch_slots: tokio::sync::Semaphore::new(MAX_FETCHES),
    });
    // Two protocols on one endpoint: the ledger, and values by hash for anyone.
    let router = Router::builder(node.endpoint.clone())
        .accept(ALPN, SyncProtocol(node.clone()))
        .accept(iroh_blobs::ALPN, BlobsProtocol::new(&blobs, None))
        .spawn();
    log(format!(
        "ready — device {} · endpoint {} · {} database(s)",
        node.device.public().short(),
        node.endpoint.id().fmt_short(),
        node.store().databases()?.len()
    ));

    // Fan-out: a winner that arrived through one session rings the others.
    let n = node.clone();
    tokio::spawn(async move {
        while let Some(ev) = events_rx.recv().await {
            match ev {
                // Forward what arrived to the other sessions right away; the peer
                // it came from already has it and admits it as a duplicate.
                Event::Added { db, id } => n.push(&db, vec![id]),
                Event::Joined(db) => {
                    log(format!("joined database {}", &db.to_hex()[..12]));
                    // Perhaps the successor of a database here.
                    let n = n.clone();
                    tokio::spawn(async move { n.check_successions().await });
                }
                Event::InSync(db) => {
                    n.synced.lock().expect("synced").insert(db);
                }
                // A put without its value: fetch it from the database's peers.
                Event::MissingValue { db, hash, size } => n.fetch(db, hash, size),
            }
        }
    });

    // Values the ledgers reference and this node lacks (after a restart, or when
    // no peer had one at first): look for them again now and then.
    let n = node.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(VALUE_SWEEP);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            n.check_successions().await;
            n.admit_due();
            if let Err(e) = n.sweep_values().await {
                log(format!("value sweep: {e}"));
            }
        }
    });

    // Redial peers from invites.
    let n = node.clone();
    tokio::spawn(async move {
        let mut last: HashMap<String, String> = HashMap::new();
        loop {
            for (db_hex, invite) in read_pairs(&n.home.join("peers")) {
                let (Some(db), Ok(inv)) = (Digest::from_hex(&db_hex), Invite::parse(&invite))
                else {
                    continue;
                };
                if let Err(e) = n.dial(db, &inv).await {
                    let key = format!("{db_hex}{}", inv.endpoint);
                    if last.get(&key) != Some(&e) {
                        log(format!(
                            "dial {}: {e}",
                            &inv.endpoint[..inv.endpoint.len().min(10)]
                        ));
                        last.insert(key, e);
                    }
                }
            }
            tokio::time::sleep(REDIAL).await;
        }
    });

    let socket = home.join("samerootd.sock");
    log(format!(
        "local clients connect through {}",
        socket.display()
    ));
    let rpc = tokio::spawn(serve_rpc(node.clone(), socket));
    // systemd stops services with SIGTERM: close the endpoint on it too, so peers
    // see the connection end at once instead of after the QUIC idle timeout.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = rpc => { r??; }
        _ = tokio::signal::ctrl_c() => log("stopping"),
        _ = term.recv() => log("stopping (SIGTERM)"),
    }
    // Closes the endpoint too, so peers see the connection end at once.
    let _ = router.shutdown().await;
    let _ = blobs.shutdown().await;
    Ok(())
}
