//! Storage for Sameroot, schema 5 (design 0003 §9, design 0004).
//!
//! An embedded store on redb. Per database it keeps the signed genesis, the ledger
//! (entries and voids, each admitted by `sameroot-core` before it is stored), the
//! certificates their chains use, the ledger trie's nodes by nibble path (updated
//! along one path per admitted record), and records deferred by the local clock.
//! The state is derived from the ledger by the contract's resolution and cached
//! until the ledger changes or a put expires.
//!
//! Values are not kept here: they live in a blob store by plain BLAKE3 (the node
//! uses iroh-blobs). A node may hold or lack any value; the ledger never depends on
//! it. Schema 3 kept values in a `values` table; a schema 3 file opens as schema 4
//! and keeps that table until the node has moved its values out
//! ([`Store::legacy_values`], [`Store::drop_legacy_values`]).
//!
//! The store is synchronous; callers that share it across tasks wrap it in a mutex.

use std::collections::{HashMap, HashSet};
use std::path::Path as FsPath;
use std::sync::Mutex;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use sameroot_core::cert::{MAX_CHAIN, chain_ids};
use sameroot_core::ledger::{Kind, Node, Proof, Trie};
use sameroot_core::refs::{RefIndex, entry_ref, ledger_commitment, void_ref};
use sameroot_core::resolve::{self, LedgerEntry, LedgerVoid, Resolved, State};
use sameroot_core::verify::deferred;
use sameroot_core::{
    Digest, Genesis, Path, PublicKey, Reject, SignedCert, SignedEntry, SignedForward,
    SignedGenesis, SignedVoid, Subspace, VoidTarget, value_hash, verify_entry, verify_forward,
    verify_void,
};

const GENESIS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("genesis");
const ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entries");
const VOIDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("voids");
/// Forward id → signed forward (design 0004 §8.1).
const FORWARDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("forwards");
/// Void id → its keep list, concatenated ids in ascending order (design 0004 §5.4).
const KEEPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("keeps");
/// db ‖ record id → when this node first admitted it (ms, local clock). Not part of
/// the format: the one clock a thief can't set, used to build keep lists (design
/// 0004 §5.6).
const FIRST_SEEN: TableDefinition<&[u8], u64> = TableDefinition::new("first_seen");
const CERTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("certs");
/// Schema 3 only: value hash → value, until moved to the blob store.
const LEGACY_VALUES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("values");
/// db ‖ record id → kind ‖ chain root ‖ chain ids.
const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");
/// db ‖ path length ‖ nibbles → node wire form.
const NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nodes");
/// db ‖ entry id → signed entry (deferred by the local clock).
const DEFERRED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("deferred");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

/// The store's own schema version, independent of the format version.
pub const SCHEMA_VERSION: u64 = 5;

/// Store errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The storage engine failed.
    #[error("storage: {0}")]
    Storage(String),
    /// The database is not known to this store.
    #[error("unknown database {0}")]
    UnknownDatabase(Digest),
    /// The record failed admission.
    #[error("rejected: {0}")]
    Rejected(#[from] Reject),
    /// Stored bytes failed to decode (corruption).
    #[error("corrupt stored object: {0}")]
    Corrupt(String),
    /// The database was retired after its succession: only its stub is kept.
    #[error("database {0} is retired (succeeded and collected)")]
    Retired(Digest),
    /// The file was written by another schema (no migration: recreate it).
    #[error("unsupported store schema {0} (expected {SCHEMA_VERSION}; recreate the store)")]
    Schema(u64),
}

macro_rules! storage_err {
    ($($t:ty),*) => { $(impl From<$t> for Error { fn from(e: $t) -> Self { Error::Storage(e.to_string()) } })* };
}
storage_err!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// What happened to an inserted record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Admitted into the ledger (the root changed).
    Added,
    /// Already in the ledger.
    Duplicate,
    /// Valid, but ahead of the local clock: kept, admitted later by
    /// [`Store::admit_due`].
    Deferred,
}

/// A ledger record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// An entry.
    Entry(SignedEntry),
    /// A void.
    Void(SignedVoid),
    /// A succession forward.
    Forward(SignedForward),
}

impl Record {
    /// The record id.
    pub fn id(&self) -> Digest {
        match self {
            Record::Entry(e) => e.id(),
            Record::Void(v) => v.id(),
            Record::Forward(f) => f.id(),
        }
    }

    /// The ledger kind.
    pub fn kind(&self) -> Kind {
        match self {
            Record::Entry(_) => Kind::Entry,
            Record::Void(_) => Kind::Void,
            Record::Forward(_) => Kind::Forward,
        }
    }

    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Record::Entry(e) => e.encode(),
            Record::Void(v) => v.encode(),
            Record::Forward(f) => f.encode(),
        }
    }

    /// Decodes a record of a known kind.
    pub fn decode(
        kind: Kind,
        bytes: &[u8],
    ) -> std::result::Result<Record, sameroot_core::FormatError> {
        Ok(match kind {
            Kind::Entry => Record::Entry(SignedEntry::decode(bytes)?),
            Kind::Void => Record::Void(SignedVoid::decode(bytes)?),
            Kind::Forward => Record::Forward(SignedForward::decode(bytes)?),
        })
    }
}

/// A database's ledger as resolution and the reference index see it.
struct Ledger {
    entries: Vec<LedgerEntry>,
    voids: Vec<LedgerVoid>,
    refs: RefIndex,
}

fn table_of(kind: Kind) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
    match kind {
        Kind::Entry => ENTRIES,
        Kind::Void => VOIDS,
        Kind::Forward => FORWARDS,
    }
}

fn ids_bytes(ids: &[Digest]) -> Vec<u8> {
    ids.iter().flat_map(|d| d.0).collect()
}

struct CachedState {
    generation: u64,
    as_of: u64,
    valid_until: u64,
    state: State,
    /// The values of the puts that count (see [`Store::live_values`]).
    live: Vec<(Digest, u64)>,
}

/// The embedded store.
pub struct Store {
    db: Database,
    tries: Mutex<HashMap<Digest, Trie>>,
    states: Mutex<HashMap<Digest, CachedState>>,
    /// Reference roots by database, with the generation they were computed at.
    refs: Mutex<HashMap<Digest, (u64, Digest)>>,
    generation: Mutex<HashMap<Digest, u64>>,
    /// The write transaction of a batch in progress ([`Store::batch`]).
    batch: Mutex<Option<redb::WriteTransaction>>,
    /// A write of the batch in progress failed: it is aborted.
    batch_failed: std::sync::atomic::AtomicBool,
}

fn digest(bytes: &[u8]) -> Result<Digest> {
    Ok(Digest(
        bytes
            .try_into()
            .map_err(|_| Error::Corrupt("digest".into()))?,
    ))
}

fn corrupt(e: impl std::fmt::Display) -> Error {
    Error::Corrupt(e.to_string())
}

fn dbkey(db: &Digest, rest: &[u8]) -> Vec<u8> {
    let mut k = db.0.to_vec();
    k.extend_from_slice(rest);
    k
}

fn node_key(db: &Digest, path: &[u8]) -> Vec<u8> {
    let mut k = db.0.to_vec();
    k.push(path.len() as u8);
    k.extend_from_slice(path);
    k
}

fn db_range(db: &Digest) -> (Vec<u8>, Vec<u8>) {
    let start = db.0.to_vec();
    let mut end = db.0.to_vec();
    end.push(0xff);
    end.extend_from_slice(&[0xff; 64]);
    (start, end)
}

fn retired_key(db: &Digest) -> String {
    format!("retired/{}", db.to_hex())
}

fn record_meta(kind: Kind, root: &PublicKey, chain: &[Digest]) -> Vec<u8> {
    let mut v = vec![kind as u8];
    v.extend_from_slice(&root.0);
    for c in chain {
        v.extend_from_slice(&c.0);
    }
    v
}

impl Store {
    /// Opens or creates a store file.
    pub fn open(path: impl AsRef<FsPath>) -> Result<Store> {
        Store::init(Database::create(path)?)
    }

    /// A store in memory (tests and simulations).
    pub fn in_memory() -> Result<Store> {
        Store::init(
            Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?,
        )
    }

    fn init(db: Database) -> Result<Store> {
        let tx = db.begin_write()?;
        {
            for t in [
                GENESIS, ENTRIES, VOIDS, FORWARDS, KEEPS, CERTS, RECORDS, NODES, DEFERRED,
            ] {
                tx.open_table(t)?;
            }
            let mut meta = tx.open_table(META)?;
            tx.open_table(FIRST_SEEN)?;
            let schema = meta.get("schema")?.map(|g| g.value());
            match schema {
                // Schema 3 differs only by its values table, which stays until drained;
                // schema 4 only lacks the forward and keep tables, created above.
                None | Some(3) | Some(4) => {
                    meta.insert("schema", SCHEMA_VERSION)?;
                }
                Some(SCHEMA_VERSION) => {}
                Some(other) => return Err(Error::Schema(other)),
            }
        }
        tx.commit()?;
        Ok(Store {
            db,
            tries: Mutex::new(HashMap::new()),
            states: Mutex::new(HashMap::new()),
            refs: Mutex::new(HashMap::new()),
            generation: Mutex::new(HashMap::new()),
            batch: Mutex::new(None),
            batch_failed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Runs `f` with every admission writing into one transaction, committed once at
    /// the end: a frame of records costs one commit instead of one each. Reads inside
    /// `f` don't see its writes yet (admission doesn't need them: each record comes
    /// with its own certificates). If any write fails, nothing of the batch is kept.
    pub fn batch<T>(&self, f: impl FnOnce(&Store) -> T) -> Result<T> {
        {
            let mut b = self.batch.lock().expect("batch");
            if b.is_some() {
                drop(b);
                return Ok(f(self));
            }
            *b = Some(self.db.begin_write()?);
        }
        self.batch_failed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let out = f(self);
        let tx = self
            .batch
            .lock()
            .expect("batch")
            .take()
            .expect("batch open");
        let failed = self
            .batch_failed
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        let committed = if failed {
            drop(tx);
            Err(Error::Storage(
                "a write of the batch failed; nothing was kept".into(),
            ))
        } else {
            tx.commit().map_err(Error::from)
        };
        if let Err(e) = committed {
            // Memory and disk in step: the tries reload on next use.
            self.tries.lock().expect("trie cache").clear();
            self.states.lock().expect("state cache").clear();
            return Err(e);
        }
        Ok(out)
    }

    /// Runs `f` on the batch's transaction if a batch is open, else on a transaction of
    /// its own, committed.
    fn with_write<T>(&self, f: impl FnOnce(&redb::WriteTransaction) -> Result<T>) -> Result<T> {
        let mut b = self.batch.lock().expect("batch");
        if let Some(tx) = b.as_mut() {
            let r = f(tx);
            if r.is_err() {
                self.batch_failed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            return r;
        }
        drop(b);
        let tx = self.db.begin_write()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// Adds a database by its signed genesis (verified when it was decoded).
    pub fn add_database(&self, genesis: &SignedGenesis) -> Result<Digest> {
        let id = genesis.id();
        let tx = self.db.begin_write()?;
        tx.open_table(GENESIS)?
            .insert(id.0.as_slice(), genesis.encode().as_slice())?;
        tx.commit()?;
        Ok(id)
    }

    /// The signed genesis of a database.
    pub fn genesis(&self, db: &Digest) -> Result<Option<SignedGenesis>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(GENESIS)?;
        t.get(db.0.as_slice())?
            .map(|g| SignedGenesis::decode(g.value()).map_err(corrupt))
            .transpose()
    }

    fn genesis_of(&self, db: &Digest) -> Result<Genesis> {
        Ok(self
            .genesis(db)?
            .ok_or(Error::UnknownDatabase(*db))?
            .genesis)
    }

    /// All databases in this store.
    pub fn databases(&self) -> Result<Vec<Digest>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(GENESIS)?;
        t.iter()?.map(|r| digest(r?.0.value())).collect()
    }

    /// Stores a certificate given to this node by its owner (its own write
    /// delegation). Peers' certificates are stored only with admitted records.
    pub fn add_cert(&self, cert: &SignedCert) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(CERTS)?
            .insert(cert.id().0.as_slice(), cert.encode().as_slice())?;
        tx.commit()?;
        Ok(())
    }

    /// A certificate by id.
    pub fn cert(&self, id: &Digest) -> Result<Option<SignedCert>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(CERTS)?;
        t.get(id.0.as_slice())?
            .map(|g| SignedCert::decode(g.value()).map_err(corrupt))
            .transpose()
    }

    /// The certificates of a chain starting at `leaf`, leaf first (those present).
    pub fn chain_from(&self, leaf: Option<Digest>) -> Result<Vec<SignedCert>> {
        let mut out = Vec::new();
        let mut next = leaf;
        while let Some(id) = next {
            let Some(c) = self.cert(&id)? else { break };
            next = c.cert.parent;
            out.push(c);
            if out.len() >= MAX_CHAIN {
                break;
            }
        }
        Ok(out)
    }

    /// The certificates a record's admission depends on.
    pub fn dependencies(&self, record: &Record) -> Result<Vec<SignedCert>> {
        match record {
            Record::Entry(e) => self.chain_from(e.header.cert),
            Record::Void(v) => match v.void.target {
                VoidTarget::Cert(c) => self.chain_from(Some(c)),
                VoidTarget::Key(_) => Ok(Vec::new()),
            },
            Record::Forward(_) => Ok(Vec::new()),
        }
    }

    /// The keep list of a void, if it has one (design 0004 §5.4: retained and served
    /// for as long as the void).
    pub fn keep_list(&self, void: &Digest) -> Result<Option<Vec<Digest>>> {
        let tx = self.db.begin_read()?;
        let Some(b) = tx.open_table(KEEPS)?.get(void.0.as_slice())? else {
            return Ok(None);
        };
        Ok(Some(
            b.value().chunks(32).map(digest).collect::<Result<_>>()?,
        ))
    }

    fn with_trie<T>(&self, db: &Digest, f: impl FnOnce(&mut Trie) -> T) -> Result<T> {
        let mut tries = self.tries.lock().expect("trie cache");
        if !tries.contains_key(db) {
            let trie = self.load_trie(db)?;
            tries.insert(*db, trie);
        }
        Ok(f(tries.get_mut(db).expect("just loaded")))
    }

    fn load_trie(&self, db: &Digest) -> Result<Trie> {
        let tx = self.db.begin_read()?;
        let (start, end) = db_range(db);
        let mut nodes = HashMap::new();
        for r in tx
            .open_table(NODES)?
            .range(start.as_slice()..end.as_slice())?
        {
            let (k, v) = r?;
            let k = k.value();
            let path = k[33..].to_vec();
            nodes.insert(
                path.clone(),
                Node::decode_at(v.value(), &path).map_err(corrupt)?,
            );
        }
        let count = tx
            .open_table(RECORDS)?
            .range(start.as_slice()..end.as_slice())?
            .count();
        Ok(if nodes.is_empty() {
            Trie::new()
        } else {
            Trie::from_nodes(nodes, count)
        })
    }

    fn bump(&self, db: &Digest) {
        *self
            .generation
            .lock()
            .expect("generation")
            .entry(*db)
            .or_default() += 1;
    }

    fn generation(&self, db: &Digest) -> u64 {
        self.generation
            .lock()
            .expect("generation")
            .get(db)
            .copied()
            .unwrap_or(0)
    }

    fn contains(&self, db: &Digest, id: &Digest) -> Result<bool> {
        let tx = self.db.begin_read()?;
        Ok(tx
            .open_table(RECORDS)?
            .get(dbkey(db, &id.0).as_slice())?
            .is_some())
    }

    /// Admits an entry. `certs` (from the peer that sent it) are used for its chain
    /// together with stored certificates, and stored only if the entry is admitted.
    /// Values aren't needed: they live in the node's blob store, by `valueHash`.
    pub fn insert_entry(
        &self,
        entry: &SignedEntry,
        certs: &[SignedCert],
        now: u64,
    ) -> Result<Outcome> {
        let h = &entry.header;
        let genesis = self.genesis_of(&h.db)?;
        let lookup = |id: &Digest| {
            certs
                .iter()
                .find(|c| c.id() == *id)
                .cloned()
                .or_else(|| self.cert(id).ok().flatten())
        };
        let accepted = verify_entry(&genesis, &h.db, entry, &lookup)?;
        if self.contains(&h.db, &accepted.id)? {
            return Ok(Outcome::Duplicate);
        }
        let chain = chain_ids(h, &lookup);
        let used: Vec<SignedCert> = chain.iter().filter_map(&lookup).collect();
        if deferred(h, now, genesis.limits.ts_skew) {
            // Keep the verified chain with it: the certificates may have come only with
            // this entry, and its admission later must not depend on seeing them again.
            self.with_write(|tx| {
                tx.open_table(DEFERRED)?.insert(
                    dbkey(&h.db, &accepted.id.0).as_slice(),
                    entry.encode().as_slice(),
                )?;
                let mut c = tx.open_table(CERTS)?;
                for cert in &used {
                    c.insert(cert.id().0.as_slice(), cert.encode().as_slice())?;
                }
                Ok(())
            })?;
            return Ok(Outcome::Deferred);
        }
        self.admit(
            &h.db,
            Kind::Entry,
            accepted.id,
            &entry.encode(),
            &record_meta(Kind::Entry, &accepted.owner, &chain),
            &used,
            None,
        )
    }

    /// Admits a void (design 0004 §5.2). Its certificate and the chain above come in
    /// `certs` or are stored; its keep list, when it has `keep`, comes in `keep` (or
    /// the void stays pending).
    pub fn insert_void(
        &self,
        void: &SignedVoid,
        certs: &[SignedCert],
        keep: Option<&[Digest]>,
    ) -> Result<Outcome> {
        let db = void.void.db;
        let genesis = self.genesis_of(&db)?;
        let lookup = |id: &Digest| {
            certs
                .iter()
                .find(|c| c.id() == *id)
                .cloned()
                .or_else(|| self.cert(id).ok().flatten())
        };
        let accepted = verify_void(&genesis, &db, void, &lookup, keep)?;
        if self.contains(&db, &accepted.id)? {
            return Ok(Outcome::Duplicate);
        }
        let used = match void.void.target {
            VoidTarget::Cert(c) => {
                let mut used = Vec::new();
                let mut next = Some(c);
                while let Some(c) = next.and_then(|n| lookup(&n)) {
                    next = c.cert.parent;
                    used.push(c);
                    if used.len() >= MAX_CHAIN {
                        break;
                    }
                }
                used
            }
            VoidTarget::Key(_) => Vec::new(),
        };
        let keep_bytes = void.void.keep.and(keep).map(ids_bytes);
        self.admit(
            &db,
            Kind::Void,
            accepted.id,
            &void.encode(),
            &record_meta(Kind::Void, &accepted.root, &accepted.authority),
            &used,
            keep_bytes.as_deref(),
        )
    }

    /// Admits a forward (design 0004 §8.1).
    pub fn insert_forward(&self, forward: &SignedForward) -> Result<Outcome> {
        let db = forward.forward.db;
        let genesis = self.genesis_of(&db)?;
        let id = verify_forward(&genesis, &db, forward)?;
        if self.contains(&db, &id)? {
            return Ok(Outcome::Duplicate);
        }
        self.admit(
            &db,
            Kind::Forward,
            id,
            &forward.encode(),
            &record_meta(Kind::Forward, &genesis.owner, &[]),
            &[],
            None,
        )
    }

    /// The certificates stored for a database.
    pub fn certs(&self, db: &Digest) -> Result<Vec<SignedCert>> {
        let tx = self.db.begin_read()?;
        let mut out = Vec::new();
        for r in tx.open_table(CERTS)?.iter()? {
            let (_, v) = r?;
            let c = SignedCert::decode(v.value()).map_err(corrupt)?;
            if c.cert.db == *db {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// When this node first admitted a record (`None` for records admitted before
    /// the node kept track).
    pub fn first_seen(&self, db: &Digest, id: &Digest) -> Result<Option<u64>> {
        let tx = self.db.begin_read()?;
        Ok(tx
            .open_table(FIRST_SEEN)?
            .get(dbkey(db, &id.0).as_slice())?
            .map(|g| g.value()))
    }

    /// The entries whose chain contains `cert`, each with when this node first saw
    /// it: what a void of `cert` decides about (design 0004 §5.6). Records admitted
    /// before the node kept track have `None`.
    pub fn entries_under(
        &self,
        db: &Digest,
        cert: &Digest,
    ) -> Result<Vec<(SignedEntry, Option<u64>)>> {
        self.entries_where(db, |e| e.chain.contains(cert))
    }

    /// Every admitted entry of a database, each with when this node first saw it.
    pub fn entries_seen(&self, db: &Digest) -> Result<Vec<(SignedEntry, Option<u64>)>> {
        self.entries_where(db, |_| true)
    }

    fn entries_where(
        &self,
        db: &Digest,
        keep: impl Fn(&LedgerEntry) -> bool,
    ) -> Result<Vec<(SignedEntry, Option<u64>)>> {
        let ids: Vec<Digest> = self
            .ledger(db)?
            .entries
            .into_iter()
            .filter(|e| keep(e))
            .map(|e| e.id)
            .collect();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(e) = self.entry(db, &id)? {
                out.push((e, self.first_seen(db, &id)?));
            }
        }
        Ok(out)
    }

    /// What the voids of a database target (certificates and keys).
    pub fn void_targets(&self, db: &Digest) -> Result<Vec<VoidTarget>> {
        Ok(self
            .ledger(db)?
            .voids
            .into_iter()
            .map(|v| v.target)
            .collect())
    }

    /// When a database was retired, if it was.
    pub fn retired(&self, db: &Digest) -> Result<Option<u64>> {
        let tx = self.db.begin_read()?;
        Ok(tx
            .open_table(META)?
            .get(retired_key(db).as_str())?
            .map(|g| g.value()))
    }

    /// Garbage collection after a succession (design 0004 §8.3 step 4): deletes the
    /// records of a database, its trie, its certificates, keep lists, first-seen
    /// times and deferred entries. The stub stays: the genesis and the forwards (the
    /// cut root is in them), under a trie of the forwards alone. Later admissions are
    /// refused. Returns how many records were deleted.
    ///
    /// The values are not touched here: they live in the node's blob store, and may
    /// be shared with the successor by hash.
    pub fn retire(&self, db: &Digest, now: u64) -> Result<u64> {
        let forwards: Vec<Digest> = self.forwards(db)?.iter().map(|f| f.id()).collect();
        if forwards.is_empty() {
            return Err(Error::Rejected(Reject::Shape));
        }
        let (start, end) = db_range(db);
        let tx = self.db.begin_write()?;
        let removed;
        {
            let mut records = tx.open_table(RECORDS)?;
            let mut gone: Vec<(Vec<u8>, Kind, Digest)> = Vec::new();
            for r in records.range(start.as_slice()..end.as_slice())? {
                let (k, meta) = r?;
                let kind =
                    Kind::from_code(meta.value()[0] as u64).ok_or_else(|| corrupt("kind"))?;
                if kind != Kind::Forward {
                    gone.push((k.value().to_vec(), kind, digest(&k.value()[32..])?));
                }
            }
            let mut entries = tx.open_table(ENTRIES)?;
            let mut voids = tx.open_table(VOIDS)?;
            let mut keeps = tx.open_table(KEEPS)?;
            let mut first_seen = tx.open_table(FIRST_SEEN)?;
            for (k, kind, id) in &gone {
                records.remove(k.as_slice())?;
                first_seen.remove(k.as_slice())?;
                match kind {
                    Kind::Entry => {
                        entries.remove(id.0.as_slice())?;
                    }
                    Kind::Void => {
                        voids.remove(id.0.as_slice())?;
                        keeps.remove(id.0.as_slice())?;
                    }
                    Kind::Forward => {}
                }
            }
            removed = gone.len() as u64;
            tx.open_table(DEFERRED)?
                .retain_in(start.as_slice()..end.as_slice(), |_, _| false)?;
            let mut nodes = tx.open_table(NODES)?;
            nodes.retain_in(start.as_slice()..end.as_slice(), |_, _| false)?;
            let stub = Trie::build(forwards.iter().map(|f| (Kind::Forward, *f)));
            for (path, node) in stub.nodes() {
                nodes.insert(node_key(db, path).as_slice(), node.encode().as_slice())?;
            }
            let mut certs = tx.open_table(CERTS)?;
            let mut theirs = Vec::new();
            for r in certs.iter()? {
                let (k, v) = r?;
                if SignedCert::decode(v.value()).map_err(corrupt)?.cert.db == *db {
                    theirs.push(k.value().to_vec());
                }
            }
            for k in theirs {
                certs.remove(k.as_slice())?;
            }
            tx.open_table(META)?.insert(retired_key(db).as_str(), now)?;
        }
        tx.commit()?;
        self.tries.lock().expect("trie cache").remove(db);
        self.states.lock().expect("state cache").remove(db);
        self.refs.lock().expect("ref cache").remove(db);
        self.bump(db);
        Ok(removed)
    }

    /// The forwards out of a database.
    pub fn forwards(&self, db: &Digest) -> Result<Vec<SignedForward>> {
        let tx = self.db.begin_read()?;
        let (start, end) = db_range(db);
        let forwards = tx.open_table(FORWARDS)?;
        let mut out = Vec::new();
        for r in tx
            .open_table(RECORDS)?
            .range(start.as_slice()..end.as_slice())?
        {
            let (k, meta) = r?;
            if meta.value()[0] != Kind::Forward as u8 {
                continue;
            }
            let id = digest(&k.value()[32..])?;
            let b = forwards
                .get(id.0.as_slice())?
                .ok_or_else(|| corrupt("forward"))?;
            out.push(SignedForward::decode(b.value()).map_err(corrupt)?);
        }
        Ok(out)
    }

    // One record's whole admission: its bytes, metadata, dependencies and keep list.
    #[allow(clippy::too_many_arguments)]
    fn admit(
        &self,
        db: &Digest,
        kind: Kind,
        id: Digest,
        bytes: &[u8],
        meta: &[u8],
        certs: &[SignedCert],
        keep: Option<&[u8]>,
    ) -> Result<Outcome> {
        if self.retired(db)?.is_some() {
            return Err(Error::Retired(*db));
        }
        let changed: Vec<(Vec<u8>, Vec<u8>)> = self.with_trie(db, |t| {
            t.insert(kind, id)
                .into_iter()
                .map(|p| {
                    let node = t.node(&p).expect("changed node exists").encode();
                    (p, node)
                })
                .collect()
        })?;
        if changed.is_empty() {
            return Ok(Outcome::Duplicate);
        }
        let write = || -> Result<()> {
            self.with_write(|tx| {
                tx.open_table(table_of(kind))?
                    .insert(id.0.as_slice(), bytes)?;
                if let Some(k) = keep {
                    tx.open_table(KEEPS)?.insert(id.0.as_slice(), k)?;
                }
                tx.open_table(RECORDS)?
                    .insert(dbkey(db, &id.0).as_slice(), meta)?;
                let mut c = tx.open_table(CERTS)?;
                for cert in certs {
                    c.insert(cert.id().0.as_slice(), cert.encode().as_slice())?;
                }
                let mut nodes = tx.open_table(NODES)?;
                for (p, node) in &changed {
                    nodes.insert(node_key(db, p).as_slice(), node.as_slice())?;
                }
                tx.open_table(DEFERRED)?
                    .remove(dbkey(db, &id.0).as_slice())?;
                tx.open_table(FIRST_SEEN)?
                    .insert(dbkey(db, &id.0).as_slice(), sameroot_core::now_ms())?;
                Ok(())
            })
        };
        if let Err(e) = write() {
            // Keep memory and disk in step: reload the trie on next use.
            self.tries.lock().expect("trie cache").remove(db);
            return Err(e);
        }
        self.bump(db);
        Ok(Outcome::Added)
    }

    /// Admits deferred entries whose time has come; returns their ids.
    pub fn admit_due(&self, db: &Digest, now: u64) -> Result<Vec<Digest>> {
        let skew = self.genesis_of(db)?.limits.ts_skew;
        let waiting: Vec<SignedEntry> = {
            let tx = self.db.begin_read()?;
            let (start, end) = db_range(db);
            tx.open_table(DEFERRED)?
                .range(start.as_slice()..end.as_slice())?
                .map(|r| SignedEntry::decode(r?.1.value()).map_err(corrupt))
                .collect::<Result<_>>()?
        };
        let mut admitted = Vec::new();
        for e in waiting {
            if deferred(&e.header, now, skew) {
                continue;
            }
            // Each entry on its own: one that fails doesn't hold back the others, and
            // a storage error is reported after the rest had their turn.
            match self.insert_entry(&e, &[], now) {
                Ok(Outcome::Added) => admitted.push(e.id()),
                Ok(_) => {}
                Err(Error::Rejected(_)) => {
                    // No longer admissible (its stored chain is gone): drop it.
                    self.with_write(|tx| {
                        tx.open_table(DEFERRED)?
                            .remove(dbkey(db, &e.id().0).as_slice())?;
                        Ok(())
                    })?;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(admitted)
    }

    /// The distinct values the admitted puts of a database reference, as `(hash,
    /// size)` from their signed headers: what a node should hold in its blob store.
    pub fn value_hashes(&self, db: &Digest) -> Result<Vec<(Digest, u64)>> {
        let mut seen = HashSet::new();
        Ok(self
            .ledger(db)?
            .entries
            .into_iter()
            .filter(|e| e.header.op == sameroot_core::Op::Put)
            .map(|e| (e.header.value_hash, e.header.value_size))
            .filter(|v| seen.insert(*v))
            .collect())
    }

    /// Up to `limit` values of the schema 3 values table with hashes after `after`,
    /// in hash order, each checked against its hash (a mismatch is skipped).
    pub fn legacy_values(
        &self,
        after: Option<&Digest>,
        limit: usize,
    ) -> Result<Vec<(Digest, Vec<u8>)>> {
        let tx = self.db.begin_read()?;
        let t = match tx.open_table(LEGACY_VALUES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let range = match after {
            Some(h) => t.range::<&[u8]>((
                std::ops::Bound::Excluded(h.0.as_slice()),
                std::ops::Bound::Unbounded,
            ))?,
            None => t.iter()?,
        };
        let mut out = Vec::new();
        for r in range.take(limit) {
            let (k, v) = r?;
            let h = digest(k.value())?;
            if value_hash(v.value()) == h {
                out.push((h, v.value().to_vec()));
            }
        }
        Ok(out)
    }

    /// Deletes the schema 3 values table, once its values are in the blob store;
    /// returns whether it existed.
    pub fn drop_legacy_values(&self) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let existed = tx.delete_table(LEGACY_VALUES)?;
        tx.commit()?;
        Ok(existed)
    }

    /// Writes a value into the schema 3 values table: only to test the migration.
    #[doc(hidden)]
    pub fn put_legacy_value(&self, value: &[u8]) -> Result<Digest> {
        let h = value_hash(value);
        let tx = self.db.begin_write()?;
        tx.open_table(LEGACY_VALUES)?
            .insert(h.0.as_slice(), value)?;
        tx.commit()?;
        Ok(h)
    }

    /// A ledger record of a database by id.
    pub fn record(&self, db: &Digest, id: &Digest) -> Result<Option<Record>> {
        let tx = self.db.begin_read()?;
        let Some(meta) = tx.open_table(RECORDS)?.get(dbkey(db, &id.0).as_slice())? else {
            return Ok(None);
        };
        let kind = Kind::from_code(meta.value()[0] as u64).ok_or_else(|| corrupt("kind"))?;
        let t = tx.open_table(table_of(kind))?;
        let bytes = t
            .get(id.0.as_slice())?
            .ok_or_else(|| corrupt("record without bytes"))?;
        Ok(Some(Record::decode(kind, bytes.value()).map_err(corrupt)?))
    }

    /// An entry by id.
    pub fn entry(&self, db: &Digest, id: &Digest) -> Result<Option<SignedEntry>> {
        Ok(match self.record(db, id)? {
            Some(Record::Entry(e)) => Some(e),
            _ => None,
        })
    }

    /// The record root and record count (design 0004 §4.1: what sync compares).
    pub fn root(&self, db: &Digest) -> Result<(usize, Digest)> {
        self.genesis_of(db)?;
        self.with_trie(db, |t| (t.count(), t.root()))
    }

    /// The reference root (design 0004 §4.1), derived from the ledger.
    pub fn ref_root(&self, db: &Digest) -> Result<Digest> {
        let generation = self.generation(db);
        if let Some((g, r)) = self.refs.lock().expect("refs cache").get(db)
            && *g == generation
        {
            return Ok(*r);
        }
        let root = self.ledger(db)?.refs.root();
        self.refs
            .lock()
            .expect("refs cache")
            .insert(*db, (generation, root));
        Ok(root)
    }

    /// The ledger commitment `H(recordRoot ‖ refRoot)` (design 0004 §4.1): what cuts,
    /// snapshots and light proofs name.
    pub fn ledger_root(&self, db: &Digest) -> Result<Digest> {
        let (_, record_root) = self.root(db)?;
        Ok(ledger_commitment(&record_root, &self.ref_root(db)?))
    }

    /// The ledger node at a nibble path (wire form), if one exists.
    pub fn node(&self, db: &Digest, path: &[u8]) -> Result<Option<Vec<u8>>> {
        self.with_trie(db, |t| t.node(path).map(Node::encode))
    }

    /// The local ledger node at a path.
    pub fn local_node(&self, db: &Digest, path: &[u8]) -> Result<Option<Node>> {
        self.with_trie(db, |t| t.node(path).cloned())
    }

    /// An inclusion or absence proof for a record id.
    pub fn prove(&self, db: &Digest, id: &Digest) -> Result<Proof> {
        self.with_trie(db, |t| t.prove(id))
    }

    /// The admitted entries and voids of a database, and its reference index.
    fn ledger(&self, db: &Digest) -> Result<Ledger> {
        let tx = self.db.begin_read()?;
        let (start, end) = db_range(db);
        let entries_t = tx.open_table(ENTRIES)?;
        let voids_t = tx.open_table(VOIDS)?;
        let keeps_t = tx.open_table(KEEPS)?;
        let certs_t = tx.open_table(CERTS)?;
        let mut out = Ledger {
            entries: Vec::new(),
            voids: Vec::new(),
            refs: RefIndex::new(),
        };
        for r in tx
            .open_table(RECORDS)?
            .range(start.as_slice()..end.as_slice())?
        {
            let (k, meta) = r?;
            let id = digest(&k.value()[32..])?;
            let meta = meta.value();
            let chain: Vec<Digest> = meta[33..].chunks(32).map(digest).collect::<Result<_>>()?;
            match Kind::from_code(meta[0] as u64).ok_or_else(|| corrupt("kind"))? {
                Kind::Void => {
                    let bytes = voids_t
                        .get(id.0.as_slice())?
                        .ok_or_else(|| corrupt("void"))?;
                    let v = SignedVoid::decode(bytes.value()).map_err(corrupt)?.void;
                    let keep = match v.keep {
                        None => None,
                        Some(_) => {
                            let b = keeps_t
                                .get(id.0.as_slice())?
                                .ok_or_else(|| corrupt("void without its keep list"))?;
                            Some(b.value().chunks(32).map(digest).collect::<Result<_>>()?)
                        }
                    };
                    // Voids stored before schema 5 have no authority in their metadata:
                    // derive it from the stored chain (a void signed by the chain root
                    // has none either way).
                    let authority = match v.target {
                        VoidTarget::Cert(target) if chain.is_empty() => {
                            let mut path = Vec::new();
                            let mut found = None;
                            let mut next = Some(target);
                            while let Some(c) = next
                                && path.len() < MAX_CHAIN
                            {
                                let Some(b) = certs_t.get(c.0.as_slice())? else {
                                    break;
                                };
                                let cert = SignedCert::decode(b.value()).map_err(corrupt)?;
                                if found.is_none() && cert.cert.issuer == v.signer {
                                    found = Some(path.len());
                                }
                                path.push(c);
                                next = cert.cert.parent;
                            }
                            found.map(|i| path[i + 1..].to_vec()).unwrap_or_default()
                        }
                        _ => chain,
                    };
                    out.refs.insert(void_ref(&v), Kind::Void, id);
                    out.voids.push(LedgerVoid {
                        id,
                        target: v.target,
                        keep,
                        before: v.before,
                        authority,
                    });
                }
                Kind::Entry => {
                    let bytes = entries_t
                        .get(id.0.as_slice())?
                        .ok_or_else(|| corrupt("entry"))?;
                    let e = SignedEntry::decode(bytes.value()).map_err(corrupt)?;
                    if let Some(r) = entry_ref(&e.header) {
                        out.refs.insert(r, Kind::Entry, id);
                    }
                    let chain_root = PublicKey(meta[1..33].try_into().map_err(corrupt)?);
                    out.entries.push(LedgerEntry {
                        id,
                        header: e.header,
                        chain_root,
                        chain,
                    });
                }
                Kind::Forward => {}
            }
        }
        Ok(out)
    }

    /// The state at `as_of` (design 0003 §6), cached until the ledger changes or a
    /// put expires.
    pub fn state(&self, db: &Digest, as_of: u64) -> Result<State> {
        self.cached(db, as_of, |c| c.state.clone())
    }

    /// The values a node should hold for a database at `as_of`: those of puts that
    /// count (not expired, voided or negated), superseded ones included. A value only
    /// voided, negated or expired entries reference is neither fetched nor kept:
    /// a revoked writer's spam costs no storage. Cached with the state.
    pub fn live_values(&self, db: &Digest, as_of: u64) -> Result<Vec<(Digest, u64)>> {
        self.cached(db, as_of, |c| c.live.clone())
    }

    fn cached<T>(&self, db: &Digest, as_of: u64, f: impl Fn(&CachedState) -> T) -> Result<T> {
        let generation = self.generation(db);
        if let Some(c) = self.states.lock().expect("state cache").get(db)
            && c.generation == generation
            && as_of >= c.as_of
            && as_of < c.valid_until
        {
            return Ok(f(c));
        }
        let genesis = self.genesis_of(db)?;
        let Ledger { entries, voids, .. } = self.ledger(db)?;
        let valid_until = entries
            .iter()
            .filter_map(|e| e.header.exp)
            .filter(|&x| x > as_of)
            .min()
            .unwrap_or(u64::MAX);
        let state = resolve::resolve(
            &entries,
            &voids,
            &genesis.contract.resolution,
            &genesis.owner,
            as_of,
        );
        let counting = resolve::counting(
            &entries,
            &voids,
            &genesis.contract.resolution,
            &genesis.owner,
            as_of,
        );
        let mut seen = HashSet::new();
        let live = entries
            .iter()
            .filter(|e| e.header.op == sameroot_core::Op::Put && counting.contains(&e.id))
            .map(|e| (e.header.value_hash, e.header.value_size))
            .filter(|v| seen.insert(*v))
            .collect();
        let c = CachedState {
            generation,
            as_of,
            valid_until,
            state,
            live,
        };
        let out = f(&c);
        self.states.lock().expect("state cache").insert(*db, c);
        Ok(out)
    }

    /// The state of one key at `as_of`.
    pub fn get(
        &self,
        db: &Digest,
        subspace: &Subspace,
        path: &Path,
        as_of: u64,
    ) -> Result<Option<Resolved>> {
        Ok(self
            .state(db, as_of)?
            .get(&(*subspace, path.clone()))
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sameroot_core::{Header, Op, SecretKey, Void, logic::presets};

    fn genesis(owner: &SecretKey) -> SignedGenesis {
        Genesis::new("t", owner.public(), presets::own_subspace(), 1).sign(owner)
    }

    fn entry(
        db: Digest,
        key: &SecretKey,
        op: Op,
        path: &str,
        ts: u64,
        value: &[u8],
        target: Option<Digest>,
    ) -> SignedEntry {
        let put = op == Op::Put;
        Header {
            db,
            subspace: Subspace::Owner(key.public()),
            path: Path::parse(path).unwrap(),
            op,
            ts,
            exp: None,
            value_size: if put { value.len() as u64 } else { 0 },
            value_hash: if put { value_hash(value) } else { Digest::ZERO },
            target,
            signer: key.public(),
            cert: None,
            work: 0,
        }
        .sign(key)
    }

    #[test]
    fn a_batch_commits_once_and_admits_everything() {
        let owner = SecretKey::from_seed([5; 32]);
        let s = Store::in_memory().unwrap();
        let db = s.add_database(&genesis(&owner)).unwrap();
        let skew = genesis(&owner).genesis.limits.ts_skew;
        let a = entry(db, &owner, Op::Put, "a", 5, b"a", None);
        let b = entry(db, &owner, Op::Put, "b", 6, b"b", None);
        let later = entry(db, &owner, Op::Put, "c", 10 + skew + 1_000, b"c", None);
        let outcomes = s
            .batch(|s| {
                [&a, &b, &later, &a]
                    .iter()
                    .map(|e| s.insert_entry(e, &[], 10).unwrap())
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert_eq!(
            outcomes,
            vec![
                Outcome::Added,
                Outcome::Added,
                Outcome::Deferred,
                Outcome::Duplicate
            ]
        );
        assert_eq!(s.root(&db).unwrap().0, 2);
        assert!(s.entry(&db, &b.id()).unwrap().is_some(), "committed");
        assert_eq!(
            s.admit_due(&db, 10 + skew + 2_000).unwrap(),
            vec![later.id()]
        );
        // Outside a batch, writes still commit on their own.
        s.insert_entry(&entry(db, &owner, Op::Put, "d", 7, b"d", None), &[], 10)
            .unwrap();
        assert_eq!(s.root(&db).unwrap().0, 4);
    }

    #[test]
    fn live_values_leave_out_voided_and_expired_ones() {
        let owner = SecretKey::from_seed([5; 32]);
        let bare = SecretKey::from_seed([9; 32]);
        let s = Store::in_memory().unwrap();
        let db = s.add_database(&genesis(&owner)).unwrap();
        // The owner overwrites a key: the superseded value stays part of the history.
        s.insert_entry(&entry(db, &owner, Op::Put, "j", 5, b"first", None), &[], 10)
            .unwrap();
        s.insert_entry(
            &entry(db, &owner, Op::Put, "j", 6, b"second", None),
            &[],
            10,
        )
        .unwrap();
        // A put that expires.
        let expiring = Header {
            exp: Some(15),
            ..entry(db, &owner, Op::Put, "e", 7, b"expiring", None).header
        }
        .sign(&owner);
        s.insert_entry(&expiring, &[], 10).unwrap();
        // A bare key writes its own subspace, then is voided.
        s.insert_entry(
            &entry(db, &bare, Op::Put, "spam", 8, b"spam", None),
            &[],
            10,
        )
        .unwrap();
        let live = |at| -> Vec<Digest> {
            let mut v: Vec<Digest> = s
                .live_values(&db, at)
                .unwrap()
                .into_iter()
                .map(|(h, _)| h)
                .collect();
            v.sort();
            v
        };
        let mut want = vec![
            value_hash(b"first"),
            value_hash(b"second"),
            value_hash(b"expiring"),
            value_hash(b"spam"),
        ];
        want.sort();
        assert_eq!(live(10), want);
        s.insert_void(&Void::of_key(db, bare.public()).sign(&bare), &[], None)
            .unwrap();
        // Voided and expired values are dead; the superseded one isn't.
        let mut want = vec![value_hash(b"first"), value_hash(b"second")];
        want.sort();
        assert_eq!(live(20), want);
        // All puts are still in the ledger.
        assert_eq!(s.value_hashes(&db).unwrap().len(), 4);
    }

    #[test]
    fn ledger_root_and_state_in_any_order() {
        let owner = SecretKey::from_seed([5; 32]);
        let g = genesis(&owner);
        let (a, b) = (Store::in_memory().unwrap(), Store::in_memory().unwrap());
        let db = a.add_database(&g).unwrap();
        b.add_database(&g).unwrap();
        let old = entry(db, &owner, Op::Put, "k", 1, b"old", None);
        let new = entry(db, &owner, Op::Put, "k", 2, b"new", None);
        let neg = entry(db, &owner, Op::Negate, "k", 3, b"", Some(new.id()));
        for e in [&old, &new, &neg] {
            assert_eq!(a.insert_entry(e, &[], 10).unwrap(), Outcome::Added);
        }
        for e in [&neg, &old, &new] {
            assert_eq!(b.insert_entry(e, &[], 10).unwrap(), Outcome::Added);
        }
        assert_eq!(a.insert_entry(&new, &[], 10).unwrap(), Outcome::Duplicate);
        assert_eq!(a.root(&db).unwrap(), b.root(&db).unwrap());
        assert_eq!(a.root(&db).unwrap().0, 3);
        let key = Path::parse("k").unwrap();
        let sub = Subspace::Owner(owner.public());
        assert_eq!(
            a.get(&db, &sub, &key, 10).unwrap(),
            Some(Resolved::Value(old.id())),
            "new is negated"
        );
        assert_eq!(a.state(&db, 10).unwrap(), b.state(&db, 10).unwrap());
        // Proofs against the root.
        let (_, root) = a.root(&db).unwrap();
        assert!(
            a.prove(&db, &new.id())
                .unwrap()
                .proves_inclusion(&root, Kind::Entry, &new.id())
        );
        // Values live in a blob store; the store lists what a node should hold.
        let hashes = a.value_hashes(&db).unwrap();
        assert!(hashes.contains(&(old.header.value_hash, 3)));
        assert!(hashes.contains(&(new.header.value_hash, 3)));
        assert_eq!(hashes, b.value_hashes(&db).unwrap());
    }

    /// A schema 3 store opens as schema 4; its values can be read out, then dropped.
    #[test]
    fn legacy_values_drain() {
        let s = Store::in_memory().unwrap();
        assert!(s.legacy_values(None, 10).unwrap().is_empty());
        let mut hashes: Vec<Digest> = (0..5u8)
            .map(|i| s.put_legacy_value(&[i; 3]).unwrap())
            .collect();
        hashes.sort();
        // Read in pages of two, after the last hash of each page.
        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let page = s.legacy_values(after.as_ref(), 2).unwrap();
            if page.is_empty() {
                break;
            }
            after = page.last().map(|(h, _)| *h);
            seen.extend(page.into_iter().map(|(h, v)| {
                assert_eq!(value_hash(&v), h);
                h
            }));
        }
        assert_eq!(seen, hashes);
        assert!(s.drop_legacy_values().unwrap());
        assert!(s.legacy_values(None, 10).unwrap().is_empty());
        assert!(!s.drop_legacy_values().unwrap());
    }

    /// Design 0003 §10.4, the honest limit: a node that withholds a negation serves a
    /// valid inclusion proof for the negated entry. A proof says "in this ledger", not
    /// "the current state".
    #[test]
    fn withheld_negation_is_the_honest_limit() {
        let owner = SecretKey::from_seed([5; 32]);
        let g = genesis(&owner);
        let (honest, withholding) = (Store::in_memory().unwrap(), Store::in_memory().unwrap());
        let db = honest.add_database(&g).unwrap();
        withholding.add_database(&g).unwrap();
        let p = entry(db, &owner, Op::Put, "k", 1, b"secret", None);
        let n = entry(db, &owner, Op::Negate, "k", 2, b"", Some(p.id()));
        for e in [&p, &n] {
            honest.insert_entry(e, &[], 10).unwrap();
        }
        withholding.insert_entry(&p, &[], 10).unwrap();
        let key = Path::parse("k").unwrap();
        let sub = Subspace::Owner(owner.public());
        assert_eq!(honest.get(&db, &sub, &key, 10).unwrap(), None, "negated");
        assert_eq!(
            withholding.get(&db, &sub, &key, 10).unwrap(),
            Some(Resolved::Value(p.id()))
        );
        // The withholding node's proof verifies, but only against its own root.
        let (_, w_root) = withholding.root(&db).unwrap();
        let (_, h_root) = honest.root(&db).unwrap();
        let proof = withholding.prove(&db, &p.id()).unwrap();
        assert!(proof.proves_inclusion(&w_root, Kind::Entry, &p.id()));
        assert!(!proof.proves_inclusion(&h_root, Kind::Entry, &p.id()));
        // Against the honest root the entry is included too: inclusion can't show the
        // negation; only the full ledger (or a trusted snapshot) can.
        assert!(honest.prove(&db, &p.id()).unwrap().proves_inclusion(
            &h_root,
            Kind::Entry,
            &p.id()
        ));
    }

    #[test]
    fn deferred_entries_wait_for_the_clock() {
        let owner = SecretKey::from_seed([5; 32]);
        let s = Store::in_memory().unwrap();
        let db = s.add_database(&genesis(&owner)).unwrap();
        let skew = 10 * 60 * 1000;
        let future = entry(db, &owner, Op::Put, "k", 1_000_000_000, b"v", None);
        assert_eq!(s.insert_entry(&future, &[], 0).unwrap(), Outcome::Deferred);
        assert_eq!(s.root(&db).unwrap().0, 0);
        assert!(s.admit_due(&db, 1_000).unwrap().is_empty());
        assert_eq!(
            s.admit_due(&db, 1_000_000_000 - skew).unwrap(),
            vec![future.id()]
        );
        assert_eq!(s.root(&db).unwrap().0, 1);
    }

    /// A future-dated entry delegated through a certificate the store never saw
    /// before: deferred with its chain, admitted after a reopen without the peer
    /// sending the certificate again.
    #[test]
    fn delegated_deferred_entry_keeps_its_chain() {
        let dir = std::env::temp_dir().join(format!("sameroot-defer-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("store.redb");
        let owner = SecretKey::from_seed([11; 32]);
        let device = SecretKey::from_seed([12; 32]);
        let g = genesis(&owner);
        let db = g.id();
        let cert = sameroot_core::Cert {
            issuer: owner.public(),
            subject: device.public(),
            parent: None,
            db,
            area: sameroot_core::Area {
                subspace: Subspace::Owner(owner.public()),
                path_prefix: Path::default(),
                ops: vec![Op::Put],
            },
            not_before: 0,
            not_after: u64::MAX,
            name: None,
            endpoint: None,
        }
        .sign(&owner);
        let future = Header {
            cert: Some(cert.id()),
            signer: device.public(),
            subspace: Subspace::Owner(owner.public()),
            ..entry(db, &device, Op::Put, "k", 1_000_000_000, b"v", None).header
        }
        .sign(&device);
        {
            let s = Store::open(&file).unwrap();
            s.add_database(&g).unwrap();
            assert_eq!(
                s.insert_entry(&future, std::slice::from_ref(&cert), 0)
                    .unwrap(),
                Outcome::Deferred
            );
        }
        let s = Store::open(&file).unwrap();
        assert!(s.admit_due(&db, 1_000).unwrap().is_empty(), "not yet");
        assert_eq!(s.admit_due(&db, 1_000_000_000).unwrap(), vec![future.id()]);
        assert_eq!(s.root(&db).unwrap().0, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn voids_remove_the_effect_of_their_chain() {
        let owner = SecretKey::from_seed([5; 32]);
        let device = SecretKey::from_seed([6; 32]);
        let s = Store::in_memory().unwrap();
        let db = s.add_database(&genesis(&owner)).unwrap();
        let cert = sameroot_core::Cert {
            issuer: owner.public(),
            subject: device.public(),
            parent: None,
            db,
            area: sameroot_core::Area {
                subspace: Subspace::Owner(owner.public()),
                path_prefix: Path::default(),
                ops: vec![Op::Put],
            },
            not_before: 0,
            not_after: 1_000,
            name: None,
            endpoint: None,
        }
        .sign(&owner);
        let by_device = Header {
            cert: Some(cert.id()),
            signer: device.public(),
            subspace: Subspace::Owner(owner.public()),
            ..entry(db, &device, Op::Put, "k", 5, b"d", None).header
        }
        .sign(&device);
        assert!(
            matches!(s.insert_entry(&by_device, &[], 10), Err(Error::Rejected(_))),
            "chain missing"
        );
        assert_eq!(
            s.insert_entry(&by_device, std::slice::from_ref(&cert), 10)
                .unwrap(),
            Outcome::Added
        );
        let key = Path::parse("k").unwrap();
        let sub = Subspace::Owner(owner.public());
        assert_eq!(
            s.get(&db, &sub, &key, 10).unwrap(),
            Some(Resolved::Value(by_device.id()))
        );
        // A second device entry, then a void that keeps only the first.
        let second = Header {
            cert: Some(cert.id()),
            signer: device.public(),
            subspace: Subspace::Owner(owner.public()),
            ..entry(db, &device, Op::Put, "j", 6, b"e", None).header
        }
        .sign(&device);
        assert_eq!(s.insert_entry(&second, &[], 10).unwrap(), Outcome::Added);
        let ref_root_before = s.ref_root(&db).unwrap();
        let ledger_root_before = s.ledger_root(&db).unwrap();
        let kept = vec![by_device.id()];
        let keep_root = Trie::build([(Kind::Entry, by_device.id())]).root();
        let partial = Void {
            keep: Some(sameroot_core::Keep {
                root: keep_root,
                count: 1,
            }),
            ..Void::of_cert(db, cert.id(), owner.public())
        }
        .sign(&owner);
        assert!(
            matches!(
                s.insert_void(&partial, &[], None),
                Err(Error::Rejected(Reject::KeepMissing))
            ),
            "the keep list is a dependency"
        );
        assert_eq!(
            s.insert_void(&partial, &[], Some(&kept)).unwrap(),
            Outcome::Added
        );
        assert_eq!(s.keep_list(&partial.id()).unwrap(), Some(kept));
        let j = Path::parse("j").unwrap();
        assert_eq!(
            s.get(&db, &sub, &key, 10).unwrap(),
            Some(Resolved::Value(by_device.id())),
            "kept"
        );
        assert_eq!(s.get(&db, &sub, &j, 10).unwrap(), None, "not kept");
        // The void changed the reference index and the ledger commitment.
        assert_ne!(s.ref_root(&db).unwrap(), ref_root_before);
        assert_ne!(s.ledger_root(&db).unwrap(), ledger_root_before);
        assert_eq!(
            s.dependencies(&s.record(&db, &partial.id()).unwrap().unwrap())
                .unwrap(),
            vec![cert.clone()]
        );
        // A total void of the same certificate removes the rest.
        let total = Void::of_cert(db, cert.id(), owner.public()).sign(&owner);
        assert_eq!(s.insert_void(&total, &[], None).unwrap(), Outcome::Added);
        assert_eq!(s.get(&db, &sub, &key, 10).unwrap(), None);
    }

    /// A void stored before schema 5 has no authority in its metadata; it is derived
    /// from the stored chain, so a superior void without `before` still disables it
    /// (design 0004 §5.3 rule 5).
    #[test]
    fn legacy_voids_get_their_authority() {
        let owner = SecretKey::from_seed([13; 32]);
        let device = SecretKey::from_seed([14; 32]);
        let agent = SecretKey::from_seed([15; 32]);
        let s = Store::in_memory().unwrap();
        let db = s.add_database(&genesis(&owner)).unwrap();
        let cert = |issuer: &SecretKey, subject: &SecretKey, parent| {
            sameroot_core::Cert {
                issuer: issuer.public(),
                subject: subject.public(),
                parent,
                db,
                area: sameroot_core::Area {
                    subspace: Subspace::Owner(owner.public()),
                    path_prefix: Path::default(),
                    ops: vec![Op::Put],
                },
                not_before: 0,
                not_after: u64::MAX,
                name: None,
                endpoint: None,
            }
            .sign(issuer)
        };
        let dc = cert(&owner, &device, None);
        let ac = cert(&device, &agent, Some(dc.id()));
        let e = Header {
            cert: Some(ac.id()),
            signer: agent.public(),
            subspace: Subspace::Owner(owner.public()),
            ..entry(db, &agent, Op::Put, "k", 5, b"a", None).header
        }
        .sign(&agent);
        s.insert_entry(&e, &[ac.clone(), dc.clone()], 10).unwrap();
        // The device voids the agent's certificate...
        let sabotage = Void::of_cert(db, ac.id(), device.public()).sign(&device);
        s.insert_void(&sabotage, &[], None).unwrap();
        // ...and that void is rewritten as an older node stored it: no authority.
        {
            let tx = s.db.begin_write().unwrap();
            tx.open_table(RECORDS)
                .unwrap()
                .insert(
                    dbkey(&db, &sabotage.id().0).as_slice(),
                    record_meta(Kind::Void, &owner.public(), &[]).as_slice(),
                )
                .unwrap();
            tx.commit().unwrap();
        }
        s.bump(&db);
        let key = Path::parse("k").unwrap();
        let sub = Subspace::Owner(owner.public());
        assert_eq!(s.get(&db, &sub, &key, 10).unwrap(), None);
        // The owner voids the device's certificate, keeping the agent's entry: the
        // device's void depends on that certificate, so it no longer counts.
        let keep = vec![e.id()];
        let by_owner = Void {
            keep: Some(sameroot_core::Keep {
                root: Trie::build([(Kind::Entry, e.id())]).root(),
                count: 1,
            }),
            ..Void::of_cert(db, dc.id(), owner.public())
        }
        .sign(&owner);
        s.insert_void(&by_owner, &[], Some(&keep)).unwrap();
        assert_eq!(
            s.get(&db, &sub, &key, 10).unwrap(),
            Some(Resolved::Value(e.id()))
        );
    }

    /// A forward is a ledger record of kind 2, signed by the owner, and must match
    /// the genesis' commitment to the next owner.
    #[test]
    fn entries_under_a_certificate_with_when_they_were_first_seen() {
        let owner = SecretKey::from_seed([7; 32]);
        let device = SecretKey::from_seed([8; 32]);
        let s = Store::in_memory().unwrap();
        let db = s.add_database(&genesis(&owner)).unwrap();
        let cert = sameroot_core::Cert {
            issuer: owner.public(),
            subject: device.public(),
            parent: None,
            db,
            area: sameroot_core::Area {
                subspace: Subspace::Owner(owner.public()),
                path_prefix: Path::default(),
                ops: vec![Op::Put],
            },
            not_before: 0,
            not_after: 1_000,
            name: None,
            endpoint: None,
        }
        .sign(&owner);
        let by_device = Header {
            cert: Some(cert.id()),
            signer: device.public(),
            subspace: Subspace::Owner(owner.public()),
            ..entry(db, &device, Op::Put, "k", 5, b"d", None).header
        }
        .sign(&device);
        let by_owner = entry(db, &owner, Op::Put, "j", 6, b"o", None);
        assert_eq!(s.first_seen(&db, &by_device.id()).unwrap(), None);
        let before = sameroot_core::now_ms();
        s.insert_entry(&by_device, std::slice::from_ref(&cert), 10)
            .unwrap();
        s.insert_entry(&by_owner, &[], 10).unwrap();
        let after = sameroot_core::now_ms();

        let under = s.entries_under(&db, &cert.id()).unwrap();
        assert_eq!(under.len(), 1, "the owner's own entry has no chain");
        assert_eq!(under[0].0.id(), by_device.id());
        let seen = under[0].1.expect("first seen");
        assert!((before..=after).contains(&seen));
        // A second copy doesn't move the time.
        assert_eq!(
            s.insert_entry(&by_device, &[], 10).unwrap(),
            Outcome::Duplicate
        );
        assert_eq!(s.first_seen(&db, &by_device.id()).unwrap(), Some(seen));
        assert_eq!(s.certs(&db).unwrap(), vec![cert]);
        assert!(s.certs(&Digest([0; 32])).unwrap().is_empty());
    }

    #[test]
    fn a_retired_database_keeps_only_its_stub() {
        let owner = SecretKey::from_seed([5; 32]);
        let device = SecretKey::from_seed([6; 32]);
        let s = Store::in_memory().unwrap();
        let g = genesis(&owner);
        let db = s.add_database(&g).unwrap();
        let cert = sameroot_core::Cert {
            issuer: owner.public(),
            subject: device.public(),
            parent: None,
            db,
            area: sameroot_core::Area {
                subspace: Subspace::Owner(owner.public()),
                path_prefix: Path::default(),
                ops: vec![Op::Put],
            },
            not_before: 0,
            not_after: 1_000,
            name: None,
            endpoint: None,
        }
        .sign(&owner);
        let by_device = Header {
            cert: Some(cert.id()),
            signer: device.public(),
            subspace: Subspace::Owner(owner.public()),
            ..entry(db, &device, Op::Put, "k", 5, b"d", None).header
        }
        .sign(&device);
        s.insert_entry(&by_device, std::slice::from_ref(&cert), 10)
            .unwrap();
        s.insert_entry(&entry(db, &owner, Op::Put, "j", 6, b"o", None), &[], 10)
            .unwrap();
        let void = Void::of_cert(db, cert.id(), owner.public()).sign(&owner);
        s.insert_void(&void, &[], None).unwrap();
        assert!(
            matches!(s.retire(&db, 20), Err(Error::Rejected(_))),
            "no forward, no retirement"
        );
        let fwd = sameroot_core::Forward {
            db,
            successor: Digest([4; 32]),
            owner: owner.public(),
            cut_root: s.ledger_root(&db).unwrap(),
        }
        .sign(&owner);
        s.insert_forward(&fwd).unwrap();
        assert_eq!(s.root(&db).unwrap().0, 4);

        assert_eq!(s.retire(&db, 20).unwrap(), 3);
        assert_eq!(s.retired(&db).unwrap(), Some(20));
        assert_eq!(s.genesis(&db).unwrap(), Some(g));
        assert_eq!(s.forwards(&db).unwrap(), vec![fwd.clone()]);
        let stub = Trie::build([(Kind::Forward, fwd.id())]);
        assert_eq!(s.root(&db).unwrap(), (1, stub.root()));
        assert!(s.entry(&db, &by_device.id()).unwrap().is_none());
        assert!(s.certs(&db).unwrap().is_empty());
        assert!(s.value_hashes(&db).unwrap().is_empty());
        assert!(s.void_targets(&db).unwrap().is_empty());
        assert!(matches!(
            s.insert_entry(&entry(db, &owner, Op::Put, "late", 30, b"x", None), &[], 30),
            Err(Error::Retired(_))
        ));
    }

    #[test]
    fn forwards() {
        let owner = SecretKey::from_seed([7; 32]);
        let next = SecretKey::from_seed([8; 32]);
        let thief = SecretKey::from_seed([9; 32]);
        let s = Store::in_memory().unwrap();
        let mut g = Genesis::new("t", owner.public(), presets::own_subspace(), 1);
        g.next_owner = Some(sameroot_core::owner_commitment(&next.public()));
        let db = s.add_database(&g.sign(&owner)).unwrap();
        let cut = s.ledger_root(&db).unwrap();
        let fwd = |to: &SecretKey| {
            sameroot_core::Forward {
                db,
                successor: Digest([1; 32]),
                owner: to.public(),
                cut_root: cut,
            }
            .sign(&owner)
        };
        assert!(matches!(
            s.insert_forward(&fwd(&thief)),
            Err(Error::Rejected(Reject::ForwardAuthority))
        ));
        let good = fwd(&next);
        assert_eq!(s.insert_forward(&good).unwrap(), Outcome::Added);
        assert_eq!(s.insert_forward(&good).unwrap(), Outcome::Duplicate);
        assert_eq!(s.forwards(&db).unwrap(), vec![good.clone()]);
        assert_eq!(
            s.record(&db, &good.id()).unwrap().map(|r| r.kind()),
            Some(Kind::Forward)
        );
        assert_eq!(s.root(&db).unwrap().0, 1);
    }

    /// A negation is indexed by its target, so the reference root reflects it.
    #[test]
    fn negations_enter_the_reference_index() {
        let owner = SecretKey::from_seed([10; 32]);
        let s = Store::in_memory().unwrap();
        let db = s.add_database(&genesis(&owner)).unwrap();
        let p = entry(db, &owner, Op::Put, "k", 1, b"v", None);
        s.insert_entry(&p, &[], 10).unwrap();
        let empty = s.ref_root(&db).unwrap();
        assert_eq!(empty, Trie::new().root());
        let n = entry(db, &owner, Op::Negate, "k", 2, b"", Some(p.id()));
        s.insert_entry(&n, &[], 10).unwrap();
        assert_ne!(s.ref_root(&db).unwrap(), empty);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("sameroot-store3-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("store.redb");
        let owner = SecretKey::from_seed([6; 32]);
        let g = genesis(&owner);
        let root = {
            let s = Store::open(&file).unwrap();
            let db = s.add_database(&g).unwrap();
            for i in 0..50 {
                s.insert_entry(
                    &entry(db, &owner, Op::Put, &format!("k{i}"), i + 1, b"1", None),
                    &[],
                    100,
                )
                .unwrap();
            }
            s.root(&db).unwrap()
        };
        let s = Store::open(&file).unwrap();
        assert_eq!(s.root(&g.id()).unwrap(), root);
        s.insert_entry(
            &entry(g.id(), &owner, Op::Put, "late", 60, b"1", None),
            &[],
            100,
        )
        .unwrap();
        let rebuilt = Trie::build(
            (0..50)
                .map(|i| entry(g.id(), &owner, Op::Put, &format!("k{i}"), i + 1, b"1", None).id())
                .chain([entry(g.id(), &owner, Op::Put, "late", 60, b"1", None).id()])
                .map(|id| (Kind::Entry, id)),
        );
        assert_eq!(s.root(&g.id()).unwrap(), (51, rebuilt.root()));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
