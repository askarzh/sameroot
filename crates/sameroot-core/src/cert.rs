//! Delegation certificates (`spec/03-certificates.md`).
//!
//! Authority is the conjunction of every link: an entry is authorized by a chain if
//! it lies inside the area and window of every certificate from the leaf up to the
//! root, whose issuer is the owner.

use crate::FORMAT_VERSION;
use crate::cbor::{self, Map, Value};
use crate::entry::{Header, Op, Path, Subspace};
use crate::fields::{Fields, FormatError, digest_value, key_value};
use crate::hash::{Digest, context};
use crate::identity::{PublicKey, SecretKey, Signature};

/// Maximum chain length (owner → device → agent).
pub const MAX_CHAIN: usize = 3;

/// What a certificate allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Area {
    /// The subspace.
    pub subspace: Subspace,
    /// Allowed path prefix (empty: the whole subspace).
    pub path_prefix: Path,
    /// Allowed operations.
    pub ops: Vec<Op>,
}

/// A delegation certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert {
    /// The signer of this certificate.
    pub issuer: PublicKey,
    /// The key it authorizes.
    pub subject: PublicKey,
    /// The issuer's own certificate, if the issuer isn't the owner.
    pub parent: Option<Digest>,
    /// The database it applies to.
    pub db: Digest,
    /// What it allows.
    pub area: Area,
    /// Validity window `[not_before, not_after)`, milliseconds.
    pub not_before: u64,
    /// See `not_before`.
    pub not_after: u64,
    /// Display name, e.g. a device name.
    pub name: Option<String>,
    /// The iroh endpoint id of the device this certificate is for, where the two
    /// identities should be bound (design 0004 §3).
    pub endpoint: Option<PublicKey>,
}

const CERT_FIELDS: &[&str] = &[
    "v", "issuer", "subject", "parent", "db", "area", "window", "name", "endpoint",
];

impl Cert {
    /// The canonical CBOR value.
    pub fn to_value(&self) -> Value {
        let mut area = Map::new();
        area.insert(
            "subspace",
            match &self.area.subspace {
                Subspace::Owner(k) => key_value(k),
                Subspace::Shared => Value::Bytes(Vec::new()),
            },
        )
        .insert(
            "pathPrefix",
            Value::Array(
                self.area
                    .path_prefix
                    .0
                    .iter()
                    .map(|c| Value::Bytes(c.clone()))
                    .collect(),
            ),
        )
        .insert("ops", Op::codes(&self.area.ops));
        let mut window = Map::new();
        window
            .insert("notBefore", Value::Uint(self.not_before))
            .insert("notAfter", Value::Uint(self.not_after));
        let mut m = Map::new();
        m.insert("v", Value::Uint(FORMAT_VERSION))
            .insert("issuer", key_value(&self.issuer))
            .insert("subject", key_value(&self.subject))
            .insert_opt("parent", self.parent.as_ref().map(digest_value))
            .insert("db", digest_value(&self.db))
            .insert("area", Value::Map(area))
            .insert("window", Value::Map(window))
            .insert_opt("name", self.name.clone().map(Value::Text))
            .insert_opt("endpoint", self.endpoint.as_ref().map(key_value));
        Value::Map(m)
    }

    /// Parses a certificate value.
    pub fn from_value(value: &Value) -> Result<Cert, FormatError> {
        let f = Fields::new("cert", value, CERT_FIELDS)?;
        f.version(FORMAT_VERSION)?;
        let area = Fields::new("area", f.value("area")?, &["subspace", "pathPrefix", "ops"])?;
        let window = Fields::new("window", f.value("window")?, &["notBefore", "notAfter"])?;
        let subspace = match area.bytes("subspace")? {
            [] => Subspace::Shared,
            b => Subspace::Owner(PublicKey(b.try_into().map_err(|_| {
                FormatError::WrongType {
                    object: "area",
                    field: "subspace",
                }
            })?)),
        };
        let path_prefix = Path(
            area.array("pathPrefix")?
                .iter()
                .map(|v| match v {
                    Value::Bytes(b) => Ok(b.clone()),
                    _ => Err(FormatError::WrongType {
                        object: "area",
                        field: "pathPrefix",
                    }),
                })
                .collect::<Result<_, _>>()?,
        );
        path_prefix.check()?;
        let ops = area
            .array("ops")?
            .iter()
            .map(|v| match v {
                Value::Uint(n) => Op::from_code(*n).ok_or(FormatError::WrongType {
                    object: "area",
                    field: "ops",
                }),
                _ => Err(FormatError::WrongType {
                    object: "area",
                    field: "ops",
                }),
            })
            .collect::<Result<_, _>>()?;
        Ok(Cert {
            issuer: f.key("issuer")?,
            subject: f.key("subject")?,
            parent: f.opt_digest("parent")?,
            db: f.digest("db")?,
            area: Area {
                subspace,
                path_prefix,
                ops,
            },
            not_before: window.uint("notBefore")?,
            not_after: window.uint("notAfter")?,
            name: f.opt_text("name")?.map(str::to_owned),
            endpoint: f.opt_key("endpoint")?,
        })
    }

    /// The certificate id: BLAKE3 ("sameroot 1 cert") of the canonical certificate.
    pub fn id(&self) -> Digest {
        Digest::derive(context::CERT, &cbor::encode(&self.to_value()))
    }

    /// Signs with the issuer's key.
    pub fn sign(self, issuer: &SecretKey) -> SignedCert {
        assert_eq!(
            issuer.public(),
            self.issuer,
            "a certificate is signed by its issuer"
        );
        let sig = issuer.sign(&self.id());
        SignedCert { cert: self, sig }
    }

    /// Does this certificate cover the entry?
    fn covers(&self, h: &Header) -> bool {
        self.db == h.db
            && self.area.subspace == h.subspace
            && h.path.starts_with(&self.area.path_prefix)
            && self.area.ops.contains(&h.op)
            && self.not_before <= h.ts
            && h.ts < self.not_after
    }
}

/// A certificate with its issuer's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCert {
    /// The certificate.
    pub cert: Cert,
    /// Signature by `cert.issuer` over `cert.id()`.
    pub sig: Signature,
}

impl SignedCert {
    /// The certificate id.
    pub fn id(&self) -> Digest {
        self.cert.id()
    }

    /// Canonical bytes `{ "c": cert, "s": signature }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("c", self.cert.to_value())
            .insert("s", Value::Bytes(self.sig.0.to_vec()));
        cbor::encode(&Value::Map(m))
    }

    /// Strict decode (the signature is checked during chain validation).
    pub fn decode(bytes: &[u8]) -> Result<SignedCert, FormatError> {
        let value = cbor::decode(bytes)?;
        let f = Fields::new("signed cert", &value, &["c", "s"])?;
        Ok(SignedCert {
            cert: Cert::from_value(f.value("c")?)?,
            sig: f.signature("s")?,
        })
    }
}

/// Why a chain doesn't authorize an entry.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// A certificate of the chain is not available.
    #[error("certificate {0} is missing")]
    Missing(Digest),
    /// The chain is longer than [`MAX_CHAIN`].
    #[error("certificate chain too long")]
    TooLong,
    /// A certificate's signature doesn't verify.
    #[error("certificate signature does not verify")]
    BadSignature,
    /// A link's subject isn't the next issuer (or the entry's signer).
    #[error("certificate chain is broken")]
    Broken,
    /// A certificate doesn't cover the entry (database, area, operation or window).
    #[error("certificate does not cover the entry")]
    NotCovered,
}

/// Validates the chain of an entry signed through delegation and returns the root
/// owner. `lookup` resolves certificate ids. For an entry without `cert`, the owner
/// is the signer itself.
pub fn authority(
    h: &Header,
    lookup: &dyn Fn(&Digest) -> Option<SignedCert>,
) -> Result<PublicKey, ChainError> {
    let Some(mut next) = h.cert else {
        return Ok(h.signer);
    };
    let mut expected_subject = h.signer;
    for _ in 0..MAX_CHAIN {
        let signed = lookup(&next).ok_or(ChainError::Missing(next))?;
        let c = &signed.cert;
        signed
            .cert
            .issuer
            .verify(&signed.id(), &signed.sig)
            .map_err(|_| ChainError::BadSignature)?;
        if c.subject != expected_subject {
            return Err(ChainError::Broken);
        }
        if !c.covers(h) {
            return Err(ChainError::NotCovered);
        }
        match c.parent {
            None => return Ok(c.issuer),
            Some(parent) => {
                expected_subject = c.issuer;
                next = parent;
            }
        }
    }
    Err(ChainError::TooLong)
}

/// What a void revokes (design 0004 §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoidTarget {
    /// A certificate: every entry whose chain contains it.
    Cert(Digest),
    /// A bare key: its own entries written without a certificate (a self-kill
    /// switch; signed by that key).
    Key(PublicKey),
}

/// The entries a void keeps: a ledger-trie root (design 0003 §4.3, entry leaves)
/// over their ids, and how many there are. The list itself travels with the void.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keep {
    /// The root of the trie over the kept entry ids.
    pub root: Digest,
    /// The number of kept ids.
    pub count: u64,
}

/// A void (design 0004 §5): revokes a certificate or a bare key for good. Without
/// `keep` it is total; with `keep`, only the listed entries stay; `before` limits it
/// to entries with `ts < before`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Void {
    /// The database.
    pub db: Digest,
    /// What it revokes.
    pub target: VoidTarget,
    /// The entries that stay.
    pub keep: Option<Keep>,
    /// Covers only entries with `ts < before` (milliseconds); requires `keep`.
    pub before: Option<u64>,
    /// Proof-of-work nonce (design 0004 §6); 0 means none.
    pub work: u64,
    /// The signing key.
    pub signer: PublicKey,
}

impl Void {
    /// A total void of a certificate.
    pub fn of_cert(db: Digest, cert: Digest, signer: PublicKey) -> Void {
        Void {
            db,
            target: VoidTarget::Cert(cert),
            keep: None,
            before: None,
            work: 0,
            signer,
        }
    }

    /// A bare key's total void of itself.
    pub fn of_key(db: Digest, key: PublicKey) -> Void {
        Void {
            db,
            target: VoidTarget::Key(key),
            keep: None,
            before: None,
            work: 0,
            signer: key,
        }
    }

    /// The canonical CBOR value.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("v", Value::Uint(FORMAT_VERSION))
            .insert("db", digest_value(&self.db));
        match &self.target {
            VoidTarget::Cert(c) => m.insert("cert", digest_value(c)),
            VoidTarget::Key(k) => m.insert("key", key_value(k)),
        };
        if let Some(k) = &self.keep {
            let mut keep = Map::new();
            keep.insert("root", digest_value(&k.root))
                .insert("count", Value::Uint(k.count));
            m.insert("keep", Value::Map(keep));
        }
        m.insert_opt("before", self.before.map(Value::Uint))
            .insert_opt("work", (self.work != 0).then_some(Value::Uint(self.work)))
            .insert("signer", key_value(&self.signer));
        Value::Map(m)
    }

    /// The shape rules of design 0004 §5.2 that need nothing but the void: a key void
    /// is signed by its key and has no `keep` or `before`; `before` requires `keep`.
    pub fn shape_ok(&self) -> bool {
        let key_ok = match self.target {
            VoidTarget::Key(k) => k == self.signer && self.keep.is_none() && self.before.is_none(),
            VoidTarget::Cert(_) => true,
        };
        key_ok && (self.before.is_none() || self.keep.is_some())
    }

    /// The void id: BLAKE3 ("sameroot 1 void") of the canonical void.
    pub fn id(&self) -> Digest {
        Digest::derive(context::VOID, &cbor::encode(&self.to_value()))
    }

    /// Varies `work` until the void id has at least `bits` leading zero bits.
    pub fn mine(&mut self, bits: u32) -> u64 {
        let mut tries = 0;
        loop {
            tries += 1;
            if crate::hash::work_bits(&self.id()) >= bits {
                return tries;
            }
            self.work = self.work.wrapping_add(1);
        }
    }

    /// Signs the void.
    pub fn sign(self, key: &SecretKey) -> SignedVoid {
        let sig = key.sign(&self.id());
        SignedVoid { void: self, sig }
    }
}

/// A void with its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedVoid {
    /// The void.
    pub void: Void,
    /// Signature by `void.signer` over `void.id()`.
    pub sig: Signature,
}

impl SignedVoid {
    /// The void id.
    pub fn id(&self) -> Digest {
        self.void.id()
    }

    /// Canonical bytes `{ "h": void, "s": signature }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("h", self.void.to_value())
            .insert("s", Value::Bytes(self.sig.0.to_vec()));
        cbor::encode(&Value::Map(m))
    }

    /// Strict decode (the signature is checked by [`crate::verify::verify_void`]).
    pub fn decode(bytes: &[u8]) -> Result<SignedVoid, FormatError> {
        let value = cbor::decode(bytes)?;
        let f = Fields::new("signed void", &value, &["h", "s"])?;
        let h = Fields::new(
            "void",
            f.value("h")?,
            &["v", "db", "cert", "key", "keep", "before", "work", "signer"],
        )?;
        h.version(FORMAT_VERSION)?;
        let target = match (h.opt_digest("cert")?, h.opt_key("key")?) {
            (Some(c), None) => VoidTarget::Cert(c),
            (None, Some(k)) => VoidTarget::Key(k),
            _ => {
                return Err(FormatError::Invalid(
                    "a void names exactly one of cert and key".into(),
                ));
            }
        };
        let keep = match h.opt_value("keep") {
            None => None,
            Some(v) => {
                let k = Fields::new("keep", v, &["root", "count"])?;
                Some(Keep {
                    root: k.digest("root")?,
                    count: k.uint("count")?,
                })
            }
        };
        let work = h.opt_uint("work")?;
        if work == Some(0) {
            return Err(FormatError::Invalid(
                "work 0 is encoded by omitting it".into(),
            ));
        }
        let void = Void {
            db: h.digest("db")?,
            target,
            keep,
            before: h.opt_uint("before")?,
            work: work.unwrap_or(0),
            signer: h.key("signer")?,
        };
        if !void.shape_ok() {
            return Err(FormatError::Invalid(
                "a key void is signed by its key and has no keep or before; before requires keep"
                    .into(),
            ));
        }
        Ok(SignedVoid {
            void,
            sig: f.signature("s")?,
        })
    }
}

/// The certificate ids of an entry's chain, leaf first (empty without `cert`; it
/// stops at the first certificate `lookup` doesn't know).
pub fn chain_ids(h: &Header, lookup: &dyn Fn(&Digest) -> Option<SignedCert>) -> Vec<Digest> {
    let mut out = Vec::new();
    let mut next = h.cert;
    while let Some(id) = next {
        if out.len() == MAX_CHAIN || out.contains(&id) {
            break;
        }
        out.push(id);
        next = lookup(&id).and_then(|c| c.cert.parent);
    }
    out
}
