//! Entries: a signed fixed header with a detached value (design 0003 §3).

use std::cmp::Ordering;

use crate::FORMAT_VERSION;
use crate::cbor::{self, Map, Value};
use crate::fields::{Fields, FormatError, digest_value, key_value};
use crate::hash::{Digest, context};
use crate::identity::{PublicKey, SecretKey, Signature};

/// Maximum number of path components.
pub const MAX_PATH_COMPONENTS: usize = 16;
/// Maximum bytes per path component.
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Maximum total path bytes.
pub const MAX_PATH_BYTES: usize = 1024;

/// Whose data an entry is: an owner's subspace, or the shared subspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subspace {
    /// The subspace owned by this key.
    Owner(PublicKey),
    /// The reserved shared subspace (encoded as an empty byte string).
    Shared,
}

/// A path: a list of byte components (UTF-8 by convention).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Path(pub Vec<Vec<u8>>);

impl Path {
    /// A path from UTF-8 components.
    pub fn from_strs<I: IntoIterator<Item = S>, S: AsRef<str>>(components: I) -> Path {
        Path(
            components
                .into_iter()
                .map(|c| c.as_ref().as_bytes().to_vec())
                .collect(),
        )
    }

    /// Parses `a/b/c` (empty components are not allowed).
    pub fn parse(s: &str) -> Option<Path> {
        if s.is_empty() {
            return Some(Path::default());
        }
        let parts: Vec<&str> = s.split('/').collect();
        if parts.iter().any(|p| p.is_empty()) {
            return None;
        }
        Some(Path::from_strs(parts))
    }

    /// Renders components joined by `/` (lossy for non-UTF-8).
    pub fn display(&self) -> String {
        self.0
            .iter()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// True if `prefix` is a prefix of this path (component-wise).
    pub fn starts_with(&self, prefix: &Path) -> bool {
        self.0.len() >= prefix.0.len() && self.0.iter().zip(&prefix.0).all(|(a, b)| a == b)
    }

    /// Checks the format-1 limits.
    pub fn check(&self) -> Result<(), FormatError> {
        let total: usize = self.0.iter().map(Vec::len).sum();
        if self.0.len() > MAX_PATH_COMPONENTS
            || self.0.iter().any(|c| c.len() > MAX_COMPONENT_BYTES)
            || total > MAX_PATH_BYTES
        {
            return Err(FormatError::Invalid(
                "path exceeds the format-1 limits".into(),
            ));
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        Value::Array(self.0.iter().map(|c| Value::Bytes(c.clone())).collect())
    }

    fn from_value(values: &[Value]) -> Result<Path, FormatError> {
        let path = values
            .iter()
            .map(|v| match v {
                Value::Bytes(b) => Ok(b.clone()),
                _ => Err(FormatError::WrongType {
                    object: "header",
                    field: "path",
                }),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Path)?;
        path.check()?;
        Ok(path)
    }
}

/// The operation of an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    /// Set the value of a key.
    Put,
    /// Delete a key (a tombstone). Never expires.
    Delete,
    /// Ask resolution to ignore one entry (`target`). Never expires.
    Negate,
}

impl Op {
    fn code(self) -> u64 {
        match self {
            Op::Put => 0,
            Op::Delete => 1,
            Op::Negate => 2,
        }
    }

    pub(crate) fn from_code(n: u64) -> Option<Op> {
        match n {
            0 => Some(Op::Put),
            1 => Some(Op::Delete),
            2 => Some(Op::Negate),
            _ => None,
        }
    }

    pub(crate) fn codes(ops: &[Op]) -> Value {
        Value::Array(ops.iter().map(|o| Value::Uint(o.code())).collect())
    }
}

/// The signed header of an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The database the entry belongs to.
    pub db: Digest,
    /// Whose data it is.
    pub subspace: Subspace,
    /// The key.
    pub path: Path,
    /// Put, delete or negate.
    pub op: Op,
    /// The writer's clock, milliseconds since the Unix epoch.
    pub ts: u64,
    /// Expiry (milliseconds); puts only.
    pub exp: Option<u64>,
    /// Value length in bytes; puts only (0 otherwise, and absent on the wire).
    pub value_size: u64,
    /// Plain BLAKE3 of the value, so the value is an iroh blob; puts only (zero
    /// otherwise, and absent on the wire).
    pub value_hash: Digest,
    /// The negated entry; negations only.
    pub target: Option<Digest>,
    /// The signing key.
    pub signer: PublicKey,
    /// Leaf delegation certificate, if the signer isn't the subspace owner.
    pub cert: Option<Digest>,
    /// Proof-of-work nonce (design 0004 §6): varied until the entry id has enough
    /// leading zero bits. 0 means none, and is absent on the wire.
    pub work: u64,
}

const HEADER_FIELDS: &[&str] = &[
    "v",
    "db",
    "subspace",
    "path",
    "op",
    "ts",
    "exp",
    "valueSize",
    "valueHash",
    "target",
    "signer",
    "cert",
    "work",
];

impl Header {
    /// The canonical CBOR value.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("v", Value::Uint(FORMAT_VERSION))
            .insert("db", digest_value(&self.db))
            .insert(
                "subspace",
                match &self.subspace {
                    Subspace::Owner(k) => key_value(k),
                    Subspace::Shared => Value::Bytes(Vec::new()),
                },
            )
            .insert("path", self.path.to_value())
            .insert("op", Value::Uint(self.op.code()))
            .insert("ts", Value::Uint(self.ts))
            .insert_opt("exp", self.exp.map(Value::Uint))
            .insert_opt(
                "valueSize",
                (self.op == Op::Put).then_some(Value::Uint(self.value_size)),
            )
            .insert_opt(
                "valueHash",
                (self.op == Op::Put).then(|| digest_value(&self.value_hash)),
            )
            .insert_opt("target", self.target.as_ref().map(digest_value))
            .insert("signer", key_value(&self.signer))
            .insert_opt("cert", self.cert.as_ref().map(digest_value))
            .insert_opt("work", (self.work != 0).then_some(Value::Uint(self.work)));
        Value::Map(m)
    }

    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// Parses a header value.
    pub fn from_value(value: &Value) -> Result<Header, FormatError> {
        let f = Fields::new("header", value, HEADER_FIELDS)?;
        f.version(FORMAT_VERSION)?;
        let subspace = match f.bytes("subspace")? {
            [] => Subspace::Shared,
            b => Subspace::Owner(PublicKey(b.try_into().map_err(|_| {
                FormatError::WrongType {
                    object: "header",
                    field: "subspace",
                }
            })?)),
        };
        let op = Op::from_code(f.uint("op")?).ok_or(FormatError::WrongType {
            object: "header",
            field: "op",
        })?;
        let value_size = f.opt_uint("valueSize")?;
        let value_hash = f.opt_digest("valueHash")?;
        let exp = f.opt_uint("exp")?;
        let target = f.opt_digest("target")?;
        let shape_ok = match op {
            Op::Put => value_size.is_some() && value_hash.is_some() && target.is_none(),
            Op::Delete => {
                value_size.is_none() && value_hash.is_none() && exp.is_none() && target.is_none()
            }
            Op::Negate => {
                value_size.is_none() && value_hash.is_none() && exp.is_none() && target.is_some()
            }
        };
        if !shape_ok {
            return Err(FormatError::Invalid(
                "fields don't match the op (values and exp on puts only, target on negations only)"
                    .into(),
            ));
        }
        let work = f.opt_uint("work")?;
        if work == Some(0) {
            return Err(FormatError::Invalid(
                "work 0 is encoded by omitting it".into(),
            ));
        }
        Ok(Header {
            db: f.digest("db")?,
            subspace,
            path: Path::from_value(f.array("path")?)?,
            op,
            ts: f.uint("ts")?,
            exp,
            value_size: value_size.unwrap_or(0),
            value_hash: value_hash.unwrap_or(Digest::ZERO),
            target,
            signer: f.key("signer")?,
            cert: f.opt_digest("cert")?,
            work: work.unwrap_or(0),
        })
    }

    /// Varies `work` until the entry id has at least `bits` leading zero bits
    /// (design 0004 §6). Returns the number of ids tried.
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

    /// The field shapes per op that decoding enforces, for headers built in code:
    /// values and `exp` on puts only, `target` on negations only.
    pub fn shape_ok(&self) -> bool {
        match self.op {
            Op::Put => self.target.is_none(),
            Op::Delete => {
                self.value_size == 0
                    && self.value_hash == Digest::ZERO
                    && self.exp.is_none()
                    && self.target.is_none()
            }
            Op::Negate => {
                self.value_size == 0
                    && self.value_hash == Digest::ZERO
                    && self.exp.is_none()
                    && self.target.is_some()
            }
        }
    }

    /// The entry id: BLAKE3 ("sameroot 1 entry") of the canonical header.
    pub fn id(&self) -> Digest {
        Digest::derive(context::ENTRY, &self.encode())
    }

    /// Signs the header.
    pub fn sign(self, key: &SecretKey) -> SignedEntry {
        let sig = key.sign(&self.id());
        SignedEntry { header: self, sig }
    }

    /// The LWW order key.
    pub fn order(&self) -> (u64, Digest) {
        (self.ts, self.id())
    }
}

/// The hash of a value as it appears in `valueHash`: plain BLAKE3, the iroh blob
/// hash of the value (design 0003 §3).
pub fn value_hash(value: &[u8]) -> Digest {
    Digest(*blake3::hash(value).as_bytes())
}

/// A header with its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEntry {
    /// The header.
    pub header: Header,
    /// Ed25519 signature by `header.signer` over `header.id()`.
    pub sig: Signature,
}

impl SignedEntry {
    /// The entry id.
    pub fn id(&self) -> Digest {
        self.header.id()
    }

    /// Canonical bytes: `{ "h": header, "s": signature }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("h", self.header.to_value())
            .insert("s", Value::Bytes(self.sig.0.to_vec()));
        cbor::encode(&Value::Map(m))
    }

    /// Strict decode (the signature is not checked here; see [`crate::verify`]).
    pub fn decode(bytes: &[u8]) -> Result<SignedEntry, FormatError> {
        let value = cbor::decode(bytes)?;
        let f = Fields::new("entry", &value, &["h", "s"])?;
        Ok(SignedEntry {
            header: Header::from_value(f.value("h")?)?,
            sig: f.signature("s")?,
        })
    }
}

/// Last-writer-wins: does `a` win over `b` for the same key? Ties on `ts` are
/// broken by the entry id.
pub fn wins(a: &Header, b: &Header) -> bool {
    a.order().cmp(&b.order()) == Ordering::Greater
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(ts: u64) -> Header {
        let key = SecretKey::from_seed([1; 32]);
        Header {
            db: Digest::derive(context::GENESIS, b"db"),
            subspace: Subspace::Owner(key.public()),
            path: Path::from_strs(["notes", "a"]),
            op: Op::Put,
            ts,
            exp: None,
            value_size: 2,
            value_hash: value_hash(b"hi"),
            target: None,
            signer: key.public(),
            cert: None,
            work: 0,
        }
    }

    #[test]
    fn op_shapes() {
        let key = SecretKey::from_seed([1; 32]);
        let mut neg = header(4);
        neg.op = Op::Negate;
        neg.value_size = 0;
        neg.value_hash = Digest::ZERO;
        neg.target = Some(header(3).id());
        let e = neg.clone().sign(&key);
        assert_eq!(SignedEntry::decode(&e.encode()).unwrap(), e);
        // A negation that expires, a delete with a target, a put without a value: refused.
        let mut bad = neg.clone();
        bad.exp = Some(9);
        assert!(Header::from_value(&bad.to_value()).is_err());
        let mut bad = neg.clone();
        bad.op = Op::Delete;
        assert!(Header::from_value(&bad.to_value()).is_err());
        let mut del = header(5);
        del.op = Op::Delete;
        del.exp = Some(9);
        assert!(Header::from_value(&del.to_value()).is_err());
        assert_eq!(value_hash(b"hi"), Digest(*blake3::hash(b"hi").as_bytes()));
    }

    #[test]
    fn roundtrip() {
        let e = header(5).sign(&SecretKey::from_seed([1; 32]));
        let bytes = e.encode();
        assert_eq!(SignedEntry::decode(&bytes).unwrap(), e);
    }

    #[test]
    fn rejects_unknown_fields_and_versions() {
        let mut v = header(1).to_value();
        if let Value::Map(m) = &mut v {
            m.insert("extra", Value::Null);
        }
        assert!(matches!(
            Header::from_value(&v),
            Err(FormatError::UnknownField { .. })
        ));
        let mut v = header(1).to_value();
        if let Value::Map(m) = &mut v {
            *m = m
                .iter()
                .map(|(k, val)| {
                    (
                        k.to_owned(),
                        if k == "v" {
                            Value::Uint(2)
                        } else {
                            val.clone()
                        },
                    )
                })
                .fold(Map::new(), |mut acc, (k, val)| {
                    acc.insert(&k, val);
                    acc
                });
        }
        assert!(matches!(
            Header::from_value(&v),
            Err(FormatError::Version { version: 2, .. })
        ));
    }

    #[test]
    fn lww_order() {
        assert!(wins(&header(2), &header(1)));
        assert!(!wins(&header(1), &header(2)));
        let (a, b) = (header(3), {
            let mut h = header(3);
            h.value_hash = value_hash(b"other");
            h
        });
        assert_ne!(
            wins(&a, &b),
            wins(&b, &a),
            "ties are broken by the entry id"
        );
    }

    #[test]
    fn path_limits() {
        assert!(Path(vec![vec![0; 256]]).check().is_err());
        assert!(Path(vec![vec![0]; 17]).check().is_err());
        assert!(Path(vec![vec![0; 255]; 4]).check().is_ok()); // 1020 bytes
        assert!(Path(vec![vec![0; 255]; 5]).check().is_err()); // 1275 bytes
        assert_eq!(Path::parse("a/b"), Some(Path::from_strs(["a", "b"])));
        assert_eq!(Path::parse("a//b"), None);
    }
}
