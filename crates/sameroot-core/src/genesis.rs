//! Database genesis: the manifest with its contract (design 0003 §5.1).

use crate::FORMAT_VERSION;
use crate::cbor::{self, Map, Value};
use crate::fields::{Fields, FormatError, digest_value, key_value};
use crate::hash::{Digest, context};
use crate::identity::{PublicKey, SecretKey, Signature};
use crate::logic;

/// How the state is computed from the ledger (design 0003 §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Per key, the put or delete with the largest `(ts, id)`.
    Lww,
    /// Per key, the put or delete with the smallest `(ts, id)` (claimed time).
    Earliest,
    /// Per key, the set of remaining puts.
    Collection,
}

/// Who may negate an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegateRight {
    /// The negation's chain root equals the target's chain root.
    Author,
    /// The database owner.
    Owner,
    /// Either.
    Both,
}

/// The resolution rule and its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// The rule.
    pub rule: Rule,
    /// Negation right.
    pub negate: NegateRight,
}

impl Default for Resolution {
    fn default() -> Self {
        Resolution {
            rule: Rule::Lww,
            negate: NegateRight::Author,
        }
    }
}

/// The contract every node enforces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    /// Logic 1 program: who may write what.
    pub access: Value,
    /// Logic 1 program: which entries are valid on their own.
    pub validity: Value,
    /// How the state is derived from the ledger.
    pub resolution: Resolution,
}

/// Limits that every replica enforces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest value in bytes.
    pub max_value: u64,
    /// Allowed clock skew for future timestamps, milliseconds (local deferral).
    pub ts_skew: u64,
    /// If set, every put must expire within this many milliseconds.
    pub max_ttl: Option<u64>,
    /// Most entry ids a void's keep list may hold (design 0004 §5.2); `None` means
    /// [`DEFAULT_MAX_KEEP`].
    pub max_keep_count: Option<u64>,
    /// Leading zero bits a void needs unless its chain root is the owner (design 0004
    /// §5.2, §6); `None` means 0.
    pub void_work: Option<u64>,
}

/// The default limit on a keep list: 65 536 ids, 2 MiB.
pub const DEFAULT_MAX_KEEP: u64 = 1 << 16;
/// The largest keep-list limit a genesis may set: 262 144 ids, 8 MiB, so a void and
/// its list always fit one protocol frame (16 MiB).
pub const MAX_KEEP_CAP: u64 = 1 << 18;

impl Limits {
    /// The effective keep-list limit.
    pub fn keep_limit(&self) -> u64 {
        self.max_keep_count
            .unwrap_or(DEFAULT_MAX_KEEP)
            .min(MAX_KEEP_CAP)
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_value: 1 << 20,
            ts_skew: 10 * 60 * 1000,
            max_ttl: None,
            max_keep_count: None,
            void_work: None,
        }
    }
}

/// What a successor database inherits from (design 0004 §8.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Predecessor {
    /// The parent database.
    pub db: Digest,
    /// The parent's ledger root at the cut.
    pub cut_root: Digest,
    /// The number of records under `cut_root`.
    pub cut_count: u64,
    /// The time the carried state was computed at.
    pub as_of: u64,
    /// For verbatim carry (later): the root over the carried entry ids.
    pub carry_root: Option<Digest>,
}

/// The genesis of a database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    /// Random bytes, so two otherwise equal databases get different ids.
    pub nonce: [u8; 16],
    /// Creation time, milliseconds.
    pub created_at: u64,
    /// Display name.
    pub name: String,
    /// The creator; signs the genesis and is the succession authority.
    pub owner: PublicKey,
    /// The contract.
    pub contract: Contract,
    /// Limits.
    pub limits: Limits,
    /// The database this one succeeds.
    pub predecessor: Option<Predecessor>,
    /// The commitment to the next owner key (`owner_commitment`): a forward out of
    /// this database must name an owner that matches it.
    pub next_owner: Option<Digest>,
}

const GENESIS_FIELDS: &[&str] = &[
    "v",
    "nonce",
    "createdAt",
    "name",
    "owner",
    "contract",
    "limits",
    "predecessor",
    "nextOwner",
];

fn rule_name(r: Rule) -> &'static str {
    match r {
        Rule::Lww => "lww",
        Rule::Earliest => "earliest",
        Rule::Collection => "collection",
    }
}

fn negate_name(n: NegateRight) -> &'static str {
    match n {
        NegateRight::Author => "author",
        NegateRight::Owner => "owner",
        NegateRight::Both => "both",
    }
}

impl Genesis {
    /// A new genesis with a random nonce, the given `access` program, `validity`
    /// accepting everything and the default resolution (`lww`, negation by author).
    pub fn new(name: &str, owner: PublicKey, access: Value, created_at: u64) -> Genesis {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).expect("operating system random source");
        Genesis {
            nonce,
            created_at,
            name: name.to_owned(),
            owner,
            contract: Contract {
                access,
                validity: logic::presets::always(),
                resolution: Resolution::default(),
            },
            limits: Limits::default(),
            predecessor: None,
            next_owner: None,
        }
    }

    /// The canonical CBOR value.
    pub fn to_value(&self) -> Value {
        let mut params = Map::new();
        params.insert(
            "negate",
            Value::Text(negate_name(self.contract.resolution.negate).into()),
        );
        let mut resolution = Map::new();
        resolution
            .insert(
                "rule",
                Value::Text(rule_name(self.contract.resolution.rule).into()),
            )
            .insert("params", Value::Map(params));
        let mut contract = Map::new();
        contract
            .insert("access", self.contract.access.clone())
            .insert("validity", self.contract.validity.clone())
            .insert("resolution", Value::Map(resolution));
        let mut limits = Map::new();
        limits
            .insert("maxValue", Value::Uint(self.limits.max_value))
            .insert("tsSkew", Value::Uint(self.limits.ts_skew))
            .insert_opt("maxTtl", self.limits.max_ttl.map(Value::Uint))
            .insert_opt("maxKeepCount", self.limits.max_keep_count.map(Value::Uint))
            .insert_opt("voidWork", self.limits.void_work.map(Value::Uint));
        let predecessor = self.predecessor.as_ref().map(|p| {
            let mut m = Map::new();
            m.insert("db", digest_value(&p.db))
                .insert("cutRoot", digest_value(&p.cut_root))
                .insert("cutCount", Value::Uint(p.cut_count))
                .insert("asOf", Value::Uint(p.as_of))
                .insert_opt("carryRoot", p.carry_root.as_ref().map(digest_value));
            Value::Map(m)
        });
        let mut m = Map::new();
        m.insert("v", Value::Uint(FORMAT_VERSION))
            .insert("nonce", Value::Bytes(self.nonce.to_vec()))
            .insert("createdAt", Value::Uint(self.created_at))
            .insert("name", Value::Text(self.name.clone()))
            .insert("owner", key_value(&self.owner))
            .insert("contract", Value::Map(contract))
            .insert("limits", Value::Map(limits))
            .insert_opt("predecessor", predecessor)
            .insert_opt("nextOwner", self.next_owner.as_ref().map(digest_value));
        Value::Map(m)
    }

    /// Parses a genesis value; the contract's programs must be well-formed Logic 1.
    pub fn from_value(value: &Value) -> Result<Genesis, FormatError> {
        let f = Fields::new("genesis", value, GENESIS_FIELDS)?;
        f.version(FORMAT_VERSION)?;
        let c = Fields::new(
            "contract",
            f.value("contract")?,
            &["access", "validity", "resolution"],
        )?;
        let access = c.value("access")?.clone();
        let validity = c.value("validity")?.clone();
        for p in [&access, &validity] {
            logic::check_program(p)
                .map_err(|e| FormatError::Invalid(format!("contract program: {e}")))?;
        }
        let r = Fields::new("resolution", c.value("resolution")?, &["rule", "params"])?;
        let rule = match r.text("rule")? {
            "lww" => Rule::Lww,
            "earliest" => Rule::Earliest,
            "collection" => Rule::Collection,
            other => {
                return Err(FormatError::Invalid(format!(
                    "unknown resolution rule {other}"
                )));
            }
        };
        let params = Fields::new("params", r.value("params")?, &["negate"])?;
        let negate = match params.text("negate")? {
            "author" => NegateRight::Author,
            "owner" => NegateRight::Owner,
            "both" => NegateRight::Both,
            other => {
                return Err(FormatError::Invalid(format!(
                    "unknown negation right {other}"
                )));
            }
        };
        let limits = Fields::new(
            "limits",
            f.value("limits")?,
            &["maxValue", "tsSkew", "maxTtl", "maxKeepCount", "voidWork"],
        )?;
        let predecessor = match f.opt_value("predecessor") {
            None => None,
            Some(v) => {
                let p = Fields::new(
                    "predecessor",
                    v,
                    &["db", "cutRoot", "cutCount", "asOf", "carryRoot"],
                )?;
                Some(Predecessor {
                    db: p.digest("db")?,
                    cut_root: p.digest("cutRoot")?,
                    cut_count: p.uint("cutCount")?,
                    as_of: p.uint("asOf")?,
                    carry_root: p.opt_digest("carryRoot")?,
                })
            }
        };
        Ok(Genesis {
            nonce: f
                .bytes("nonce")?
                .try_into()
                .map_err(|_| FormatError::WrongType {
                    object: "genesis",
                    field: "nonce",
                })?,
            created_at: f.uint("createdAt")?,
            name: f.text("name")?.to_owned(),
            owner: f.key("owner")?,
            contract: Contract {
                access,
                validity,
                resolution: Resolution { rule, negate },
            },
            limits: Limits {
                max_value: limits.uint("maxValue")?,
                ts_skew: limits.uint("tsSkew")?,
                max_ttl: limits.opt_uint("maxTtl")?,
                max_keep_count: match limits.opt_uint("maxKeepCount")? {
                    Some(n) if n > MAX_KEEP_CAP => {
                        return Err(FormatError::Invalid(format!(
                            "maxKeepCount {n} is above {MAX_KEEP_CAP}"
                        )));
                    }
                    n => n,
                },
                void_work: limits.opt_uint("voidWork")?,
            },
            predecessor,
            next_owner: f.opt_digest("nextOwner")?,
        })
    }

    /// The database id: BLAKE3 ("sameroot 1 genesis") of the canonical genesis.
    pub fn id(&self) -> Digest {
        Digest::derive(context::GENESIS, &cbor::encode(&self.to_value()))
    }

    /// Signs the genesis with the owner's key.
    pub fn sign(self, owner: &SecretKey) -> SignedGenesis {
        assert_eq!(
            owner.public(),
            self.owner,
            "the genesis is signed by its owner"
        );
        let sig = owner.sign(&self.id());
        SignedGenesis { genesis: self, sig }
    }
}

/// A genesis with the owner's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGenesis {
    /// The genesis.
    pub genesis: Genesis,
    /// Signature by `genesis.owner` over `genesis.id()`.
    pub sig: Signature,
}

impl SignedGenesis {
    /// The database id.
    pub fn id(&self) -> Digest {
        self.genesis.id()
    }

    /// Canonical bytes `{ "g": genesis, "s": signature }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("g", self.genesis.to_value())
            .insert("s", Value::Bytes(self.sig.0.to_vec()));
        cbor::encode(&Value::Map(m))
    }

    /// Strict decode and signature check.
    pub fn decode(bytes: &[u8]) -> Result<SignedGenesis, FormatError> {
        let value = cbor::decode(bytes)?;
        let f = Fields::new("signed genesis", &value, &["g", "s"])?;
        let signed = SignedGenesis {
            genesis: Genesis::from_value(f.value("g")?)?,
            sig: f.signature("s")?,
        };
        signed
            .genesis
            .owner
            .verify(&signed.id(), &signed.sig)
            .map_err(|e| FormatError::Invalid(format!("genesis signature: {e}")))?;
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic::presets;

    #[test]
    fn roundtrip_and_program_checks() {
        let owner = SecretKey::from_seed([3; 32]);
        let mut g = Genesis::new("g", owner.public(), presets::own_subspace(), 1);
        g.contract.resolution = Resolution {
            rule: Rule::Collection,
            negate: NegateRight::Both,
        };
        let s = g.clone().sign(&owner);
        assert_eq!(SignedGenesis::decode(&s.encode()).unwrap(), s);
        let mut bad = g.clone();
        let mut m = Map::new();
        m.insert("plus", Value::Array(vec![Value::Uint(1)]));
        bad.contract.access = Value::Map(m);
        assert!(
            Genesis::from_value(&bad.to_value()).is_err(),
            "unknown operator in the contract"
        );
    }
}
