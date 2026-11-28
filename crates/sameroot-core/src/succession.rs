//! Succession in rewrite mode (design 0004 §8.2): the owner signs the state of the
//! parent at a cut anew in a child database.
//!
//! Pure: the caller (the owner's tool) reads the cut and the state from its node, and
//! publishes what [`rewrite`] returns.

use crate::cert::{Cert, SignedCert};
use crate::entry::{Header, Op, Path, SignedEntry, Subspace, value_hash};
use crate::forward::{Forward, SignedForward, owner_commitment};
use crate::genesis::{Genesis, Predecessor, SignedGenesis};
use crate::hash::Digest;
use crate::identity::SecretKey;

/// Where certificates for the child are published, so devices find their own
/// (design 0004 §9 Q1: a member registry as an application convention).
pub const GRANTS: &str = ".grants";

/// The cut of the parent, as the owner's node saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cut {
    /// The parent's ledger root.
    pub root: Digest,
    /// The number of records under it.
    pub count: u64,
    /// The time the carried state was computed at.
    pub as_of: u64,
}

/// One put of the parent's state that the child carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carried {
    /// The key.
    pub path: Path,
    /// The value's hash and size: the value itself is not copied, nodes already
    /// hold it by hash.
    pub value_hash: Digest,
    /// The value's size.
    pub value_size: u64,
    /// The original expiry, if any.
    pub exp: Option<u64>,
}

/// What a succession publishes.
#[derive(Clone, Debug)]
pub struct Plan {
    /// The child's genesis.
    pub genesis: SignedGenesis,
    /// The carried state and the grants, signed by the owner in the child.
    pub entries: Vec<SignedEntry>,
    /// The values of the grant entries (encoded certificates).
    pub values: Vec<Vec<u8>>,
    /// The device certificates of the child, one per device carried over.
    pub certs: Vec<SignedCert>,
    /// The parent's forward to the child.
    pub forward: SignedForward,
}

/// Why a succession can't be planned.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The key is not the parent's owner.
    #[error("the key is not the owner of the database")]
    NotOwner,
    /// The parent commits to another next owner (rotation isn't in v1).
    #[error("the database commits to another next owner")]
    NextOwner,
    /// A device certificate given to carry is not the owner's direct grant in the
    /// parent.
    #[error("certificate {0} is not a device grant of this database")]
    NotAGrant(String),
}

/// Plans a succession in rewrite mode:
///
/// - the child's genesis keeps the name, owner, contract and limits, and records the
///   predecessor and the cut; `next_owner` is the child's own commitment;
/// - every carried put is signed anew by the owner in its own subspace, at `now`
///   (the floor rule: nothing older than the child), keeping its expiry; puts
///   already expired at `now` are left out;
/// - every device certificate given must be the owner's direct grant in the parent,
///   with a valid owner signature; it is issued anew in the child with the same
///   subject, area, name and end, and published under [`GRANTS`];
/// - the forward names the child, its owner and the cut.
pub fn rewrite(
    parent: &SignedGenesis,
    owner: &SecretKey,
    cut: &Cut,
    state: &[Carried],
    devices: &[SignedCert],
    next_owner: Option<Digest>,
    now: u64,
) -> Result<Plan, Error> {
    rewrite_renewing(parent, owner, cut, state, devices, next_owner, now, None)
}

/// [`rewrite`], with the devices' certificates in the child lasting until
/// `renew_until` instead of keeping their ends: a succession renews them in one go.
#[allow(clippy::too_many_arguments)]
pub fn rewrite_renewing(
    parent: &SignedGenesis,
    owner: &SecretKey,
    cut: &Cut,
    state: &[Carried],
    devices: &[SignedCert],
    next_owner: Option<Digest>,
    now: u64,
    renew_until: Option<u64>,
) -> Result<Plan, Error> {
    let p = &parent.genesis;
    let parent_id = parent.id();
    if owner.public() != p.owner {
        return Err(Error::NotOwner);
    }
    if p.next_owner
        .is_some_and(|n| n != owner_commitment(&owner.public()))
    {
        return Err(Error::NextOwner);
    }
    let mut child = Genesis::new(&p.name, p.owner, p.contract.access.clone(), now);
    child.contract = p.contract.clone();
    child.limits = p.limits.clone();
    child.predecessor = Some(Predecessor {
        db: parent_id,
        cut_root: cut.root,
        cut_count: cut.count,
        as_of: cut.as_of,
        carry_root: None,
    });
    child.next_owner = next_owner;
    let genesis = child.sign(owner);
    let db = genesis.id();

    let put = |path: Path, value_hash: Digest, value_size: u64, exp: Option<u64>| {
        Header {
            db,
            subspace: Subspace::Owner(owner.public()),
            path,
            op: Op::Put,
            ts: now,
            exp,
            value_size,
            value_hash,
            target: None,
            signer: owner.public(),
            cert: None,
            work: 0,
        }
        .sign(owner)
    };
    let mut entries: Vec<SignedEntry> = state
        .iter()
        .filter(|c| c.exp.is_none_or(|e| e > now))
        .map(|c| put(c.path.clone(), c.value_hash, c.value_size, c.exp))
        .collect();

    let mut certs = Vec::new();
    let mut values = Vec::new();
    for d in devices {
        let c = &d.cert;
        let signed_by_owner = p.owner.verify(&c.id(), &d.sig).is_ok();
        if c.db != parent_id || c.issuer != p.owner || c.parent.is_some() || !signed_by_owner {
            return Err(Error::NotAGrant(d.id().to_hex()));
        }
        let cert = Cert {
            issuer: owner.public(),
            subject: c.subject,
            parent: None,
            db,
            area: c.area.clone(),
            not_before: now.saturating_sub(5 * 60 * 1000),
            not_after: renew_until.unwrap_or(c.not_after),
            name: c.name.clone(),
            endpoint: c.endpoint,
        }
        .sign(owner);
        let bytes = cert.encode();
        entries.push(put(
            Path::from_strs([GRANTS, &cert.id().to_hex()]),
            value_hash(&bytes),
            bytes.len() as u64,
            None,
        ));
        values.push(bytes);
        certs.push(cert);
    }

    let forward = Forward {
        db: parent_id,
        successor: db,
        owner: owner.public(),
        cut_root: cut.root,
    }
    .sign(owner);
    Ok(Plan {
        genesis,
        entries,
        values,
        certs,
        forward,
    })
}

/// Checks a child genesis against the forward that names it (design 0004 §8.1): the
/// id, the owner, the parent and the cut.
pub fn follows(forward: &Forward, child: &SignedGenesis) -> bool {
    child.id() == forward.successor
        && child.genesis.owner == forward.owner
        && child
            .genesis
            .predecessor
            .as_ref()
            .is_some_and(|p| p.db == forward.db && p.cut_root == forward.cut_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Area;
    use crate::logic;
    use crate::verify::{verify_entry, verify_forward};

    fn parent(owner: &SecretKey) -> SignedGenesis {
        Genesis::new("p", owner.public(), logic::presets::own_subspace(), 1_000).sign(owner)
    }

    fn device_cert(owner: &SecretKey, db: Digest, device: &SecretKey) -> SignedCert {
        Cert {
            issuer: owner.public(),
            subject: device.public(),
            parent: None,
            db,
            area: Area {
                subspace: Subspace::Owner(owner.public()),
                path_prefix: Path::default(),
                ops: vec![Op::Put, Op::Delete, Op::Negate],
            },
            not_before: 0,
            not_after: 9_000_000,
            name: Some("lab".into()),
            endpoint: None,
        }
        .sign(owner)
    }

    #[test]
    fn a_rewrite_is_admitted_in_the_child_and_the_forward_in_the_parent() {
        let owner = SecretKey::from_seed([1; 32]);
        let device = SecretKey::from_seed([2; 32]);
        let p = parent(&owner);
        let cut = Cut {
            root: Digest([9; 32]),
            count: 7,
            as_of: 5_000,
        };
        let state = vec![
            Carried {
                path: Path::parse("notes/a").unwrap(),
                value_hash: value_hash(b"a"),
                value_size: 1,
                exp: None,
            },
            Carried {
                path: Path::parse("notes/gone").unwrap(),
                value_hash: value_hash(b"g"),
                value_size: 1,
                exp: Some(5_500),
            },
        ];
        let dev = device_cert(&owner, p.id(), &device);
        let plan = rewrite(
            &p,
            &owner,
            &cut,
            &state,
            std::slice::from_ref(&dev),
            None,
            6_000,
        )
        .unwrap();

        let g = &plan.genesis.genesis;
        let pred = g.predecessor.as_ref().unwrap();
        assert_eq!(
            (pred.db, pred.cut_root, pred.cut_count),
            (p.id(), cut.root, 7)
        );
        assert_eq!(g.created_at, 6_000);
        assert_eq!(g.contract, p.genesis.contract);
        // The expired put is left out; the grant is added.
        assert_eq!(plan.entries.len(), 2);
        let lookup = |_: &Digest| None;
        for e in &plan.entries {
            verify_entry(g, &plan.genesis.id(), e, &lookup).unwrap();
        }
        let grant = &plan.entries[1];
        assert_eq!(
            grant.header.path,
            Path::from_strs([GRANTS, &plan.certs[0].id().to_hex()])
        );
        assert_eq!(value_hash(&plan.values[0]), grant.header.value_hash);
        let c = &plan.certs[0].cert;
        assert_eq!(
            (c.subject, c.db, c.not_after),
            (device.public(), plan.genesis.id(), 9_000_000)
        );

        verify_forward(&p.genesis, &p.id(), &plan.forward).unwrap();
        assert!(follows(&plan.forward.forward, &plan.genesis));
        let other = rewrite(&p, &owner, &cut, &[], &[], None, 6_000).unwrap();
        assert!(!follows(&plan.forward.forward, &other.genesis));
    }

    #[test]
    fn a_succession_can_renew_the_devices() {
        let owner = SecretKey::from_seed([1; 32]);
        let device = SecretKey::from_seed([2; 32]);
        let p = parent(&owner);
        let cut = Cut {
            root: Digest([0; 32]),
            count: 0,
            as_of: 0,
        };
        let dev = device_cert(&owner, p.id(), &device);
        let kept = rewrite(
            &p,
            &owner,
            &cut,
            &[],
            std::slice::from_ref(&dev),
            None,
            2_000,
        )
        .unwrap();
        assert_eq!(kept.certs[0].cert.not_after, dev.cert.not_after);
        let renewed = rewrite_renewing(
            &p,
            &owner,
            &cut,
            &[],
            std::slice::from_ref(&dev),
            None,
            2_000,
            Some(99_000_000),
        )
        .unwrap();
        assert_eq!(renewed.certs[0].cert.not_after, 99_000_000);
    }

    #[test]
    fn only_the_owner_and_only_its_grants() {
        let owner = SecretKey::from_seed([1; 32]);
        let device = SecretKey::from_seed([2; 32]);
        let p = parent(&owner);
        let cut = Cut {
            root: Digest([0; 32]),
            count: 0,
            as_of: 0,
        };
        assert_eq!(
            rewrite(&p, &device, &cut, &[], &[], None, 2_000).unwrap_err(),
            Error::NotOwner
        );
        let elsewhere = device_cert(&owner, Digest([3; 32]), &device);
        assert!(matches!(
            rewrite(&p, &owner, &cut, &[], &[elsewhere], None, 2_000),
            Err(Error::NotAGrant(_))
        ));
        let mut g = Genesis::new("p", owner.public(), logic::presets::own_subspace(), 1_000);
        g.next_owner = Some(owner_commitment(&device.public()));
        let committed = g.sign(&owner);
        assert_eq!(
            rewrite(&committed, &owner, &cut, &[], &[], None, 2_000).unwrap_err(),
            Error::NextOwner
        );
    }

    #[test]
    fn a_grant_without_the_owners_signature_is_refused() {
        let owner = SecretKey::from_seed([1; 32]);
        let device = SecretKey::from_seed([2; 32]);
        let intruder = SecretKey::from_seed([3; 32]);
        let p = parent(&owner);
        let cut = Cut {
            root: Digest([9; 32]),
            count: 7,
            as_of: 5_000,
        };
        let mut forged = device_cert(&owner, p.id(), &device);
        forged.cert.subject = intruder.public();
        assert!(matches!(
            rewrite(&p, &owner, &cut, &[], &[forged], None, 6_000),
            Err(Error::NotAGrant(_))
        ));
    }
}
