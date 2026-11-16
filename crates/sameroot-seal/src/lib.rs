//! Sealed values: application-level encryption on an open platform (vision,
//! principle 8; design 0003 §3).
//!
//! The ledger is readable by every node, so an application that keeps private data
//! seals its values before writing them. A sealed value is
//!
//! ```text
//! "SRS1" ‖ key id (8 bytes) ‖ nonce (24 bytes) ‖ XChaCha20-Poly1305 ciphertext and tag
//! ```
//!
//! with associated data `"sameroot sealed value 1" ‖ 0x00 ‖ origin id (32) ‖ path`, where the
//! origin is the first database of the succession chain (the caller passes it),
//! so a sealed value only opens in the chain and under the path it was written for.
//! Every seal draws a fresh random nonce: equal plaintexts give unrelated ciphertexts,
//! and their hashes say nothing about each other.
//!
//! The key is 32 random bytes, shared by the owner's devices out of band (a file with
//! mode 0600). Signed headers stay public.
//!
//! **Hidden names.** [`MemoryKey::hide_path`] maps a path to `~/t1/t2/…`, where each
//! token is a keyed BLAKE3 MAC (under a subkey of the memory key) of the component and
//! the tokens before it, 128 bits in lowercase base32. The same name gives the same
//! tokens on every device with the key, so lookups and prefix listings work; without
//! the key the tokens say nothing about the names. They still show the depth of a path
//! and which paths share a parent.

use std::io::Write;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Prefix of every sealed value.
pub const MAGIC: &[u8; 4] = b"SRS1";
const ID_LEN: usize = 8;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + ID_LEN + NONCE_LEN;
const AAD_CONTEXT: &[u8] = b"sameroot sealed value 1\0";

/// Why a sealed value didn't open, or a key couldn't be used.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// Not a sealed value.
    #[error("not a sealed value")]
    NotSealed,
    /// Sealed with another key.
    #[error("sealed with another key ({0})")]
    OtherKey(String),
    /// Wrong database or path, or tampered bytes.
    #[error("doesn't open: wrong database or path, or tampered")]
    Corrupt,
    /// The key file is malformed.
    #[error("key file must hold exactly 32 bytes")]
    BadKey,
    /// Reading or writing the key file failed.
    #[error("key file: {0}")]
    Io(#[from] std::io::Error),
}

/// A memory key: 32 random bytes.
pub struct MemoryKey {
    key: [u8; 32],
}

impl std::fmt::Debug for MemoryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemoryKey({})", self.id_hex())
    }
}

/// The first component of every hidden path.
pub const HIDDEN_ROOT: &str = "~";

/// Is `path` a hidden path (made by [`MemoryKey::hide_path`])?
pub fn is_hidden_path(path: &str) -> bool {
    path == HIDDEN_ROOT || path.starts_with("~/")
}

fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Is `value` a sealed value?
pub fn is_sealed(value: &[u8]) -> bool {
    value.len() > HEADER_LEN && value.starts_with(MAGIC)
}

/// The key id a sealed value names, as hex.
pub fn sealed_key_id(value: &[u8]) -> Option<String> {
    is_sealed(value).then(|| hex(&value[4..4 + ID_LEN]))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn aad(db: &[u8; 32], path: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_CONTEXT.len() + 32 + path.len());
    a.extend_from_slice(AAD_CONTEXT);
    a.extend_from_slice(db);
    a.extend_from_slice(path.as_bytes());
    a
}

impl MemoryKey {
    /// A new random key.
    pub fn generate() -> MemoryKey {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("operating system random source");
        MemoryKey { key }
    }

    /// A key from its 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<MemoryKey, SealError> {
        Ok(MemoryKey {
            key: bytes.try_into().map_err(|_| SealError::BadKey)?,
        })
    }

    /// Loads the key at `path`, if the file exists.
    pub fn load(path: &Path) -> Result<Option<MemoryKey>, SealError> {
        match std::fs::read(path) {
            Ok(b) => MemoryKey::from_bytes(&b).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Creates a new key file at `path` (mode 0600); fails if it exists.
    pub fn create(path: &Path) -> Result<MemoryKey, SealError> {
        use std::os::unix::fs::OpenOptionsExt;
        let key = MemoryKey::generate();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(&key.key)?;
        f.sync_all()?;
        Ok(key)
    }

    /// The key's id: the first 8 bytes of BLAKE3-derive("sameroot memory key id", key).
    pub fn id(&self) -> [u8; ID_LEN] {
        let d = blake3::derive_key("sameroot memory key id", &self.key);
        d[..ID_LEN].try_into().expect("8 bytes")
    }

    /// The key's id as hex.
    pub fn id_hex(&self) -> String {
        hex(&self.id())
    }

    /// The hidden form of a path: `~` followed by one token per component.
    pub fn hide_path(&self, path: &str) -> String {
        let names = blake3::derive_key("sameroot memory names 1", &self.key);
        let mut out = String::from(HIDDEN_ROOT);
        for component in path.split('/') {
            let mut mac = blake3::Hasher::new_keyed(&names);
            mac.update(out.as_bytes());
            mac.update(&[0]);
            mac.update(component.as_bytes());
            out.push('/');
            out.push_str(&base32(&mac.finalize().as_bytes()[..16]));
        }
        out
    }

    /// Seals `plaintext` for `path` in database `db`.
    pub fn seal(&self, db: &[u8; 32], path: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("operating system random source");
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let aad = aad(db, path);
        let ct = cipher
            .encrypt(
                &XNonce::try_from(&nonce[..]).expect("24 bytes"),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("encryption of an in-memory buffer");
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.id());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Opens a sealed value written for `path` in database `db`.
    pub fn open(&self, db: &[u8; 32], path: &str, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if !is_sealed(sealed) {
            return Err(SealError::NotSealed);
        }
        if sealed[4..4 + ID_LEN] != self.id() {
            return Err(SealError::OtherKey(hex(&sealed[4..4 + ID_LEN])));
        }
        let nonce =
            XNonce::try_from(&sealed[4 + ID_LEN..HEADER_LEN]).map_err(|_| SealError::Corrupt)?;
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &sealed[HEADER_LEN..],
                    aad: &aad(db, path),
                },
            )
            .map_err(|_| SealError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB: [u8; 32] = [7; 32];

    #[test]
    fn roundtrip_and_binding() {
        let k = MemoryKey::generate();
        let s = k.seal(&DB, "notes/a", b"secret");
        assert!(is_sealed(&s));
        assert_eq!(sealed_key_id(&s), Some(k.id_hex()));
        assert_eq!(k.open(&DB, "notes/a", &s).unwrap(), b"secret");
        // Moved to another path or database: doesn't open.
        assert!(matches!(
            k.open(&DB, "notes/b", &s),
            Err(SealError::Corrupt)
        ));
        assert!(matches!(
            k.open(&[8; 32], "notes/a", &s),
            Err(SealError::Corrupt)
        ));
        // Tampered: doesn't open.
        let mut t = s.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(matches!(
            k.open(&DB, "notes/a", &t),
            Err(SealError::Corrupt)
        ));
        // Another key.
        assert!(matches!(
            MemoryKey::generate().open(&DB, "notes/a", &s),
            Err(SealError::OtherKey(_))
        ));
        // Plaintext isn't sealed.
        assert!(!is_sealed(b"{\"plain\":true}"));
        assert!(matches!(
            k.open(&DB, "notes/a", b"plain"),
            Err(SealError::NotSealed)
        ));
    }

    #[test]
    fn hidden_paths() {
        let k = MemoryKey::generate();
        let a = k.hide_path("notes/topic");
        assert!(is_hidden_path(&a));
        assert!(!a.contains("notes") && !a.contains("topic"));
        assert_eq!(a.split('/').count(), 3);
        assert!(a.split('/').skip(1).all(|t| t.len() == 26));
        // Deterministic, so lookups work; prefix-preserving, so listings work.
        assert_eq!(a, k.hide_path("notes/topic"));
        assert!(a.starts_with(&(k.hide_path("notes") + "/")));
        assert_ne!(a, k.hide_path("notes/other"));
        // The same name in another place, or under another key, is another token.
        assert_ne!(k.hide_path("topic").split('/').nth(1), a.split('/').nth(2));
        assert_ne!(MemoryKey::generate().hide_path("notes/topic"), a);
        assert!(!is_hidden_path("notes/~"));
        assert_eq!(base32(&[0xff; 16]).len(), 26);
    }

    #[test]
    fn equal_plaintexts_seal_differently() {
        let k = MemoryKey::generate();
        assert_ne!(k.seal(&DB, "p", b"same"), k.seal(&DB, "p", b"same"));
    }

    #[test]
    fn key_files() {
        let dir = std::env::temp_dir().join(format!("sameroot-seal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("memory.key");
        assert!(MemoryKey::load(&path).unwrap().is_none());
        let k = MemoryKey::create(&path).unwrap();
        assert!(MemoryKey::create(&path).is_err(), "never overwrites a key");
        let again = MemoryKey::load(&path).unwrap().unwrap();
        assert_eq!(k.id(), again.id());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(&path, b"short").unwrap();
        assert!(matches!(MemoryKey::load(&path), Err(SealError::BadKey)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
