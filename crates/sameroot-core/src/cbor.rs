//! The frozen CBOR profile of format 1 (`spec/01-encoding.md`).
//!
//! A deliberately small subset of CBOR: unsigned and negative integers up to 64
//! bits, byte strings, text strings, arrays, maps with **text keys only**,
//! `false`/`true`/`null`. Definite lengths only, shortest-form integers and
//! lengths, map keys in canonical order (length first, then bytewise — for text
//! keys this is both the RFC 7049 and the RFC 8949 order), no duplicate keys, no
//! tags, no floats, nesting depth at most [`MAX_DEPTH`].
//!
//! [`decode`] is strict: it rejects anything outside the profile, trailing bytes,
//! and any input whose canonical re-encoding differs from the input.

use std::collections::BTreeMap;

/// Maximum nesting depth of arrays and maps.
pub const MAX_DEPTH: usize = 16;

/// A value of the CBOR profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An unsigned integer (major type 0).
    Uint(u64),
    /// A negative integer `-1 - n` (major type 1), stored as `n`.
    Nint(u64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A UTF-8 text string.
    Text(String),
    /// An array.
    Array(Vec<Value>),
    /// A map with text keys, kept in canonical order.
    Map(Map),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
}

/// A map with text keys in canonical CBOR order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Map(BTreeMap<CanonicalKey, Value>);

/// A text map key ordered canonically: shorter keys first, then bytewise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalKey(pub String);

impl Ord for CanonicalKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.0.len(), self.0.as_bytes()).cmp(&(other.0.len(), other.0.as_bytes()))
    }
}

impl PartialOrd for CanonicalKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Map {
    /// An empty map.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Inserts a field; panics on a duplicate key (a programming error).
    pub fn insert(&mut self, key: &str, value: Value) -> &mut Self {
        let previous = self.0.insert(CanonicalKey(key.to_owned()), value);
        assert!(previous.is_none(), "duplicate map key {key}");
        self
    }

    /// Inserts a field only if `value` is `Some`.
    pub fn insert_opt(&mut self, key: &str, value: Option<Value>) -> &mut Self {
        if let Some(value) = value {
            self.insert(key, value);
        }
        self
    }

    /// The value of a field, if present.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(&CanonicalKey(key.to_owned()))
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if the map has no fields.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Fields in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.0.as_str(), v))
    }
}

/// Why an input is not valid CBOR of the profile.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The input ended inside a value.
    #[error("unexpected end of input")]
    Eof,
    /// Bytes remain after the top-level value.
    #[error("trailing bytes after the value")]
    TrailingBytes,
    /// A major type or simple value outside the profile (tags, floats, undefined, …).
    #[error("unsupported CBOR item (initial byte {0:#04x})")]
    Unsupported(u8),
    /// An indefinite-length item.
    #[error("indefinite length is not allowed")]
    Indefinite,
    /// An integer or length not in its shortest form.
    #[error("non-shortest integer or length encoding")]
    NonCanonicalInt,
    /// A map key that is not a text string.
    #[error("map keys must be text strings")]
    NonTextKey,
    /// Map keys out of canonical order, or duplicated.
    #[error("map keys out of canonical order or duplicated")]
    KeyOrder,
    /// A text string that is not valid UTF-8.
    #[error("text string is not valid UTF-8")]
    InvalidUtf8,
    /// Nesting deeper than [`MAX_DEPTH`].
    #[error("nesting deeper than {MAX_DEPTH}")]
    TooDeep,
    /// The canonical re-encoding differs from the input.
    #[error("input is not in canonical form")]
    NotCanonical,
}

/// Encodes a value canonically.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(n) => head(0, *n, out),
        Value::Nint(n) => head(1, *n, out),
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(map) => {
            head(5, map.len() as u64, out);
            for (k, v) in map.iter() {
                head(3, k.len() as u64, out);
                out.extend_from_slice(k.as_bytes());
                encode_into(v, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

/// Decodes one value of the profile, strictly (see the module docs).
pub fn decode(input: &[u8]) -> Result<Value, DecodeError> {
    let mut reader = Reader { input, pos: 0 };
    let value = reader.value(0)?;
    if reader.pos != input.len() {
        return Err(DecodeError::TrailingBytes);
    }
    // The checks above already enforce canonical form; this is the belt-and-braces
    // rule the spec requires of every implementation.
    if encode(&value) != input {
        return Err(DecodeError::NotCanonical);
    }
    Ok(value)
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.input.get(self.pos).ok_or(DecodeError::Eof)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: u64) -> Result<&[u8], DecodeError> {
        let n = usize::try_from(n).map_err(|_| DecodeError::Eof)?;
        let end = self.pos.checked_add(n).ok_or(DecodeError::Eof)?;
        let slice = self.input.get(self.pos..end).ok_or(DecodeError::Eof)?;
        self.pos = end;
        Ok(slice)
    }

    /// Reads the argument of an initial byte, enforcing the shortest form.
    fn argument(&mut self, initial: u8) -> Result<u64, DecodeError> {
        let info = initial & 0x1f;
        let (n, min) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.byte()?), 24),
            25 => (
                u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
                0x100,
            ),
            26 => (
                u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
            31 => return Err(DecodeError::Indefinite),
            _ => return Err(DecodeError::Unsupported(initial)),
        };
        if n < min {
            return Err(DecodeError::NonCanonicalInt);
        }
        Ok(n)
    }

    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let initial = self.byte()?;
        let major = initial >> 5;
        match major {
            0 => Ok(Value::Uint(self.argument(initial)?)),
            1 => Ok(Value::Nint(self.argument(initial)?)),
            2 => {
                let n = self.argument(initial)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.argument(initial)?;
                let bytes = self.take(n)?.to_vec();
                Ok(Value::Text(
                    String::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)?,
                ))
            }
            4 | 5 => {
                if depth >= MAX_DEPTH {
                    return Err(DecodeError::TooDeep);
                }
                let n = self.argument(initial)?;
                if major == 4 {
                    // Each item takes at least one byte: reject absurd lengths early.
                    if n > (self.input.len() - self.pos) as u64 {
                        return Err(DecodeError::Eof);
                    }
                    let mut items = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        items.push(self.value(depth + 1)?);
                    }
                    Ok(Value::Array(items))
                } else {
                    let mut map = Map::new();
                    let mut previous: Option<CanonicalKey> = None;
                    for _ in 0..n {
                        let key_initial = self.byte()?;
                        if key_initial >> 5 != 3 {
                            return Err(DecodeError::NonTextKey);
                        }
                        let len = self.argument(key_initial)?;
                        let key = String::from_utf8(self.take(len)?.to_vec())
                            .map_err(|_| DecodeError::InvalidUtf8)?;
                        let key = CanonicalKey(key);
                        if previous.as_ref().is_some_and(|p| *p >= key) {
                            return Err(DecodeError::KeyOrder);
                        }
                        let value = self.value(depth + 1)?;
                        map.0.insert(key.clone(), value);
                        previous = Some(key);
                    }
                    Ok(Value::Map(map))
                }
            }
            7 => match initial {
                0xf4 => Ok(Value::Bool(false)),
                0xf5 => Ok(Value::Bool(true)),
                0xf6 => Ok(Value::Null),
                0xff => Err(DecodeError::Indefinite),
                _ => Err(DecodeError::Unsupported(initial)),
            },
            _ => Err(DecodeError::Unsupported(initial)), // major 6: tags
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn roundtrip_and_canonical_order() {
        let mut m = Map::new();
        m.insert("zz", Value::Uint(1))
            .insert("a", Value::Bytes(vec![1, 2]))
            .insert("bb", Value::Null);
        let v = Value::Map(m);
        let bytes = encode(&v);
        // keys: "a" (len 1) before "bb" and "zz" (len 2), then bytewise
        assert_eq!(bytes, hex("a36161420102626262f6627a7a01"));
        assert_eq!(decode(&bytes).unwrap(), v);
    }

    #[test]
    fn integers_use_shortest_form() {
        for (n, h) in [
            (0u64, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65536, "1a00010000"),
            (u64::MAX, "1bffffffffffffffff"),
        ] {
            assert_eq!(encode(&Value::Uint(n)), hex(h), "{n}");
            assert_eq!(decode(&hex(h)).unwrap(), Value::Uint(n));
        }
        assert_eq!(decode(&hex("1817")), Err(DecodeError::NonCanonicalInt));
        assert_eq!(decode(&hex("190017")), Err(DecodeError::NonCanonicalInt));
    }

    #[test]
    fn rejects_everything_outside_the_profile() {
        assert_eq!(decode(&hex("c100")), Err(DecodeError::Unsupported(0xc1))); // tag
        assert_eq!(decode(&hex("f93c00")), Err(DecodeError::Unsupported(0xf9))); // half float
        assert_eq!(decode(&hex("f7")), Err(DecodeError::Unsupported(0xf7))); // undefined
        assert_eq!(decode(&hex("9f00ff")), Err(DecodeError::Indefinite));
        assert_eq!(decode(&hex("a10000")), Err(DecodeError::NonTextKey));
        assert_eq!(decode(&hex("a2616201616101")), Err(DecodeError::KeyOrder)); // "b" before "a"
        assert_eq!(decode(&hex("a2616101616101")), Err(DecodeError::KeyOrder)); // duplicate
        assert_eq!(decode(&hex("0000")), Err(DecodeError::TrailingBytes));
        assert_eq!(decode(&hex("62c328")), Err(DecodeError::InvalidUtf8));
        assert_eq!(decode(&hex("5a00010000")), Err(DecodeError::Eof)); // 65536-byte string, input ends
        assert_eq!(
            decode(&hex("5a00000010")),
            Err(DecodeError::NonCanonicalInt)
        ); // 16 in four bytes
        let deep: Vec<u8> = std::iter::repeat_n(0x81u8, MAX_DEPTH + 1)
            .chain([0x00])
            .collect();
        assert_eq!(decode(&deep), Err(DecodeError::TooDeep));
        let ok: Vec<u8> = std::iter::repeat_n(0x81u8, MAX_DEPTH)
            .chain([0x00])
            .collect();
        assert!(decode(&ok).is_ok());
    }
}
