//! Strict field access for the signed objects of format 1.
//!
//! Core objects reject unknown fields: a new field is a new format version. (The
//! tolerant-reader rule applies to platform conventions, not to these objects.)

use crate::cbor::{Map, Value};
use crate::hash::Digest;
use crate::identity::{PublicKey, Signature};

/// Why a decoded CBOR value is not a valid object of format 1.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    /// Not in the CBOR profile.
    #[error("CBOR: {0}")]
    Cbor(#[from] crate::cbor::DecodeError),
    /// The top-level value has the wrong type.
    #[error("{0}: expected a map")]
    NotAMap(&'static str),
    /// A required field is missing.
    #[error("{object}: missing field {field}")]
    Missing {
        /// Object type.
        object: &'static str,
        /// Field name.
        field: &'static str,
    },
    /// A field has the wrong type or size.
    #[error("{object}: field {field} has the wrong type or size")]
    WrongType {
        /// Object type.
        object: &'static str,
        /// Field name.
        field: &'static str,
    },
    /// A field this version doesn't define.
    #[error("{object}: unknown field {field}")]
    UnknownField {
        /// Object type.
        object: &'static str,
        /// Field name.
        field: String,
    },
    /// An unsupported format version.
    #[error("{object}: unsupported version {version}")]
    Version {
        /// Object type.
        object: &'static str,
        /// The version found.
        version: u64,
    },
    /// A value outside its allowed range.
    #[error("{0}")]
    Invalid(String),
}

/// A typed view over a decoded map, tracking the object type for errors.
pub(crate) struct Fields<'a> {
    pub object: &'static str,
    map: &'a Map,
}

impl<'a> Fields<'a> {
    pub fn new(
        object: &'static str,
        value: &'a Value,
        allowed: &[&str],
    ) -> Result<Self, FormatError> {
        let Value::Map(map) = value else {
            return Err(FormatError::NotAMap(object));
        };
        for (key, _) in map.iter() {
            if !allowed.contains(&key) {
                return Err(FormatError::UnknownField {
                    object,
                    field: key.to_owned(),
                });
            }
        }
        Ok(Fields { object, map })
    }

    fn wrong(&self, field: &'static str) -> FormatError {
        FormatError::WrongType {
            object: self.object,
            field,
        }
    }

    fn req(&self, field: &'static str) -> Result<&'a Value, FormatError> {
        self.map.get(field).ok_or(FormatError::Missing {
            object: self.object,
            field,
        })
    }

    pub fn version(&self, supported: u64) -> Result<(), FormatError> {
        let v = self.uint("v")?;
        if v != supported {
            return Err(FormatError::Version {
                object: self.object,
                version: v,
            });
        }
        Ok(())
    }

    pub fn uint(&self, field: &'static str) -> Result<u64, FormatError> {
        match self.req(field)? {
            Value::Uint(n) => Ok(*n),
            _ => Err(self.wrong(field)),
        }
    }

    pub fn opt_uint(&self, field: &'static str) -> Result<Option<u64>, FormatError> {
        self.map.get(field).map(|_| self.uint(field)).transpose()
    }

    pub fn bytes(&self, field: &'static str) -> Result<&'a [u8], FormatError> {
        match self.req(field)? {
            Value::Bytes(b) => Ok(b),
            _ => Err(self.wrong(field)),
        }
    }

    pub fn text(&self, field: &'static str) -> Result<&'a str, FormatError> {
        match self.req(field)? {
            Value::Text(s) => Ok(s),
            _ => Err(self.wrong(field)),
        }
    }

    pub fn opt_text(&self, field: &'static str) -> Result<Option<&'a str>, FormatError> {
        self.map.get(field).map(|_| self.text(field)).transpose()
    }

    pub fn array(&self, field: &'static str) -> Result<&'a [Value], FormatError> {
        match self.req(field)? {
            Value::Array(a) => Ok(a),
            _ => Err(self.wrong(field)),
        }
    }

    pub fn value(&self, field: &'static str) -> Result<&'a Value, FormatError> {
        self.req(field)
    }

    pub fn digest(&self, field: &'static str) -> Result<Digest, FormatError> {
        let b = self.bytes(field)?;
        Ok(Digest(b.try_into().map_err(|_| self.wrong(field))?))
    }

    pub fn opt_digest(&self, field: &'static str) -> Result<Option<Digest>, FormatError> {
        self.map.get(field).map(|_| self.digest(field)).transpose()
    }

    pub fn key(&self, field: &'static str) -> Result<PublicKey, FormatError> {
        let b = self.bytes(field)?;
        Ok(PublicKey(b.try_into().map_err(|_| self.wrong(field))?))
    }

    pub fn opt_key(&self, field: &'static str) -> Result<Option<PublicKey>, FormatError> {
        self.map.get(field).map(|_| self.key(field)).transpose()
    }

    pub fn opt_value(&self, field: &'static str) -> Option<&'a Value> {
        self.map.get(field)
    }

    pub fn signature(&self, field: &'static str) -> Result<Signature, FormatError> {
        let b = self.bytes(field)?;
        Ok(Signature(b.try_into().map_err(|_| self.wrong(field))?))
    }
}

/// `Value::Bytes` of a digest.
pub(crate) fn digest_value(d: &Digest) -> Value {
    Value::Bytes(d.0.to_vec())
}

/// `Value::Bytes` of a public key.
pub(crate) fn key_value(k: &PublicKey) -> Value {
    Value::Bytes(k.0.to_vec())
}
