//! The local RPC between `samerootd` and its clients (`docs/design/0001-architecture.md` §14).
//!
//! Length-prefixed (u32, big-endian) frames of the format-1 CBOR profile over an
//! owner-only Unix socket. A request is a map with `op`; a response is a map with
//! `ok: true` and results, or `ok: false` and `error`. This interface is local and
//! may change in any release; it isn't part of the format 1 specification.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use sameroot_core::cbor::{self, Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest RPC frame.
pub const MAX_FRAME: usize = 32 << 20;

/// Builds a request map.
pub fn request(op: &str) -> Map {
    let mut m = Map::new();
    m.insert("op", Value::Text(op.to_owned()));
    m
}

/// A successful response.
pub fn ok() -> Map {
    let mut m = Map::new();
    m.insert("ok", Value::Bool(true));
    m
}

/// An error response.
pub fn err(message: impl Into<String>) -> Map {
    let mut m = Map::new();
    m.insert("ok", Value::Bool(false))
        .insert("error", Value::Text(message.into()));
    m
}

fn frame(v: &Map) -> Vec<u8> {
    let body = cbor::encode(&Value::Map(v.clone()));
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn unframe(body: &[u8]) -> std::io::Result<Map> {
    match cbor::decode(body) {
        Ok(Value::Map(m)) => Ok(m),
        Ok(_) => Err(std::io::Error::other("frame is not a map")),
        Err(e) => Err(std::io::Error::other(format!("frame: {e}"))),
    }
}

/// Client side: one request, one response, blocking.
pub fn call(socket: &Path, req: &Map) -> std::io::Result<Map> {
    let mut s = UnixStream::connect(socket)?;
    s.write_all(&frame(req))?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::other("response too large"));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)?;
    unframe(&body)
}

/// Server side: reads one request (None at end of stream).
pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Map>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::other("request too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    unframe(&body).map(Some)
}

/// Server side: writes one response. One the client would refuse as too large is
/// replaced by an error response, so the caller learns why.
pub async fn write_response<W: AsyncWrite + Unpin>(w: &mut W, resp: &Map) -> std::io::Result<()> {
    let mut bytes = frame(resp);
    if bytes.len() - 4 > MAX_FRAME {
        bytes = frame(&err(format!(
            "response of {} bytes is over the {MAX_FRAME}-byte limit",
            bytes.len() - 4
        )));
    }
    w.write_all(&bytes).await?;
    w.flush().await
}

/// Typed field access for requests and responses.
pub trait Fields {
    /// A text field.
    fn text(&self, k: &str) -> Option<&str>;
    /// A byte-string field.
    fn bytes(&self, k: &str) -> Option<&[u8]>;
    /// An unsigned integer field.
    fn uint(&self, k: &str) -> Option<u64>;
    /// A boolean field.
    fn flag(&self, k: &str) -> Option<bool>;
    /// An array field.
    fn list(&self, k: &str) -> Option<&[Value]>;
}

impl Fields for Map {
    fn text(&self, k: &str) -> Option<&str> {
        match self.get(k)? {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }
    fn bytes(&self, k: &str) -> Option<&[u8]> {
        match self.get(k)? {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
    fn uint(&self, k: &str) -> Option<u64> {
        match self.get(k)? {
            Value::Uint(n) => Some(*n),
            _ => None,
        }
    }
    fn flag(&self, k: &str) -> Option<bool> {
        match self.get(k)? {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    fn list(&self, k: &str) -> Option<&[Value]> {
        match self.get(k)? {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
}

/// An invite: a database and one peer to reach it through.
///
/// `sameroot:join?v=1&db=<hex>&id=<endpoint id>&relay=<url>&addr=<ip:port>…`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    /// Database id (hex).
    pub db: String,
    /// The peer's iroh endpoint id.
    pub endpoint: String,
    /// The peer's home relay, if any.
    pub relay: Option<String>,
    /// The peer's direct addresses.
    pub addrs: Vec<String>,
}

fn pct_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b':'
            | b'['
            | b']' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn pct_decode(s: &str) -> Option<String> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(s.get(i + 1..i + 3)?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl Invite {
    /// Renders the invite string.
    pub fn render(&self) -> String {
        let mut s = format!(
            "sameroot:join?v=1&db={}&id={}",
            self.db,
            pct_encode(&self.endpoint)
        );
        if let Some(r) = &self.relay {
            s.push_str(&format!("&relay={}", pct_encode(r)));
        }
        for a in &self.addrs {
            s.push_str(&format!("&addr={}", pct_encode(a)));
        }
        s
    }

    /// Parses an invite string; unknown parameters are ignored, an unknown `v` is refused.
    pub fn parse(s: &str) -> Result<Invite, String> {
        let query = s
            .strip_prefix("sameroot:join?")
            .ok_or("not a sameroot invite")?;
        let (mut v, mut db, mut endpoint, mut relay, mut addrs) =
            (None, None, None, None, Vec::new());
        for pair in query.split('&') {
            let (k, val) = pair.split_once('=').ok_or("malformed invite")?;
            let val = pct_decode(val).ok_or("malformed invite")?;
            match k {
                "v" => v = Some(val),
                "db" => db = Some(val),
                "id" => endpoint = Some(val),
                "relay" => relay = Some(val),
                "addr" => addrs.push(val),
                _ => {}
            }
        }
        if v.as_deref() != Some("1") {
            return Err("unsupported invite version".into());
        }
        Ok(Invite {
            db: db.ok_or("invite has no db")?,
            endpoint: endpoint.ok_or("invite has no id")?,
            relay,
            addrs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip() {
        let i = Invite {
            db: "ab".repeat(32),
            endpoint: "cd".repeat(32),
            relay: Some("https://relay.example.org./".into()),
            addrs: vec!["1.2.3.4:5678".into(), "[2001:db8::1]:9".into()],
        };
        assert_eq!(Invite::parse(&i.render()).unwrap(), i);
        assert!(Invite::parse("sameroot:join?v=2&db=x&id=y").is_err());
        assert!(Invite::parse("sameroot:join?v=1&id=y").is_err(), "no db");
        assert!(
            Invite::parse("sameroot:join?v=1&db=x").is_err(),
            "no endpoint"
        );
    }

    fn read(bytes: Vec<u8>) -> std::io::Result<Option<Map>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async { read_request(&mut bytes.as_slice()).await })
    }

    #[test]
    fn request_framing() {
        // A request round-trips.
        let mut r = request("status");
        r.insert("db", Value::Text("ab".into()));
        assert_eq!(read(frame(&r)).unwrap(), Some(r));
        // End of stream before a frame: no request.
        assert_eq!(read(Vec::new()).unwrap(), None);
        // A length over the limit is refused before anything is allocated.
        let mut big = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        big.extend([0; 8]);
        assert!(read(big).is_err());
        // A body shorter than its length.
        let mut cut = frame(&request("status"));
        cut.truncate(cut.len() - 1);
        assert!(read(cut).is_err());
        // A frame that isn't a map.
        let body = cbor::encode(&Value::Uint(7));
        let mut not_map = (body.len() as u32).to_be_bytes().to_vec();
        not_map.extend(body);
        assert!(read(not_map).is_err());
    }

    #[test]
    fn oversized_responses_become_errors() {
        let mut resp = ok();
        resp.insert("value", Value::Bytes(vec![0; MAX_FRAME + 1]));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut out = Vec::new();
        rt.block_on(write_response(&mut out, &resp)).unwrap();
        assert!(out.len() < 1024, "an error, not the value");
        let back = unframe(&out[4..]).unwrap();
        assert_eq!(back.flag("ok"), Some(false));
        assert!(back.text("error").unwrap().contains("over the"));
    }
}
