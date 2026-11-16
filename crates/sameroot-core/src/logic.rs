//! Sameroot Logic 1: the language of a contract's `access` and `validity` programs
//! (design 0003 §5.2).
//!
//! A program is a canonical CBOR value. A map with exactly one key is an operator
//! call, `{ "<op>": args }`, where `args` is an array of argument expressions or a
//! single expression. An array is a list literal whose elements are expressions.
//! Booleans, unsigned integers, byte strings and text strings (as UTF-8 bytes) are
//! literals. Anything else is an error.
//!
//! The semantics are strict and fixed for every implementation: no coercion, no
//! truthiness, no arithmetic, short-circuiting `and`, `or` and `if`, and every error
//! (an unknown operator, a missing input, a type mismatch, an index out of range,
//! too many steps) makes [`run`] return `false`.

use std::collections::BTreeMap;

use crate::cbor::{self, Map, Value};

/// Largest program, in canonical CBOR bytes.
pub const MAX_PROGRAM_BYTES: usize = 16 * 1024;
/// Most operators evaluated in one run.
pub const MAX_STEPS: usize = 10_000;

/// A value during evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V {
    /// `true` or `false`.
    Bool(bool),
    /// An unsigned 64-bit integer.
    Uint(u64),
    /// Bytes (text literals and inputs are bytes).
    Bytes(Vec<u8>),
    /// A list.
    List(Vec<V>),
}

/// Why an evaluation failed. Every error denies.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvalError {
    /// Not a literal, list or operator call.
    #[error("malformed expression")]
    Malformed,
    /// An operator Logic 1 doesn't have.
    #[error("unknown operator {0}")]
    UnknownOp(String),
    /// The wrong number of arguments.
    #[error("{0}: wrong number of arguments")]
    Arity(&'static str),
    /// An argument of the wrong type.
    #[error("{0}: type mismatch")]
    Type(&'static str),
    /// An input the program reads is absent and has no default.
    #[error("missing input {0}")]
    MissingInput(String),
    /// `at` past the end of a list.
    #[error("index out of range")]
    Index,
    /// More than [`MAX_STEPS`] operators.
    #[error("step limit exceeded")]
    Steps,
    /// The program's result isn't a boolean.
    #[error("result is not a boolean")]
    NotBool,
}

/// The inputs a program can read, by name.
pub type Inputs = BTreeMap<&'static str, V>;

/// Runs `program` on `inputs`: true only if it evaluates to `true` without error.
pub fn run(program: &Value, inputs: &Inputs) -> bool {
    matches!(eval_program(program, inputs), Ok(true))
}

/// Evaluates `program`, reporting why it failed.
pub fn eval_program(program: &Value, inputs: &Inputs) -> Result<bool, EvalError> {
    let mut steps = 0;
    match eval(program, inputs, &mut steps)? {
        V::Bool(b) => Ok(b),
        _ => Err(EvalError::NotBool),
    }
}

/// Checks that `program` is a well-formed Logic 1 program of acceptable size: only
/// known operators with the right number of arguments, only literal types the
/// language has. (It doesn't check types, which depend on inputs.)
pub fn check_program(program: &Value) -> Result<(), EvalError> {
    if cbor::encode(program).len() > MAX_PROGRAM_BYTES {
        return Err(EvalError::Malformed);
    }
    check(program)
}

fn check(e: &Value) -> Result<(), EvalError> {
    match e {
        Value::Bool(_) | Value::Uint(_) | Value::Bytes(_) | Value::Text(_) => Ok(()),
        Value::Array(items) => items.iter().try_for_each(check),
        Value::Map(m) => {
            let (op, args) = call(m)?;
            if !OPS.contains(&op) {
                return Err(EvalError::UnknownOp(op.to_owned()));
            }
            // The arities evaluation checks, checked once at creation, so a malformed
            // program is refused in the genesis instead of denying everything later.
            let n = args_of(args).len();
            let ok = match op {
                "var" => n == 1 || n == 2,
                "!" | "len" | "hex" => n == 1,
                "and" | "or" | "cat" => n >= 1,
                "if" => n >= 3 && n % 2 == 1,
                _ => n == 2,
            };
            if !ok {
                return Err(EvalError::Malformed);
            }
            match args {
                Value::Array(items) => items.iter().try_for_each(check),
                single => check(single),
            }
        }
        Value::Nint(_) | Value::Null => Err(EvalError::Malformed),
    }
}

const OPS: &[&str] = &[
    "var",
    "==",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "and",
    "or",
    "!",
    "if",
    "in",
    "cat",
    "startsWith",
    "at",
    "len",
    "hex",
];

fn call(m: &Map) -> Result<(&str, &Value), EvalError> {
    let mut it = m.iter();
    match (it.next(), it.next()) {
        (Some((op, args)), None) => Ok((op, args)),
        _ => Err(EvalError::Malformed),
    }
}

fn args_of(args: &Value) -> &[Value] {
    match args {
        Value::Array(items) => items,
        single => std::slice::from_ref(single),
    }
}

fn eval(e: &Value, inputs: &Inputs, steps: &mut usize) -> Result<V, EvalError> {
    match e {
        Value::Bool(b) => Ok(V::Bool(*b)),
        Value::Uint(n) => Ok(V::Uint(*n)),
        Value::Bytes(b) => Ok(V::Bytes(b.clone())),
        Value::Text(t) => Ok(V::Bytes(t.as_bytes().to_vec())),
        Value::Array(items) => Ok(V::List(
            items
                .iter()
                .map(|i| eval(i, inputs, steps))
                .collect::<Result<_, _>>()?,
        )),
        Value::Map(m) => {
            *steps += 1;
            if *steps > MAX_STEPS {
                return Err(EvalError::Steps);
            }
            let (op, args) = call(m)?;
            apply(op, args_of(args), inputs, steps)
        }
        Value::Nint(_) | Value::Null => Err(EvalError::Malformed),
    }
}

fn arity(name: &'static str, args: &[Value], n: usize) -> Result<(), EvalError> {
    if args.len() == n {
        Ok(())
    } else {
        Err(EvalError::Arity(name))
    }
}

fn boolean(name: &'static str, v: V) -> Result<bool, EvalError> {
    match v {
        V::Bool(b) => Ok(b),
        _ => Err(EvalError::Type(name)),
    }
}

/// Equality of two values of one type; lists compare element-wise, and a type
/// mismatch anywhere is an error.
fn equal(name: &'static str, a: &V, b: &V) -> Result<bool, EvalError> {
    match (a, b) {
        (V::Bool(x), V::Bool(y)) => Ok(x == y),
        (V::Uint(x), V::Uint(y)) => Ok(x == y),
        (V::Bytes(x), V::Bytes(y)) => Ok(x == y),
        (V::List(x), V::List(y)) => {
            if x.len() != y.len() {
                return Ok(false);
            }
            for (i, j) in x.iter().zip(y) {
                if !equal(name, i, j)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Err(EvalError::Type(name)),
    }
}

fn apply(op: &str, args: &[Value], inputs: &Inputs, steps: &mut usize) -> Result<V, EvalError> {
    let mut ev = |e: &Value| eval(e, inputs, steps);
    match op {
        "var" => {
            let name = match args.first() {
                Some(Value::Text(t)) => t.as_str(),
                _ => return Err(EvalError::Type("var")),
            };
            match (inputs.get(name), args.len()) {
                (Some(v), 1 | 2) => Ok(v.clone()),
                (None, 2) => ev(&args[1]),
                (None, 1) => Err(EvalError::MissingInput(name.to_owned())),
                _ => Err(EvalError::Arity("var")),
            }
        }
        "==" | "!=" => {
            arity("==", args, 2)?;
            let (a, b) = (ev(&args[0])?, ev(&args[1])?);
            let eq = equal("==", &a, &b)?;
            Ok(V::Bool(if op == "==" { eq } else { !eq }))
        }
        "<" | "<=" | ">" | ">=" => {
            arity("<", args, 2)?;
            let ord = match (ev(&args[0])?, ev(&args[1])?) {
                (V::Uint(a), V::Uint(b)) => a.cmp(&b),
                (V::Bytes(a), V::Bytes(b)) => a.cmp(&b),
                _ => return Err(EvalError::Type("<")),
            };
            Ok(V::Bool(match op {
                "<" => ord.is_lt(),
                "<=" => ord.is_le(),
                ">" => ord.is_gt(),
                _ => ord.is_ge(),
            }))
        }
        "and" | "or" => {
            if args.is_empty() {
                return Err(EvalError::Arity("and"));
            }
            let stop_on = op == "or";
            for a in args {
                if boolean("and", ev(a)?)? == stop_on {
                    return Ok(V::Bool(stop_on));
                }
            }
            Ok(V::Bool(!stop_on))
        }
        "!" => {
            arity("!", args, 1)?;
            Ok(V::Bool(!boolean("!", ev(&args[0])?)?))
        }
        "if" => {
            if args.len() < 3 || args.len().is_multiple_of(2) {
                return Err(EvalError::Arity("if"));
            }
            let mut i = 0;
            while i + 1 < args.len() {
                if boolean("if", ev(&args[i])?)? {
                    return ev(&args[i + 1]);
                }
                i += 2;
            }
            ev(&args[args.len() - 1])
        }
        "in" => {
            arity("in", args, 2)?;
            let x = ev(&args[0])?;
            let V::List(items) = ev(&args[1])? else {
                return Err(EvalError::Type("in"));
            };
            for i in &items {
                if equal("in", &x, i)? {
                    return Ok(V::Bool(true));
                }
            }
            Ok(V::Bool(false))
        }
        "cat" => {
            if args.is_empty() {
                return Err(EvalError::Arity("cat"));
            }
            let mut out = Vec::new();
            for a in args {
                match ev(a)? {
                    V::Bytes(b) => out.extend_from_slice(&b),
                    _ => return Err(EvalError::Type("cat")),
                }
            }
            Ok(V::Bytes(out))
        }
        "startsWith" => {
            arity("startsWith", args, 2)?;
            match (ev(&args[0])?, ev(&args[1])?) {
                (V::Bytes(a), V::Bytes(p)) => Ok(V::Bool(a.starts_with(&p))),
                (V::List(a), V::List(p)) => {
                    if p.len() > a.len() {
                        return Ok(V::Bool(false));
                    }
                    for (x, y) in a.iter().zip(&p) {
                        if !equal("startsWith", x, y)? {
                            return Ok(V::Bool(false));
                        }
                    }
                    Ok(V::Bool(true))
                }
                _ => Err(EvalError::Type("startsWith")),
            }
        }
        "at" => {
            arity("at", args, 2)?;
            match (ev(&args[0])?, ev(&args[1])?) {
                (V::List(items), V::Uint(i)) => usize::try_from(i)
                    .ok()
                    .and_then(|i| items.into_iter().nth(i))
                    .ok_or(EvalError::Index),
                _ => Err(EvalError::Type("at")),
            }
        }
        "len" => {
            arity("len", args, 1)?;
            match ev(&args[0])? {
                V::List(items) => Ok(V::Uint(items.len() as u64)),
                V::Bytes(b) => Ok(V::Uint(b.len() as u64)),
                _ => Err(EvalError::Type("len")),
            }
        }
        "hex" => {
            arity("hex", args, 1)?;
            match ev(&args[0])? {
                V::Bytes(b) => Ok(V::Bytes(crate::hash::hex(&b).into_bytes())),
                _ => Err(EvalError::Type("hex")),
            }
        }
        other => Err(EvalError::UnknownOp(other.to_owned())),
    }
}

/// The canonical preset programs (design 0003 §5.2).
pub mod presets {
    use super::*;
    use crate::identity::PublicKey;

    fn op(name: &str, args: Vec<Value>) -> Value {
        let mut m = Map::new();
        m.insert(name, Value::Array(args));
        Value::Map(m)
    }

    fn var(name: &str) -> Value {
        op("var", vec![Value::Text(name.into())])
    }

    fn keys(list: &[PublicKey]) -> Value {
        Value::Array(list.iter().map(|k| Value::Bytes(k.0.to_vec())).collect())
    }

    /// Accepts everything (the default `validity`).
    pub fn always() -> Value {
        Value::Bool(true)
    }

    /// `own-subspace`: a key writes its own subspace. Open write.
    pub fn own_subspace() -> Value {
        op(
            "and",
            vec![
                op("!", vec![var("shared")]),
                op("==", vec![var("subspaceOwner"), var("chainRoot")]),
            ],
        )
    }

    /// `owner-only`: only the database owner (or its delegates) writes.
    pub fn owner_only() -> Value {
        op("==", vec![var("chainRoot"), var("owner")])
    }

    /// `allowlist`: the listed keys (or their delegates) write.
    pub fn allowlist(writers: &[PublicKey]) -> Value {
        op("in", vec![var("chainRoot"), keys(writers)])
    }

    /// `shared-allowlist`: the listed keys write the shared subspace.
    pub fn shared_allowlist(writers: &[PublicKey]) -> Value {
        op("and", vec![var("shared"), allowlist(writers)])
    }

    /// `public-shared`: anyone writes the shared subspace.
    pub fn public_shared() -> Value {
        var("shared")
    }

    /// `put-only`: `access` restricted to puts.
    pub fn put_only(access: Value) -> Value {
        op(
            "and",
            vec![access, op("==", vec![var("op"), Value::Text("put".into())])],
        )
    }

    /// `namespace-per-writer`: in the shared subspace, a key writes under
    /// `agents/<its hex>/`.
    pub fn namespace_per_writer() -> Value {
        op(
            "and",
            vec![
                var("shared"),
                op(
                    "==",
                    vec![
                        op("at", vec![var("path"), Value::Uint(0)]),
                        Value::Text("agents".into()),
                    ],
                ),
                op(
                    "==",
                    vec![
                        op("at", vec![var("path"), Value::Uint(1)]),
                        op("hex", vec![var("chainRoot")]),
                    ],
                ),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::presets::*;
    use super::*;
    use crate::identity::PublicKey;

    fn parse(json: &str) -> Value {
        fn conv(j: &serde_json::Value) -> Value {
            match j {
                serde_json::Value::Bool(b) => Value::Bool(*b),
                serde_json::Value::Number(n) => Value::Uint(n.as_u64().expect("uint")),
                serde_json::Value::String(s) => Value::Text(s.clone()),
                serde_json::Value::Array(a) => Value::Array(a.iter().map(conv).collect()),
                serde_json::Value::Object(o) => {
                    let mut m = Map::new();
                    for (k, v) in o {
                        m.insert(k, conv(v));
                    }
                    Value::Map(m)
                }
                serde_json::Value::Null => Value::Null,
            }
        }
        conv(&serde_json::from_str(json).unwrap())
    }

    fn inputs() -> Inputs {
        let mut i = Inputs::new();
        i.insert("op", V::Bytes(b"put".to_vec()));
        i.insert("shared", V::Bool(false));
        i.insert("ts", V::Uint(10));
        i.insert(
            "path",
            V::List(vec![V::Bytes(b"notes".to_vec()), V::Bytes(b"a".to_vec())]),
        );
        i.insert("signer", V::Bytes(vec![7; 32]));
        i.insert("chainRoot", V::Bytes(vec![7; 32]));
        i.insert("subspaceOwner", V::Bytes(vec![7; 32]));
        i.insert("owner", V::Bytes(vec![9; 32]));
        i
    }

    fn eval_json(json: &str) -> Result<bool, EvalError> {
        eval_program(&parse(json), &inputs())
    }

    #[test]
    fn arities_are_checked_at_creation() {
        for bad in [
            r#"{"==": [1]}"#,
            r#"{"!": [true, false]}"#,
            r#"{"and": []}"#,
            r#"{"if": [true, 1]}"#,
            r#"{"var": ["a", 1, 2]}"#,
            r#"{"len": [[1], [2]]}"#,
        ] {
            assert_eq!(
                check_program(&parse(bad)),
                Err(EvalError::Malformed),
                "{bad}"
            );
        }
        for good in [
            r#"{"==": [1, 1]}"#,
            r#"{"!": true}"#,
            r#"{"if": [true, 1, 2]}"#,
            r#"{"var": "ts"}"#,
            r#"{"and": [true]}"#,
        ] {
            assert_eq!(check_program(&parse(good)), Ok(()), "{good}");
        }
        for preset in [
            always(),
            own_subspace(),
            owner_only(),
            public_shared(),
            namespace_per_writer(),
        ] {
            assert_eq!(check_program(&preset), Ok(()));
        }
    }

    #[test]
    fn operators() {
        let ok = |j: &str| assert_eq!(eval_json(j), Ok(true), "{j}");
        ok(r#"{"==":[{"var":"op"},"put"]}"#);
        ok(r#"{"!=":[{"var":"ts"},11]}"#);
        ok(r#"{"<":[{"var":"ts"},11]}"#);
        ok(r#"{">=":["b","a"]}"#);
        ok(r#"{"and":[true,{"!":false}]}"#);
        ok(r#"{"or":[false,true]}"#);
        ok(r#"{"if":[false,false,true,true,false]}"#);
        ok(r#"{"in":["a",["b","a"]]}"#);
        ok(r#"{"==":[{"cat":["ab","c"]},"abc"]}"#);
        ok(r#"{"startsWith":["abc","ab"]}"#);
        ok(r#"{"startsWith":[{"var":"path"},["notes"]]}"#);
        ok(r#"{"==":[{"at":[{"var":"path"},1]},"a"]}"#);
        ok(r#"{"==":[{"len":{"var":"path"}},2]}"#);
        ok(r#"{"==":[{"hex":"\u0001"},"01"]}"#);
        ok(r#"{"==":[{"var":["exp",0]},0]}"#);
        ok(r#"{"==":[["a",1],["a",1]]}"#);
    }

    #[test]
    fn errors_deny() {
        let err = |j: &str| assert!(eval_json(j).is_err(), "{j} should error");
        err(r#"{"==":[1,"1"]}"#); // no coercion
        err(r#"{"and":[1]}"#); // no truthiness
        err(r#"{"var":"exp"}"#); // missing input
        err(r#"{"at":[{"var":"path"},5]}"#); // out of range
        err(r#"{"plus":[1,2]}"#); // unknown operator
        err(r#""put""#); // not a boolean
        err(r#"{"==":[1]}"#); // arity
        err(r#"{"a":1,"b":2}"#); // two keys
        err(r#"{"in":["a","abc"]}"#); // `in` needs a list
        assert!(!run(&parse(r#"{"var":"exp"}"#), &inputs()));
    }

    #[test]
    fn short_circuit_skips_errors() {
        assert_eq!(eval_json(r#"{"or":[true,{"var":"missing"}]}"#), Ok(true));
        assert_eq!(eval_json(r#"{"and":[false,{"var":"missing"}]}"#), Ok(false));
        assert_eq!(
            eval_json(r#"{"if":[true,true,{"var":"missing"}]}"#),
            Ok(true)
        );
    }

    #[test]
    fn step_limit() {
        // A list literal of 10,001 operator calls exceeds the step limit.
        let call = parse(r#"{"!":false}"#);
        let prog = {
            let mut m = Map::new();
            m.insert(
                "in",
                Value::Array(vec![
                    Value::Bool(true),
                    Value::Array(vec![call; MAX_STEPS + 1]),
                ]),
            );
            Value::Map(m)
        };
        assert_eq!(eval_program(&prog, &inputs()), Err(EvalError::Steps));
    }

    #[test]
    fn checks_programs() {
        assert!(check_program(&own_subspace()).is_ok());
        assert!(check_program(&parse(r#"{"plus":[1,2]}"#)).is_err());
        assert!(check_program(&Value::Null).is_err());
        assert!(check_program(&Value::Bytes(vec![0; MAX_PROGRAM_BYTES + 1])).is_err());
    }

    #[test]
    fn presets_decide() {
        let i = inputs();
        assert!(run(&own_subspace(), &i));
        assert!(!run(&owner_only(), &i));
        assert!(run(&allowlist(&[PublicKey([7; 32])]), &i));
        assert!(!run(&allowlist(&[PublicKey([8; 32])]), &i));
        assert!(!run(&public_shared(), &i));
        assert!(run(&put_only(own_subspace()), &i));
        let mut shared = i.clone();
        shared.insert("shared", V::Bool(true));
        shared.remove("subspaceOwner");
        assert!(
            !run(&own_subspace(), &shared),
            "short-circuits before the absent owner"
        );
        assert!(run(&public_shared(), &shared));
        assert!(!run(&namespace_per_writer(), &shared));
        shared.insert(
            "path",
            V::List(vec![
                V::Bytes(b"agents".to_vec()),
                V::Bytes(crate::hash::hex(&[7; 32]).into_bytes()),
            ]),
        );
        assert!(run(&namespace_per_writer(), &shared));
        assert!(run(&shared_allowlist(&[PublicKey([7; 32])]), &shared));
    }
}
