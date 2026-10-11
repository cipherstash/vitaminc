#![allow(dead_code)]

use std::any::Any;
use std::borrow::Cow;

use chrono::{DateTime, NaiveDate, Utc};
use vitaminc_aead::{Cipher, Context, Encrypt, IntoAad, MapCipher, SeqCipher, Unspecified};
use vitaminc_aead_value::transport::{decode_value, encode_value, Reader};
use vitaminc_aead_value::Value;
use vitaminc_protected::{Controlled, Protected};

/// What a cipher was asked to do, call for call. Two `Encrypt` impls that
/// produce equal `Rec`s produce the same ciphertext under any real cipher,
/// up to the nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rec {
    Leaf { aad: Vec<u8>, plaintext: Vec<u8> },
    None { aad: Vec<u8> },
    Seq { aad: Vec<u8>, size_hint: Option<usize>, items: Vec<Rec> },
    Map { aad: Vec<u8>, entries: Vec<(String, Rec)> },
    /// The passthrough payload, transport-encoded.
    Passthrough(Vec<u8>),
}

#[derive(Clone, Copy)]
pub struct Recorder;

fn aad_bytes<'a>(aad: impl IntoAad<'a>) -> Vec<u8> {
    aad.into_aad().as_bytes().to_vec()
}

fn record_passthrough(value: Box<dyn Any + Send + 'static>) -> Result<Rec, Unspecified> {
    let value = value.downcast::<Value>().map_err(|_| Unspecified)?;
    let mut out = Vec::new();
    encode_value(*value, &mut out).map_err(|_| Unspecified)?;
    Ok(Rec::Passthrough(out))
}

impl Cipher for Recorder {
    type Ok = Rec;
    type Error = Unspecified;
    type Passthrough = Box<dyn Any + Send + 'static>;
    type SeqCipher = RecSeq;
    type MapCipher = RecMap;

    fn encrypt_bytes_vec<'a, A: IntoAad<'a>>(self, data: Protected<Vec<u8>>, aad: A) -> Result<Rec, Unspecified> {
        Ok(Rec::Leaf {
            aad: aad_bytes(aad),
            plaintext: data.risky_ref().to_vec(),
        })
    }

    fn encrypt_seq<'a, A: IntoAad<'a>>(self, size_hint: Option<usize>, aad: A) -> RecSeq {
        RecSeq {
            aad: aad_bytes(aad),
            size_hint,
            items: Vec::new(),
        }
    }

    fn encrypt_map<'a, A: IntoAad<'a>>(self, aad: A) -> RecMap {
        RecMap {
            aad: aad_bytes(aad),
            pending: None,
            entries: Vec::new(),
        }
    }

    fn encrypt_none<'a, A: IntoAad<'a>>(self, aad: A) -> Result<Rec, Unspecified> {
        Ok(Rec::None { aad: aad_bytes(aad) })
    }

    fn passthrough(self, value: Self::Passthrough) -> Result<Rec, Unspecified> {
        record_passthrough(value)
    }

    fn passthrough_boxed(self, value: Box<dyn Any + Send + 'static>) -> Result<Rec, Unspecified> {
        record_passthrough(value)
    }
}

pub struct RecSeq {
    aad: Vec<u8>,
    size_hint: Option<usize>,
    items: Vec<Rec>,
}

impl SeqCipher for RecSeq {
    type Ok = Rec;
    type Error = Unspecified;
    type Passthrough = Box<dyn Any + Send + 'static>;

    fn encrypt_next<T: Encrypt>(mut self, data: T) -> Result<Self, Unspecified> {
        let item = data.encrypt_with_aad(Recorder, Context::from_encoded(self.aad.clone()))?;
        self.items.push(item);
        Ok(self)
    }

    fn passthrough_next(mut self, value: Self::Passthrough) -> Result<Self, Unspecified> {
        self.items.push(record_passthrough(value)?);
        Ok(self)
    }

    fn end(self) -> Result<Rec, Unspecified> {
        Ok(Rec::Seq {
            aad: self.aad,
            size_hint: self.size_hint,
            items: self.items,
        })
    }
}

pub struct RecMap {
    aad: Vec<u8>,
    pending: Option<String>,
    entries: Vec<(String, Rec)>,
}

impl MapCipher for RecMap {
    type Ok = Rec;
    type Error = Unspecified;
    type Passthrough = Box<dyn Any + Send + 'static>;

    fn encrypt_key<K: Into<Cow<'static, str>>>(mut self, key: K) -> Result<Self, Unspecified> {
        self.pending = Some(key.into().into_owned());
        Ok(self)
    }

    fn encrypt_value<T: Encrypt>(mut self, value: T) -> Result<Self, Unspecified> {
        let key = self.pending.take().ok_or(Unspecified)?;
        let rec = value.encrypt_with_aad(Recorder, Context::from_encoded(self.aad.clone()))?;
        self.entries.push((key, rec));
        Ok(self)
    }

    fn passthrough_entry<K: Into<Cow<'static, str>>>(mut self, key: K, value: Self::Passthrough) -> Result<Self, Unspecified> {
        self.entries.push((key.into().into_owned(), record_passthrough(value)?));
        Ok(self)
    }

    fn passthrough_entry_boxed<K: Into<Cow<'static, str>>>(
        self,
        key: K,
        value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self, Unspecified> {
        self.passthrough_entry(key, value)
    }

    fn end(self) -> Result<Rec, Unspecified> {
        Ok(Rec::Map {
            aad: self.aad,
            entries: self.entries,
        })
    }
}

pub struct Vector {
    pub name: String,
    pub bytes: Vec<u8>,
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn vectors(section: &str) -> Vec<Vector> {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../../testdata/value-conformance.json")).expect("corpus");
    corpus[section]
        .as_array()
        .expect("section")
        .iter()
        .map(|v| Vector {
            name: v["name"].as_str().expect("name").to_owned(),
            bytes: hex(v["transport"].as_str().expect("transport")),
        })
        .collect()
}

/// Every valid corpus vector, plus a nested sample that covers containers
/// and passthrough.
pub fn valid() -> Vec<Vector> {
    let mut all = vectors("vectors");
    all.push(Vector {
        name: "nested-sample".into(),
        bytes: encode(sample()),
    });
    all
}

pub fn malformed() -> Vec<Vector> {
    vectors("malformed")
}

pub fn decode(bytes: &[u8]) -> Value {
    decode_value(&mut Reader::new(bytes)).expect("decodes")
}

pub fn encode(value: Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(value, &mut out).expect("encodes");
    out
}

pub fn ts() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 123_456_789).expect("valid")
}

pub fn sample() -> Value {
    Value::Object(vec![
        ("name".into(), Value::String("Ada".into())),
        ("age".into(), Value::UInt32(34)),
        (
            "scores".into(),
            Value::Array(vec![Value::Int8(-1), Value::Float64(2.5), Value::Null]),
        ),
        (
            "joined".into(),
            Value::Date(NaiveDate::from_ymd_opt(2024, 2, 29).expect("valid")),
        ),
        ("note".into(), Value::Passthrough(Box::new(Value::String("public".into())))),
        ("blob".into(), Value::Bytes(Protected::new(vec![1, 2, 3]))),
        ("seen".into(), Value::Timestamp(ts())),
        ("active".into(), Value::Bool(true)),
    ])
}
