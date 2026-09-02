use std::{
    any::Any,
    borrow::Cow,
    collections::BTreeMap,
    convert::Infallible,
    future::{ready, IntoFuture, Ready},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use futures::executor::block_on;
use hmac::{Hmac, KeyInit, Mac};
use quickcheck_macros::quickcheck;
use sha2::Sha256;
use vitaminc_protected::{Controlled, Protected};

use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::{
    BlockVisitor, IntoPrfContext, MapAccess, MapPrf, Prf, PrfBuildError, PrfContext, PrfEncoding,
    PrfError, PrfKeyInit, PrfValue, PrfVisitor, PrfVisitorError, ReadyPrf, ResolvedPrf,
    ResolvedVisitor, SeqAccess, SeqPrf,
};
use zeroize::ZeroizeOnDrop;

type Boxed = Box<dyn Any + Send + 'static>;
type Node = ResolvedPrf<[u8; 32], Boxed>;
type Finish<T> = Box<dyn FnOnce(Node) -> Result<T, PrfError<Infallible>>>;

fn key_bytes() -> [u8; 32] {
    std::array::from_fn(|index| index as u8)
}

/// The same key material as [`key_bytes`], for backends that take a
/// runtime-length key.
fn key() -> Protected<Vec<u8>> {
    Protected::new(key_bytes().to_vec())
}

fn local() -> HmacSha256Prf {
    HmacSha256Prf::new(Protected::new(key_bytes()))
}

fn hex(bytes: &str) -> Vec<u8> {
    let digits = bytes.as_bytes();
    // Pair up the digits, ignoring a trailing odd one as `chunks_exact` would.
    (0..digits.len().saturating_sub(1))
        .step_by(2)
        .map(|i| {
            let pair = std::str::from_utf8(&digits[i..i + 2]).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

#[test]
fn hmac_sha256_known_answer_and_byte_container_equivalence() {
    let key = [0x0b; 32];
    let expected = hex("a192f4fccf3cbb90b845a1db9dfc42baa68ee612ff6d019a1168a1f74eb75230");
    let array = *b"Hi There";

    let from_array = array
        .prf(&HmacSha256Prf::new(Protected::new(key)))
        .into_result()
        .unwrap();
    let from_vec = array
        .to_vec()
        .prf(&HmacSha256Prf::new(Protected::new(key)))
        .into_result()
        .unwrap();

    assert_eq!(from_array.as_slice(), expected);
    assert_eq!(from_array, from_vec);
}

#[test]
fn hmac_sha256_normalizes_keys_larger_than_one_hash_block() {
    let key_bytes = vec![0xaa; 131];
    let input = b"long HMAC key".to_vec();
    let local = input
        .clone()
        .prf(&HmacSha256Prf::try_from_bytes(Protected::new(key_bytes.clone())).unwrap())
        .into_result()
        .unwrap();
    let reference = block_on(
        input
            .prf(&DeferredPrf::new(Protected::new(key_bytes)))
            .into_future(),
    )
    .unwrap();

    assert_eq!(local, reference);
}

#[derive(Clone, Copy)]
struct BloomVisitor {
    positions: usize,
    modulus: i16,
}

impl<P> PrfVisitor<[u8; 32], P> for BloomVisitor {
    type Value = Vec<i16>;

    fn visit_block(self, block: [u8; 32]) -> Result<Self::Value, PrfVisitorError> {
        Ok((0..block.len())
            .step_by(2)
            .take(self.positions)
            .map(|i| i16::from_le_bytes([block[i], block[i + 1]]).rem_euclid(self.modulus))
            .collect())
    }
}

#[test]
fn visitors_can_produce_equality_and_bloom_terms() {
    let equality: [u8; 32] = b"needle".as_slice().prf(&local()).into_result().unwrap();
    let positions: Vec<i16> = b"needle"
        .as_slice()
        .prf_visit(
            &local(),
            BloomVisitor {
                positions: 6,
                modulus: 2048,
            },
        )
        .into_result()
        .unwrap();

    assert_ne!(equality, [0; 32]);
    assert_eq!(positions.len(), 6);
    assert!(positions
        .iter()
        .all(|position| (0..2048).contains(position)));
}

#[test]
fn custom_leaf_encoding_domains_are_separated() {
    let derive = |encoding| {
        local()
            .prf_bytes_vec(
                Protected::new(vec![1, 2, 3]),
                encoding,
                PrfContext::empty(),
                BlockVisitor,
            )
            .into_result()
            .unwrap()
    };

    assert_ne!(
        derive(PrfEncoding::new("com.example/customer-id/v1")),
        derive(PrfEncoding::new("com.example/order-id/v1"))
    );
}

#[derive(Debug, PartialEq, Eq)]
struct DerivedRecord {
    email: [u8; 32],
    tags: Vec<[u8; 32]>,
    nickname_absent: bool,
    version: u32,
}

struct RecordVisitor;

struct BlocksVisitor;

impl<P> PrfVisitor<[u8; 32], P> for BlocksVisitor {
    type Value = Vec<[u8; 32]>;

    fn visit_seq(self, seq: SeqAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
        seq.map(|node| node.visit(BlockVisitor)).collect()
    }
}

struct IsAbsent;

impl<B, P> PrfVisitor<B, P> for IsAbsent {
    type Value = bool;

    fn visit_absent(self) -> Result<Self::Value, PrfVisitorError> {
        Ok(true)
    }
}

impl PrfVisitor<[u8; 32], Boxed> for RecordVisitor {
    type Value = DerivedRecord;

    fn visit_map(
        self,
        mut map: MapAccess<[u8; 32], Boxed>,
    ) -> Result<Self::Value, PrfVisitorError> {
        let (email_key, email) = map.next_entry().ok_or(PrfVisitorError::InvalidValue)?;
        let (tags_key, tags) = map.next_entry().ok_or(PrfVisitorError::InvalidValue)?;
        let (nickname_key, nickname) = map.next_entry().ok_or(PrfVisitorError::InvalidValue)?;
        let (version_key, version) = map.next_entry().ok_or(PrfVisitorError::InvalidValue)?;
        if email_key != "email"
            || tags_key != "tags"
            || nickname_key != "nickname"
            || version_key != "version"
            || map.next_entry().is_some()
        {
            return Err(PrfVisitorError::InvalidValue);
        }
        let version = match version {
            ResolvedPrf::Passthrough(value) => *value
                .downcast::<u32>()
                .map_err(|_| PrfVisitorError::InvalidValue)?,
            _ => return Err(PrfVisitorError::UnexpectedShape),
        };
        Ok(DerivedRecord {
            email: email.visit(BlockVisitor)?,
            tags: tags.visit(BlocksVisitor)?,
            nickname_absent: nickname.visit(IsAbsent)?,
            version,
        })
    }
}

struct MixedRecord {
    email: String,
    tags: Vec<String>,
    nickname: Option<String>,
    version: u32,
}

impl PrfValue for MixedRecord {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: &P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        let context = context.into_prf_context().into_owned();
        prf.prf_map(Some(4))
            .prf_entry("email", self.email, context.clone())
            .prf_entry("tags", self.tags, context.clone())
            .prf_entry("nickname", self.nickname, context)
            .passthrough_entry_boxed("version", Box::new(self.version))
            .end(visitor)
    }
}

fn mixed_record() -> MixedRecord {
    MixedRecord {
        email: "alice@example.com".into(),
        tags: vec!["admin".into(), "active".into()],
        nickname: None,
        version: 7,
    }
}

#[test]
fn handwritten_mixed_record_resolves_heterogeneous_children() {
    let output = mixed_record()
        .prf_visit_with_context(&local(), "tenant-42", RecordVisitor)
        .into_result()
        .unwrap();
    assert_eq!(output.tags.len(), 2);
    assert!(output.nickname_absent);
    assert_eq!(output.version, 7);
}

enum PendingNode {
    Leaf(Protected<Vec<u8>>, PrfEncoding, PrfContext<'static>),
    Sequence(Vec<PendingNode>),
    Map(Vec<(String, PendingNode)>),
    Absent,
    Passthrough(Boxed),
}

struct DeferredOutput<T> {
    node: Result<PendingNode, PrfError<Infallible>>,
    finish: Option<Finish<T>>,
    backend: DeferredPrf,
}

impl<T> DeferredOutput<T> {
    fn into_node(self) -> Result<PendingNode, PrfError<Infallible>> {
        self.node
    }
}

impl<T: Send + 'static> IntoFuture for DeferredOutput<T> {
    type Output = Result<T, PrfError<Infallible>>;
    type IntoFuture = Ready<Self::Output>;

    fn into_future(mut self) -> Self::IntoFuture {
        self.backend.batch_calls.fetch_add(1, Ordering::SeqCst);
        let result = self
            .node
            .and_then(|node| self.backend.resolve(node))
            .and_then(|node| {
                self.finish
                    .take()
                    .expect("successful outputs have a visitor")(node)
            });
        ready(result)
    }
}

#[derive(Clone)]
struct DeferredPrf {
    key: Arc<Protected<Vec<u8>>>,
    batch_calls: Arc<AtomicUsize>,
}

impl DeferredPrf {
    fn new(key: Protected<Vec<u8>>) -> Self {
        Self {
            key: Arc::new(key),
            batch_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn output<T, V>(&self, node: PendingNode, visitor: V) -> DeferredOutput<T>
    where
        T: Send + 'static,
        V: PrfVisitor<[u8; 32], Boxed, Value = T> + 'static,
    {
        DeferredOutput {
            node: Ok(node),
            finish: Some(Box::new(move |node| {
                node.visit(visitor).map_err(PrfError::Visitor)
            })),
            backend: self.clone(),
        }
    }

    fn resolve(&self, node: PendingNode) -> Result<Node, PrfError<Infallible>> {
        Ok(match node {
            PendingNode::Leaf(data, encoding, context) => {
                let framed =
                    PrfContext::pae(&[encoding.as_bytes(), context.as_bytes(), data.risky_ref()]);
                let mut mac = Hmac::<Sha256>::new_from_slice(self.key.risky_ref()).unwrap();
                mac.update(framed.as_bytes());
                let bytes = mac.finalize().into_bytes();
                let mut block = [0; 32];
                block.copy_from_slice(&bytes);
                ResolvedPrf::Block(block)
            }
            PendingNode::Sequence(values) => ResolvedPrf::Sequence(
                values
                    .into_iter()
                    .map(|value| self.resolve(value))
                    .collect::<Result<_, _>>()?,
            ),
            PendingNode::Map(entries) => ResolvedPrf::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| Ok((key, self.resolve(value)?)))
                    .collect::<Result<_, PrfError<Infallible>>>()?,
            ),
            PendingNode::Absent => ResolvedPrf::Absent,
            PendingNode::Passthrough(value) => ResolvedPrf::Passthrough(value),
        })
    }
}

impl Prf for DeferredPrf {
    type Block = [u8; 32];
    type BackendError = Infallible;
    type Passthrough = Boxed;
    type SeqPrf<'a> = DeferredSeq<'a>;
    type MapPrf<'a> = DeferredMap<'a>;
    type Ok<T>
        = DeferredOutput<T>
    where
        T: Send + 'static;

    fn prf_bytes_vec<V>(
        &self,
        data: Protected<Vec<u8>>,
        encoding: PrfEncoding,
        context: PrfContext<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        // The test backend is deliberately test-only and can require owned
        // visitors through this type-erased finish closure.
        self.output(PendingNode::Leaf(data, encoding, context), visitor)
    }

    fn prf_seq(&self, size_hint: Option<usize>) -> Self::SeqPrf<'_> {
        DeferredSeq {
            backend: self,
            values: Vec::with_capacity(size_hint.unwrap_or(0)),
            error: None,
        }
    }

    fn prf_map(&self, size_hint: Option<usize>) -> Self::MapPrf<'_> {
        DeferredMap {
            backend: self,
            entries: Vec::with_capacity(size_hint.unwrap_or(0)),
            pending: None,
            error: None,
        }
    }

    fn prf_none<V>(&self, _context: PrfContext<'static>, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        self.output(PendingNode::Absent, visitor)
    }

    fn passthrough<V>(&self, value: Self::Passthrough, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        self.output(PendingNode::Passthrough(value), visitor)
    }

    fn passthrough_boxed<V>(&self, value: Boxed, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        self.passthrough(value, visitor)
    }

    fn failure<T>(&self, error: PrfError<Self::BackendError>) -> Self::Ok<T>
    where
        T: Send + 'static,
    {
        DeferredOutput {
            node: Err(error),
            finish: None,
            backend: self.clone(),
        }
    }
}

struct DeferredSeq<'a> {
    backend: &'a DeferredPrf,
    values: Vec<PendingNode>,
    error: Option<PrfError<Infallible>>,
}

impl SeqPrf for DeferredSeq<'_> {
    type Prf = DeferredPrf;
    type Block = [u8; 32];
    type BackendError = Infallible;
    type Passthrough = Boxed;

    fn prf_next<T: PrfValue>(mut self, value: T, context: PrfContext<'static>) -> Self {
        if self.error.is_none() {
            match value
                .prf_visit_with_context(self.backend, context, ResolvedVisitor)
                .into_node()
            {
                Ok(node) => self.values.push(node),
                Err(error) => self.error = Some(error),
            }
        }
        self
    }

    fn passthrough_next(mut self, value: Self::Passthrough) -> Self {
        self.values.push(PendingNode::Passthrough(value));
        self
    }

    fn passthrough_next_boxed(self, value: Boxed) -> Self {
        self.passthrough_next(value)
    }

    fn end<V>(self, visitor: V) -> <Self::Prf as Prf>::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        match self.error {
            Some(error) => self.backend.failure(error),
            None => self
                .backend
                .output(PendingNode::Sequence(self.values), visitor),
        }
    }
}

struct DeferredMap<'a> {
    backend: &'a DeferredPrf,
    entries: Vec<(String, PendingNode)>,
    pending: Option<String>,
    error: Option<PrfError<Infallible>>,
}

impl DeferredMap<'_> {
    fn build_error(&mut self, error: PrfBuildError) {
        if self.error.is_none() {
            self.error = Some(PrfError::Build(error));
        }
    }
}

impl MapPrf for DeferredMap<'_> {
    type Prf = DeferredPrf;
    type Block = [u8; 32];
    type BackendError = Infallible;
    type Passthrough = Boxed;

    fn prf_key<K: Into<Cow<'static, str>>>(mut self, key: K) -> Self {
        if self.pending.is_some() {
            self.build_error(PrfBuildError::KeyWithoutValue);
        } else {
            self.pending = Some(key.into().into_owned());
        }
        self
    }

    fn prf_value<T: PrfValue>(mut self, value: T, context: PrfContext<'static>) -> Self {
        let Some(key) = self.pending.take() else {
            self.build_error(PrfBuildError::ValueWithoutKey);
            return self;
        };
        match value
            .prf_visit_with_context(self.backend, context.for_map_entry(&key), ResolvedVisitor)
            .into_node()
        {
            Ok(node) => self.entries.push((key, node)),
            Err(error) => self.error = Some(error),
        }
        self
    }

    fn passthrough_entry<K: Into<Cow<'static, str>>>(
        mut self,
        key: K,
        value: Self::Passthrough,
    ) -> Self {
        self.entries
            .push((key.into().into_owned(), PendingNode::Passthrough(value)));
        self
    }

    fn passthrough_entry_boxed<K: Into<Cow<'static, str>>>(self, key: K, value: Boxed) -> Self {
        self.passthrough_entry(key, value)
    }

    fn end<V>(mut self, visitor: V) -> <Self::Prf as Prf>::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        if self.pending.is_some() {
            self.build_error(PrfBuildError::DanglingKey);
        }
        match self.error {
            Some(error) => self.backend.failure(error),
            None => self.backend.output(PendingNode::Map(self.entries), visitor),
        }
    }
}

#[test]
fn deferred_nested_record_executes_one_batch() {
    let backend = DeferredPrf::new(key());
    let calls = backend.batch_calls.clone();
    let output = block_on(
        mixed_record()
            .prf_visit_with_context(&backend, "tenant-42", RecordVisitor)
            .into_future(),
    )
    .unwrap();
    assert_eq!(output.tags.len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[quickcheck]
fn local_and_deferred_backends_match(values: Vec<Vec<u8>>, context: Vec<u8>) -> bool {
    let expected = values
        .clone()
        .prf_visit_with_context(&local(), context.clone(), BlocksVisitor)
        .into_result()
        .unwrap();
    let actual = block_on(
        values
            .prf_visit_with_context(&DeferredPrf::new(key()), context, BlocksVisitor)
            .into_future(),
    )
    .unwrap();
    expected == actual
}

#[quickcheck]
fn sequence_order_and_shape_are_preserved(values: Vec<Vec<u8>>) -> bool {
    let expected: Vec<_> = values
        .iter()
        .map(|value| value.clone().prf(&local()).into_result().unwrap())
        .collect();
    let structured = values
        .prf_visit(&local(), BlocksVisitor)
        .into_result()
        .unwrap();
    expected == structured
}

#[quickcheck]
fn derivation_is_deterministic(key_suffix: Vec<u8>, context: Vec<u8>, input: Vec<u8>) -> bool {
    // Arbitrary key material, lengthened past the minimum the constructor
    // enforces so that every generated case reaches the derivation.
    let key_bytes = [key_bytes().to_vec(), key_suffix].concat();
    let first = input
        .clone()
        .prf_with_context(
            &HmacSha256Prf::try_from_bytes(Protected::new(key_bytes.clone())).unwrap(),
            context.clone(),
        )
        .into_result()
        .unwrap();
    let second = input
        .prf_with_context(
            &HmacSha256Prf::try_from_bytes(Protected::new(key_bytes)).unwrap(),
            context,
        )
        .into_result()
        .unwrap();
    first == second
}

/// `HmacSha256Prf` declares `ZeroizeOnDrop`. The marker is hand-written,
/// so this only checks the declaration exists; the single-owner property it
/// rests on (no `Clone`) is pinned by the compile-fail case in
/// `tests/ui/negative_space`.
#[test]
fn prf_declares_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<HmacSha256Prf>();
}

/// Derivation borrows the PRF, so one instance serves repeated derivations
/// without a `Clone` handle and without consuming the key.
#[test]
fn one_prf_instance_serves_repeated_derivations_by_reference() {
    let prf = local();
    let first: [u8; 32] = b"needle".as_slice().prf(&prf).into_result().unwrap();
    let second: [u8; 32] = b"needle".as_slice().prf(&prf).into_result().unwrap();
    let other: [u8; 32] = b"haystack".as_slice().prf(&prf).into_result().unwrap();
    assert_eq!(first, second);
    assert_ne!(first, other);

    // Structural drivers borrow the same instance, then hand it back.
    let terms = vec![vec![1_u8], vec![2_u8]]
        .prf_visit(&prf, BlocksVisitor)
        .into_result()
        .unwrap();
    assert_eq!(terms.len(), 2);
    let after: [u8; 32] = b"needle".as_slice().prf(&prf).into_result().unwrap();
    assert_eq!(first, after);
}

/// Callers generic over "any PRF constructible from a key" bound on
/// `PrfKeyInit` alone (`Prf` is its supertrait). Its two constructor paths,
/// the fixed-length `new` and the runtime-length `try_from_bytes`, key the
/// backend identically, and `try_from_bytes` still rejects short keys.
#[test]
fn prf_key_init_builds_the_backend_generically() {
    fn keyed<P: PrfKeyInit>(key: P::Key) -> P {
        P::new(key)
    }
    fn keyed_from_bytes<P: PrfKeyInit>(key: Protected<Vec<u8>>) -> Result<P, P::KeyError> {
        P::try_from_bytes(key)
    }
    // `PrfKeyInit` alone is enough to derive with: `Prf` is its supertrait.
    fn needle<P: PrfKeyInit>(prf: &P) -> P::Ok<P::Block> {
        b"needle".as_slice().prf(prf)
    }

    let via_trait: HmacSha256Prf = keyed(Protected::new(key_bytes()));
    let via_trait_bytes: HmacSha256Prf = keyed_from_bytes(key()).unwrap();
    let expected: [u8; 32] = needle(&local()).into_result().unwrap();
    let a: [u8; 32] = needle(&via_trait).into_result().unwrap();
    let b: [u8; 32] = needle(&via_trait_bytes).into_result().unwrap();
    assert_eq!(a, expected);
    assert_eq!(b, expected);

    match keyed_from_bytes::<HmacSha256Prf>(Protected::new(vec![0x0b; 16])) {
        Err(error) => assert_eq!(error.len(), 16),
        Ok(_) => panic!("a 16-byte key must be rejected through the trait too"),
    }
}

#[test]
fn short_keys_are_rejected() {
    for len in 0..vitaminc_hmac::MIN_KEY_LEN {
        let error = HmacSha256Prf::try_from_bytes(Protected::new(vec![0x0b; len]))
            .err()
            .unwrap_or_else(|| panic!("a {len}-byte key must be rejected"));
        assert_eq!(error.len(), len);
        assert_eq!(error.is_empty(), len == 0);
        // The rejection has to say what was wrong and what is required, so
        // that a caller wiring up key material can act on it.
        assert_eq!(
            error.to_string(),
            format!(
                "HMAC-SHA256 PRF key must be at least {} bytes, got {len}",
                vitaminc_hmac::MIN_KEY_LEN
            )
        );
    }

    assert!(
        HmacSha256Prf::try_from_bytes(Protected::new(vec![0x0b; vitaminc_hmac::MIN_KEY_LEN]))
            .is_ok()
    );
}

#[test]
fn both_constructors_agree_on_the_same_key() {
    let input = b"same key, same derivation".to_vec();
    let from_array = input
        .clone()
        .prf(&HmacSha256Prf::new(Protected::new(key_bytes())))
        .into_result()
        .unwrap();
    let from_bytes = input
        .prf(&HmacSha256Prf::try_from_bytes(key()).unwrap())
        .into_result()
        .unwrap();

    assert_eq!(from_array, from_bytes);
}

#[quickcheck]
fn equal_sequence_values_share_terms(value: Vec<u8>, context: Vec<u8>) -> bool {
    let terms = vec![value.clone(), value]
        .prf_visit_with_context(&local(), context, BlocksVisitor)
        .into_result()
        .unwrap();
    terms[0] == terms[1]
}

#[test]
fn map_key_context_separates_equal_values() {
    let values = BTreeMap::from([
        ("left".to_owned(), "same".to_owned()),
        ("right".to_owned(), "same".to_owned()),
    ]);
    struct MapBlocks;
    impl<P> PrfVisitor<[u8; 32], P> for MapBlocks {
        type Value = Vec<[u8; 32]>;
        fn visit_map(self, map: MapAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
            map.map(|(_, node)| node.visit(BlockVisitor)).collect()
        }
    }
    let terms = values.prf_visit(&local(), MapBlocks).into_result().unwrap();
    assert_ne!(terms[0], terms[1]);
}

#[test]
fn outputs_are_into_future_and_resolved_values_are_send() {
    fn assert_into_future<T: IntoFuture>() {}
    fn assert_send<T: Send>() {}

    assert_into_future::<ReadyPrf<[u8; 32], Infallible>>();
    assert_send::<Node>();
    assert_send::<DerivedRecord>();
    assert_send::<Vec<i16>>();
}

#[test]
fn structural_and_visitor_errors_remain_distinct() {
    let malformed = local()
        .prf_map(None)
        .prf_key("dangling")
        .end(ResolvedVisitor)
        .into_result();
    assert!(matches!(
        malformed,
        Err(PrfError::Build(PrfBuildError::DanglingKey))
    ));

    let wrong_visitor = b"leaf"
        .as_slice()
        .prf_visit(&local(), BlocksVisitor)
        .into_result();
    assert!(matches!(
        wrong_visitor,
        Err(PrfError::Visitor(PrfVisitorError::UnexpectedShape))
    ));
}

#[test]
fn duplicate_map_keys_are_rejected() {
    let duplicated = local()
        .prf_map(None)
        .prf_entry("email", "a@example.com", PrfContext::empty())
        .prf_entry("email", "b@example.com", PrfContext::empty())
        .end(ResolvedVisitor)
        .into_result();
    assert!(matches!(
        duplicated,
        Err(PrfError::Build(PrfBuildError::DuplicateKey))
    ));
}

#[test]
fn duplicate_passthrough_map_keys_are_rejected() {
    let duplicated = local()
        .prf_map(None)
        .prf_entry("field", "value", PrfContext::empty())
        .passthrough_entry("field", Box::new(1_u32))
        .end(ResolvedVisitor)
        .into_result();
    assert!(matches!(
        duplicated,
        Err(PrfError::Build(PrfBuildError::DuplicateKey))
    ));
}
