//! Async backends: the walk is synchronous, the leaves are sealed and
//! opened afterwards, and a provider with a batch API gets one round trip
//! per document.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use futures::executor::block_on;
use vitaminc_aead::{Context, LocalCipherText, Unspecified};
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_plaintext_spike::{
    decrypt_as_async, decrypt_into, decrypt_into_async, encrypt, encrypt_async, encrypt_with_terms_async, AsyncBackend,
    Backend, EncryptError, Frame, FrameWriter, Pending,
};
use vitaminc_protected::{Controlled, Protected};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

/// A stand-in for a remote key provider: AES behind an await, counting
/// round trips. It batches, so a document costs one round trip.
///
/// `Aes256Cipher` isn't `Sync` (its nonce generator is a `RefCell`), and an
/// async backend is shared across tasks, so it sits behind a mutex here.
struct Kms {
    aes: Mutex<Aes256Cipher>,
    round_trips: AtomicUsize,
}

impl Kms {
    fn new() -> Self {
        Self {
            aes: Mutex::new(cipher()),
            round_trips: AtomicUsize::new(0),
        }
    }

    fn round_trips(&self) -> usize {
        self.round_trips.load(Ordering::SeqCst)
    }
}

impl AsyncBackend for Kms {
    type Leaf = LocalCipherText;
    type Error = Unspecified;

    async fn seal(&self, plaintext: Protected<Vec<u8>>, aad: Context<'static>) -> Result<LocalCipherText, Unspecified> {
        self.round_trips.fetch_add(1, Ordering::SeqCst);
        Backend::seal(&*self.aes.lock().unwrap(), plaintext, &aad)
    }

    async fn open(&self, leaf: LocalCipherText, aad: Context<'static>) -> Result<Protected<Vec<u8>>, Unspecified> {
        self.round_trips.fetch_add(1, Ordering::SeqCst);
        Backend::open(&*self.aes.lock().unwrap(), leaf, &aad)
    }

    async fn seal_many(&self, leaves: Vec<Pending>) -> Result<Vec<LocalCipherText>, Unspecified> {
        self.round_trips.fetch_add(1, Ordering::SeqCst);
        let aes = self.aes.lock().unwrap();
        leaves.into_iter().map(|p| Backend::seal(&*aes, p.plaintext, &p.aad)).collect()
    }

    async fn open_many(&self, leaves: Vec<(LocalCipherText, Context<'static>)>) -> Result<Vec<Protected<Vec<u8>>>, Unspecified> {
        self.round_trips.fetch_add(1, Ordering::SeqCst);
        leaves.into_iter().map(|(leaf, aad)| Backend::open(&*self.aes.lock().unwrap(), leaf, &aad)).collect()
    }
}

/// The same provider without a batch API: the trait's defaults seal each
/// leaf on its own.
struct LeafByLeaf(Kms);

impl AsyncBackend for LeafByLeaf {
    type Leaf = LocalCipherText;
    type Error = Unspecified;

    async fn seal(&self, plaintext: Protected<Vec<u8>>, aad: Context<'static>) -> Result<LocalCipherText, Unspecified> {
        self.0.seal(plaintext, aad).await
    }

    async fn open(&self, leaf: LocalCipherText, aad: Context<'static>) -> Result<Protected<Vec<u8>>, Unspecified> {
        self.0.open(leaf, aad).await
    }
}

/// The nested sample: ten scalars, one of them passthrough, so nine
/// sealed leaves.
fn sample() -> Vec<u8> {
    common::encode(common::sample())
}

const SEALED_LEAVES: usize = 9;

#[test]
fn a_document_is_one_round_trip_each_way() {
    let kms = Kms::new();
    let bytes = sample();

    let ct = block_on(encrypt_async(Frame::parse(&bytes).unwrap(), &kms, ())).unwrap();
    assert_eq!(kms.round_trips(), 1);

    let mut out = Vec::new();
    block_on(decrypt_into_async(&kms, ct, (), FrameWriter::new(&mut out))).unwrap();
    assert_eq!(kms.round_trips(), 2);
    assert_eq!(out, bytes);
}

#[test]
fn without_a_batch_api_each_leaf_is_its_own_call() {
    let kms = LeafByLeaf(Kms::new());
    let bytes = sample();

    let ct = block_on(encrypt_async(Frame::parse(&bytes).unwrap(), &kms, ())).unwrap();
    assert_eq!(kms.0.round_trips(), SEALED_LEAVES);

    let mut out = Vec::new();
    block_on(decrypt_into_async(&kms, ct, (), FrameWriter::new(&mut out))).unwrap();
    assert_eq!(kms.0.round_trips(), 2 * SEALED_LEAVES);
    assert_eq!(out, bytes);
}

#[test]
fn sync_and_async_backends_read_each_others_ciphertext() {
    let kms = Kms::new();
    let aes = cipher();
    let bytes = sample();

    // Sealed by the async provider, opened by the local cipher.
    let ct = block_on(encrypt_async(Frame::parse(&bytes).unwrap(), &kms, ())).unwrap();
    let mut out = Vec::new();
    decrypt_into(&aes, ct, (), FrameWriter::new(&mut out)).unwrap();
    assert_eq!(out, bytes);

    // And the other way round, into a typed target.
    let ct = encrypt(34u32, &aes, ()).unwrap();
    assert_eq!(block_on(decrypt_as_async::<u32, _, _>(&kms, ct, ())).unwrap(), 34);
}

#[test]
fn terms_are_complete_before_the_first_await() {
    let kms = Kms::new();
    let bytes = sample();
    let (ct, terms) = block_on(encrypt_with_terms_async(Frame::parse(&bytes).unwrap(), &kms, ())).unwrap();
    assert_eq!(kms.round_trips(), 1);
    // Every sealed leaf but the null and the bool has a term; the
    // passthrough has none.
    assert_eq!(terms.len(), SEALED_LEAVES - 2);
    let mut out = Vec::new();
    block_on(decrypt_into_async(&kms, ct, (), FrameWriter::new(&mut out))).unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn a_backend_that_miscounts_is_refused() {
    struct DropsOne(Kms);

    impl AsyncBackend for DropsOne {
        type Leaf = LocalCipherText;
        type Error = Unspecified;

        async fn seal(&self, plaintext: Protected<Vec<u8>>, aad: Context<'static>) -> Result<LocalCipherText, Unspecified> {
            self.0.seal(plaintext, aad).await
        }

        async fn open(&self, leaf: LocalCipherText, aad: Context<'static>) -> Result<Protected<Vec<u8>>, Unspecified> {
            self.0.open(leaf, aad).await
        }

        async fn seal_many(&self, mut leaves: Vec<Pending>) -> Result<Vec<LocalCipherText>, Unspecified> {
            leaves.pop();
            self.0.seal_many(leaves).await
        }
    }

    let bytes = sample();
    let err = block_on(encrypt_async(Frame::parse(&bytes).unwrap(), &DropsOne(Kms::new()), ())).unwrap_err();
    assert!(matches!(err, EncryptError::Shape("backend returned too few leaves")));
}

#[test]
fn a_leaf_that_fails_to_seal_fails_the_document() {
    struct Refuses;

    impl AsyncBackend for Refuses {
        type Leaf = LocalCipherText;
        type Error = &'static str;

        async fn seal(&self, _: Protected<Vec<u8>>, _: Context<'static>) -> Result<LocalCipherText, &'static str> {
            Err("key provider unavailable")
        }

        async fn open(&self, _: LocalCipherText, _: Context<'static>) -> Result<Protected<Vec<u8>>, &'static str> {
            Err("key provider unavailable")
        }
    }

    let err = block_on(encrypt_async(34u32, &Refuses, ())).unwrap_err();
    assert!(matches!(err, EncryptError::Backend("key provider unavailable")));
}

#[test]
fn the_plan_holds_each_leaf_with_its_own_aad() {
    // The AAD per leaf is derived during the walk, so a batch call has
    // everything it needs and nothing about the tree.
    let bytes = sample();
    let plan = vitaminc_plaintext_spike::plan::<_, Unspecified, _>(Frame::parse(&bytes).unwrap(), ()).unwrap();
    let mut leaves = Vec::new();
    collect(plan, &mut leaves);
    assert_eq!(leaves.len(), SEALED_LEAVES);
    // Distinct map entries get distinct AAD; the three sequence elements
    // share one.
    let aads: std::collections::HashSet<Vec<u8>> = leaves.iter().map(|p| p.aad.as_bytes().to_vec()).collect();
    assert_eq!(aads.len(), SEALED_LEAVES - 2);
    assert!(leaves.iter().all(|p| !p.plaintext.risky_ref().is_empty()), "no markers in this sample");
}

fn collect(node: vitaminc_plaintext_spike::Node<Pending>, out: &mut Vec<Pending>) {
    use vitaminc_aead::CipherText::*;
    match node {
        Single(p) | EmptySequence(p) | EmptyMap(p) | None(p) => out.push(p),
        Sequence(items) => items.into_iter().for_each(|n| collect(n, out)),
        Map(entries) => entries.into_iter().for_each(|(_, n)| collect(n, out)),
        Passthrough(_) => {}
    }
}
