//! **SPIKE.** `#[derive(Seal)]`: a record sealed into its typed
//! counterpart. Passthrough fields are moved (owned) or borrowed (by
//! reference), never copied, and the sealed fields are the entries the
//! dynamic tree holds.

use std::sync::atomic::{AtomicUsize, Ordering};

use futures_executor::block_on;
use vitaminc_aead::{
    decrypt, encrypt, AsyncCipher, CipherText, Context, Decrypt, DecryptError, Encrypt, Pending,
    Seal,
};
use vitaminc_protected::{Controlled, Protected};

// A cipher that keeps the plaintext in the clear and authenticates the AAD,
// so two trees can be compared exactly.

#[derive(Debug, Clone, PartialEq, Eq)]
struct Leaf {
    aad: Vec<u8>,
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refused;

#[derive(Default)]
struct Mock {
    seal_batches: AtomicUsize,
    open_batches: AtomicUsize,
}

impl vitaminc_aead::seal::Cipher for Mock {
    type Leaf = Leaf;
    type Error = Refused;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Leaf, Refused> {
        Ok(Leaf {
            aad: aad.as_bytes().to_vec(),
            plaintext: plaintext.risky_unwrap(),
        })
    }

    fn open(&self, leaf: Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Refused> {
        if leaf.aad != aad.as_bytes() {
            return Err(Refused);
        }
        Ok(Protected::new(leaf.plaintext))
    }
}

/// The same cipher, async, counting its batches.
impl AsyncCipher for Mock {
    type Leaf = Leaf;
    type Error = Refused;

    async fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        aad: Context<'static>,
    ) -> Result<Leaf, Refused> {
        vitaminc_aead::seal::Cipher::seal(self, plaintext, &aad)
    }

    async fn open(&self, leaf: Leaf, aad: Context<'static>) -> Result<Protected<Vec<u8>>, Refused> {
        vitaminc_aead::seal::Cipher::open(self, leaf, &aad)
    }

    async fn seal_many(&self, leaves: Vec<Pending>) -> Result<Vec<Leaf>, Refused> {
        self.seal_batches.fetch_add(1, Ordering::SeqCst);
        leaves
            .into_iter()
            .map(|p| vitaminc_aead::seal::Cipher::seal(self, p.plaintext, &p.aad))
            .collect()
    }

    async fn open_many(
        &self,
        leaves: Vec<(Leaf, Context<'static>)>,
    ) -> Result<Vec<Protected<Vec<u8>>>, Refused> {
        self.open_batches.fetch_add(1, Ordering::SeqCst);
        leaves
            .into_iter()
            .map(|(leaf, aad)| vitaminc_aead::seal::Cipher::open(self, leaf, &aad))
            .collect()
    }
}

/// A passthrough type that cannot be cloned or copied.
#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct Audit {
    by: String,
}

#[derive(Encrypt, Decrypt, Seal, Debug, PartialEq)]
struct User {
    #[aead(passthrough)]
    id: u64,
    email: String,
    #[aead(passthrough)]
    notes: String,
    #[aead(passthrough)]
    audit: Audit,
    #[aead(rename = "years")]
    age: u32,
    #[aead(skip)]
    cache: Option<u32>,
}

fn user() -> User {
    User {
        id: 7,
        email: "ada@example.com".into(),
        notes: "public notes".into(),
        audit: Audit { by: "admin".into() },
        age: 37,
        cache: None,
    }
}

#[test]
fn sealing_an_owned_record_moves_its_passthrough_fields() {
    let user = user();
    let notes = user.notes.as_ptr();
    let audit = user.audit.by.as_ptr();

    let sealed = user.seal(&Mock::default(), "ctx").expect("seals");

    // The same heap buffers: moved, not copied.
    assert_eq!(sealed.notes.as_ptr(), notes);
    assert_eq!(sealed.audit.by.as_ptr(), audit);
    assert_eq!(sealed.id, 7);

    let opened = sealed.open(&Mock::default(), "ctx").expect("opens");
    assert_eq!(opened.notes.as_ptr(), notes);
    assert_eq!(opened.audit.by.as_ptr(), audit);
    assert_eq!(opened, user_with_cache_default());
}

fn user_with_cache_default() -> User {
    User {
        cache: None,
        ..user()
    }
}

#[test]
fn sealing_a_borrowed_record_borrows_its_passthrough_fields() {
    let user = user();
    let sealed = user.seal_ref(&Mock::default(), "ctx").expect("seals");

    assert!(std::ptr::eq(sealed.notes, &user.notes));
    assert!(std::ptr::eq(sealed.audit, &user.audit));
    assert!(std::ptr::eq(sealed.id, &user.id));
}

#[test]
fn a_sealed_record_is_the_tree_encrypt_makes() {
    let cipher = Mock::default();
    let dynamic = encrypt(user(), &cipher, "ctx").expect("encrypts");
    let owned = user().seal(&cipher, "ctx").expect("seals");
    let borrowed_from = user();
    let borrowed = borrowed_from.seal_ref(&cipher, "ctx").expect("seals");

    // The mock is deterministic, so the trees compare exactly: the same
    // keys in the same order, the same leaves under the same contexts, and
    // the same passthrough frame bytes. (`Debug` redacts a frame, so the
    // trees are compared entry by entry.)
    let dynamic = entries(dynamic);
    assert_eq!(dynamic.len(), 5);
    assert_eq!(entries(owned.into_node().expect("frames")), dynamic);
    assert_eq!(entries(borrowed.into_node().expect("frames")), dynamic);
}

#[derive(Debug, PartialEq)]
enum Column {
    Sealed(Leaf),
    Clear(Vec<u8>),
}

fn entries(node: vitaminc_aead::Node<Leaf>) -> Vec<(String, Column)> {
    let CipherText::Map(entries) = node else {
        panic!("a struct encrypts as a map");
    };
    entries
        .into_iter()
        .map(|(key, node)| {
            let column = match node {
                CipherText::Single(leaf) => Column::Sealed(leaf),
                CipherText::Passthrough(frame) => Column::Clear(frame.0),
                _ => panic!("the spike's test record holds scalar and passthrough columns only"),
            };
            (key, column)
        })
        .collect()
}

#[test]
fn the_dynamic_tree_of_a_sealed_record_decrypts_as_the_record() {
    let cipher = Mock::default();
    let node = user()
        .seal(&cipher, "ctx")
        .expect("seals")
        .into_node()
        .expect("frames");
    let back: User = decrypt(&cipher, node, "ctx").expect("decrypts");
    assert_eq!(back, user());
}

/// A row stored by the dynamic path, with its passthrough columns read back
/// as their own types, opens as a sealed record.
#[test]
fn a_row_the_dynamic_path_stored_opens_as_a_sealed_record() {
    let cipher = Mock::default();
    let CipherText::Map(entries) = encrypt(user(), &cipher, "ctx").expect("encrypts") else {
        panic!("a struct encrypts as a map");
    };
    let column = |key: &str| {
        entries
            .iter()
            .position(|(k, _)| k == key)
            .map(|at| entries[at].1.clone_leaves())
            .expect("column")
    };
    let row = SealedUser {
        id: 7,
        email: column("email"),
        notes: "public notes".into(),
        audit: Audit { by: "admin".into() },
        age: column("years"),
    };
    assert_eq!(row.open(&cipher, "ctx").expect("opens"), user());
}

/// A sealed field is bound to its key and the record's context, as in the
/// dynamic tree.
#[test]
fn a_sealed_record_opens_only_under_its_own_context_and_keys() {
    let cipher = Mock::default();
    let sealed = user().seal(&cipher, "ctx").expect("seals");
    assert!(matches!(
        sealed.open(&cipher, "other"),
        Err(DecryptError::Cipher(Refused))
    ));

    // Swapping two sealed fields fails too: each is bound to its key.
    let sealed = user().seal(&cipher, "ctx").expect("seals");
    let swapped = SealedUser {
        email: sealed.age,
        age: sealed.email,
        ..sealed
    };
    assert!(matches!(
        swapped.open(&cipher, "ctx"),
        Err(DecryptError::Cipher(Refused))
    ));
}

#[test]
fn an_async_cipher_seals_and_opens_a_record_in_one_batch_each() {
    let cipher = Mock::default();
    let user = user();
    let notes = user.notes.as_ptr();

    let sealed = block_on(user.seal_async(&cipher, "ctx")).expect("seals");
    assert_eq!(sealed.notes.as_ptr(), notes);
    let opened = block_on(sealed.open_async(&cipher, "ctx")).expect("opens");

    assert_eq!(opened, user_with_cache_default());
    assert_eq!(opened.notes.as_ptr(), notes);
    assert_eq!(cipher.seal_batches.load(Ordering::SeqCst), 1);
    assert_eq!(cipher.open_batches.load(Ordering::SeqCst), 1);
}

#[test]
fn a_skipped_field_comes_back_as_its_default() {
    let cipher = Mock::default();
    let user = User {
        cache: Some(9),
        ..user()
    };
    let opened = user
        .seal(&cipher, "ctx")
        .expect("seals")
        .open(&cipher, "ctx")
        .expect("opens");
    assert_eq!(opened.cache, None);
}

/// Copy a mock tree's leaves, for building a row by hand.
trait CloneLeaves {
    fn clone_leaves(&self) -> Self;
}

impl CloneLeaves for vitaminc_aead::Node<Leaf> {
    fn clone_leaves(&self) -> Self {
        match self {
            CipherText::Single(leaf) => CipherText::Single(leaf.clone()),
            _ => panic!("the spike's test rows hold scalar columns only"),
        }
    }
}
