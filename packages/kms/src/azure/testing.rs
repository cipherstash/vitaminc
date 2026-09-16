//! Test scaffolding shared by the Azure adapters' own test modules: a
//! zero-network stub transport, and a client pointed at the Lowkey Vault
//! emulator from `packages/kms/docker-compose.yml`.

use async_trait::async_trait;
use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::http::headers::{Headers, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use azure_core::http::{
    AsyncRawResponse, Body, ClientOptions, HttpClient, Request, StatusCode, Transport, Url,
};
use azure_core::time::OffsetDateTime;
use azure_security_keyvault_keys::models::{CreateKeyParameters, CurveName, KeyOperation, KeyType};
use azure_security_keyvault_keys::{KeyClient, KeyClientOptions, ResourceExt};
use std::sync::{Arc, Mutex};

/// Lowkey Vault rejects the crate's default date-based API version
/// (`2025-07-01`); it speaks the classic `7.x` scheme.
const LOWKEY_API_VERSION: &str = "7.6";
const LOWKEY_ENDPOINT: &str = "https://localhost:8443";

/// A credential that hands out a fixed token. Lowkey Vault ignores token
/// values, and the stub transport never checks one either — the bearer
/// policy just needs *some* credential to call.
#[derive(Debug)]
pub(super) struct StubCredential;

#[async_trait]
impl TokenCredential for StubCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        Ok(AccessToken::new(
            "stub-token",
            OffsetDateTime::now_utc() + azure_core::time::Duration::hours(1),
        ))
    }
}

/// One request the [`StubTransport`] was asked to send.
#[derive(Debug, Clone)]
pub(super) struct RecordedRequest {
    pub(super) url: Url,
    pub(super) body: Vec<u8>,
}

impl RecordedRequest {
    /// The request body as JSON. Every Key Vault crypto call sends JSON.
    pub(super) fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("request body should be JSON")
    }

    /// The path of the request URL, with the query string dropped.
    pub(super) fn path(&self) -> &str {
        self.url.path()
    }
}

/// An [`HttpClient`] that answers from a queue of canned JSON bodies and
/// records what it was asked to send, so a test can assert on the request
/// without a network.
///
/// Key Vault clients discover their auth scope by sending the first request
/// unauthorized and reading the challenge off the 401 (see
/// `azure_security_keyvault_keys`'s `KeyVaultAuthorizer`). This stub plays
/// that back: a request with no `authorization` header gets the challenge
/// and is not recorded, so `requests()` holds only the real calls.
#[derive(Debug)]
pub(super) struct StubTransport {
    responses: Mutex<Vec<(StatusCode, String)>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

impl StubTransport {
    fn new(responses: Vec<(StatusCode, String)>) -> Self {
        Self {
            // Popped from the back, so reverse once up front.
            responses: Mutex::new(responses.into_iter().rev().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub(super) fn call_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

#[async_trait]
impl HttpClient for StubTransport {
    async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
        if request.headers().get_optional_str(&AUTHORIZATION).is_none() {
            let mut headers = Headers::new();
            headers.insert(
                WWW_AUTHENTICATE,
                r#"Bearer authorization="https://login.microsoftonline.com/tenant", resource="https://vault.azure.net""#,
            );
            return Ok(AsyncRawResponse::from_bytes(
                StatusCode::Unauthorized,
                headers,
                Vec::new(),
            ));
        }

        let body = match request.body() {
            Body::Bytes(bytes) => bytes.to_vec(),
            Body::SeekableStream(_) => panic!("the stub transport does not stream request bodies"),
        };
        self.requests.lock().unwrap().push(RecordedRequest {
            url: request.url().clone(),
            body,
        });

        let (status, body) = self
            .responses
            .lock()
            .unwrap()
            .pop()
            .expect("the stub transport ran out of canned responses");

        let mut headers = Headers::new();
        headers.insert(CONTENT_TYPE, "application/json; charset=utf-8");
        Ok(AsyncRawResponse::from_bytes(status, headers, body))
    }
}

/// A [`KeyClient`] whose transport answers with `responses` in order, each
/// with a 200 status.
pub(super) fn stub_client(responses: &[&str]) -> (KeyClient, Arc<StubTransport>) {
    let transport = Arc::new(StubTransport::new(
        responses
            .iter()
            .map(|body| (StatusCode::Ok, (*body).to_owned()))
            .collect(),
    ));
    let client = KeyClient::new(
        "https://my-vault.vault.azure.net",
        Arc::new(StubCredential),
        Some(KeyClientOptions {
            api_version: LOWKEY_API_VERSION.to_owned(),
            client_options: ClientOptions {
                transport: Some(Transport::new(transport.clone() as Arc<dyn HttpClient>)),
                ..Default::default()
            },
            verify_challenge_resource: Some(false),
        }),
    )
    .expect("the stub client should build");
    (client, transport)
}

/// A [`KeyClient`] for the Lowkey Vault emulator.
///
/// Three things are needed to talk to it, all of them test-only:
///
/// - `api_version` must be a classic `7.x` version. The crate's default
///   (`2025-07-01`) is not a route Lowkey Vault serves.
/// - `verify_challenge_resource` must be off. Lowkey Vault's challenge names
///   `https://localhost:8443` as the resource, and the SDK's check demands
///   the request host be a subdomain of the challenge host.
/// - The transport must trust Lowkey Vault's self-signed certificate. This
///   builds a `reqwest` client that accepts it, rather than installing
///   anything in the OS trust store. The bearer policy refuses plain HTTP,
///   so dropping to `http://localhost:8080` is not an option.
pub(super) fn lowkey_client() -> KeyClient {
    let http: Arc<dyn HttpClient> = Arc::new(
        reqwest::Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .build()
            .expect("the Lowkey Vault HTTP client should build"),
    );
    KeyClient::new(
        LOWKEY_ENDPOINT,
        Arc::new(StubCredential),
        Some(KeyClientOptions {
            api_version: LOWKEY_API_VERSION.to_owned(),
            client_options: ClientOptions {
                transport: Some(Transport::new(http)),
                ..Default::default()
            },
            verify_challenge_resource: Some(false),
        }),
    )
    .expect("the Lowkey Vault client should build")
}

/// A key name no other test run will have used.
pub(super) fn unique_key_name(prefix: &str) -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock should be after the epoch")
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{prefix}-{nanos}-{n}")
}

/// Creates a key in Lowkey Vault and returns its version.
///
/// Lowkey Vault denies every operation a key was not created with, so
/// `key_ops` is explicit. It also rejects `sign`/`verify` on an `oct-HSM`
/// key outright.
pub(super) async fn create_key(
    client: &KeyClient,
    key_name: &str,
    kty: KeyType,
    key_size: Option<i32>,
    curve: Option<CurveName>,
    key_ops: &[KeyOperation],
) -> String {
    let parameters = CreateKeyParameters {
        kty: Some(kty),
        key_size,
        curve,
        key_ops: Some(key_ops.to_vec()),
        ..Default::default()
    };
    let key = client
        .create_key(key_name, parameters.try_into().unwrap(), None)
        .await
        .expect("Lowkey Vault should create the key")
        .into_model()
        .expect("the created key should deserialize");
    key.resource_id()
        .expect("the created key should carry a parseable kid")
        .version
        .expect("a created key should have a version")
}
