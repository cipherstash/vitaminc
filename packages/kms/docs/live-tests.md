# Live tests: Vault Enterprise, Azure Managed HSM, Google Cloud KMS

Some adapter paths have no emulator:

- The native batch path of `VaultDataKeySource` (`datakeys`). Only Vault
  Enterprise has it (CIP-4071).
- `AzureDataKeySource` (`A256GCM` on `oct-HSM`) and `AzureMacKey` (`HS256`
  on `oct-HSM`). Lowkey Vault rejects both (CIP-4072).
- All of the Google Cloud KMS adapters. No emulator exists (CIP-4073).

For these paths, the crate has *live tests*. A live test talks to a real
backend. It runs only when you turn it on.

## How the switch works

Each backend has one flag:

| Backend | Flag |
|---|---|
| Vault Enterprise | `VITAMINC_KMS_LIVE_VAULT_ENTERPRISE` |
| Azure Managed HSM | `VITAMINC_KMS_LIVE_AZURE` |
| Google Cloud KMS | `VITAMINC_KMS_LIVE_GCP` |

- **Flag not set** (or empty, `0`, `false`): each live test writes one
  `skipped: ...` line to stderr and returns. The test shows as `ok`,
  because Rust has no runtime skip. Use `--nocapture` to see the lines.
- **Flag set to `1` or `true`**: the test runs. If a required variable is
  missing or empty, the test **fails** and names the variable. Thus a CI
  job with a missing secret cannot pass by skipping.
- **Any other value**: the test fails.

The code is in `src/live.rs`. It compiles only for tests.

Every other variable starts with `VITAMINC_KMS_<BACKEND>_`. A variable with
a default is optional. An empty value is the same as no value.

The tests do not create cloud resources. They use keys that you create one
time, as this page tells you. The Vault Enterprise tests create Transit keys
in a dev server, which keeps no data after it stops.

## Vault Enterprise (CIP-4071)

| Variable | Required | Default |
|---|---|---|
| `VITAMINC_KMS_LIVE_VAULT_ENTERPRISE` | yes | — |
| `VITAMINC_KMS_VAULT_ENTERPRISE_ADDR` | no | `http://localhost:8210` |
| `VITAMINC_KMS_VAULT_ENTERPRISE_TOKEN` | no | `root` |

You need a Vault Enterprise licence. The `vault-enterprise` service of
`packages/kms/docker-compose.yml` is in the `enterprise` profile, so a
plain `up` does not start it. Without `VAULT_LICENSE`, the server stops at
once with `license check failed: no autoloaded license provided`, and
`up --wait` fails.

```sh
export VAULT_LICENSE=...   # do not write the licence into a file in the repo
docker compose -f packages/kms/docker-compose.yml --profile enterprise up -d --wait vault-enterprise
VITAMINC_KMS_LIVE_VAULT_ENTERPRISE=1 cargo test -p vitaminc-kms --features vault -- vault:: --nocapture
docker compose -f packages/kms/docker-compose.yml --profile enterprise down
```

When the flag is on, **all** Vault integration tests use the Enterprise
server, not only the Enterprise tests. The token must be able to enable a
Transit mount, create keys, policies and tokens: a root token.

The tests in `vault::data_key::enterprise_tests` prove which path a batch
used. They do this with token policies, not with a hook in the adapter:

- A token that can call only `transit/datakeys/plaintext/<name>` (not
  `datakey`) mints a batch under one binding. The fan-out cannot mint a key
  with that token, so the batch used the native path.
- A token that can call only `transit/datakey/plaintext/<name>` (not
  `datakeys`) mints a batch with mixed bindings. A probe of `datakeys`
  would get `403` and set the source's fallback flag. The flag stays clear,
  so the batch did not probe the native path.

If you point these tests at Community Vault, the native-path tests fail
with `403 permission denied`.

## Azure Managed HSM (CIP-4072)

| Variable | Required | Default |
|---|---|---|
| `VITAMINC_KMS_LIVE_AZURE` | yes | — |
| `VITAMINC_KMS_AZURE_HSM_URL` | yes | — (for example `https://<name>.managedhsm.azure.net`) |
| `VITAMINC_KMS_AZURE_DATA_KEY` | no | `vitaminc-live-aes256` |
| `VITAMINC_KMS_AZURE_MAC_KEY` | no | `vitaminc-live-hmac256` |
| `VITAMINC_KMS_AZURE_API_VERSION` | no | the default of `azure_security_keyvault_keys` |

Keys (create them one time):

```sh
az keyvault key create --hsm-name <name> --name vitaminc-live-aes256 \
  --kty oct-HSM --size 256 --ops encrypt decrypt
az keyvault key create --hsm-name <name> --name vitaminc-live-hmac256 \
  --kty oct-HSM --size 256 --ops sign verify
```

The MAC tests use the current version of the MAC key. They read it with
`get key`.

Permissions: give the identity the Managed HSM local RBAC role
**Managed HSM Crypto User** on the two keys (scope `/keys/<key name>`).
That role has encrypt, decrypt, sign, verify and read on keys.

```sh
az keyvault role assignment create --hsm-name <name> \
  --role "Managed HSM Crypto User" --assignee <object id> --scope /keys/vitaminc-live-aes256
az keyvault role assignment create --hsm-name <name> \
  --role "Managed HSM Crypto User" --assignee <object id> --scope /keys/vitaminc-live-hmac256
```

Credentials: the tests get each token from the Azure CLI, with
`az account get-access-token --scope <scope>`. This is the same method
that `azure_identity`'s `AzureCliCredential` uses. The crate does not add
`azure_identity` as a dependency for these tests. Sign in first:

```sh
az login
VITAMINC_KMS_LIVE_AZURE=1 VITAMINC_KMS_AZURE_HSM_URL=https://<name>.managedhsm.azure.net \
  cargo test -p vitaminc-kms --features azure -- azure::live_tests --nocapture
```

## Google Cloud KMS (CIP-4073)

| Variable | Required | Default |
|---|---|---|
| `VITAMINC_KMS_LIVE_GCP` | yes | — |
| `VITAMINC_KMS_GCP_PROJECT` | yes | — |
| `VITAMINC_KMS_GCP_LOCATION` | yes | — (for example `global`) |
| `VITAMINC_KMS_GCP_KEY_RING` | yes | — |
| `VITAMINC_KMS_GCP_ENCRYPT_KEY` | no | `vitaminc-live-encrypt` |
| `VITAMINC_KMS_GCP_MAC_KEY` | no | `vitaminc-live-hmac-sha256` |
| `VITAMINC_KMS_GCP_EC_P256_KEY` | no | `vitaminc-live-ec-p256` |
| `VITAMINC_KMS_GCP_EC_P384_KEY` | no | `vitaminc-live-ec-p384` |
| `VITAMINC_KMS_GCP_RSA_PSS_KEY` | no | `vitaminc-live-rsa-pss` |
| `VITAMINC_KMS_GCP_RSA_PKCS1_KEY` | no | `vitaminc-live-rsa-pkcs1` |
| `VITAMINC_KMS_GCP_ED25519_KEY` | no | `vitaminc-live-ed25519` |

Keys (create them one time). The tests use **version 1** of each key, so do
not disable or destroy version 1:

```sh
L=global R=vitaminc-live
gcloud kms keyrings create $R --location $L
gcloud kms keys create vitaminc-live-encrypt     --keyring $R --location $L --purpose encryption
gcloud kms keys create vitaminc-live-hmac-sha256 --keyring $R --location $L --purpose mac \
  --default-algorithm hmac-sha256
gcloud kms keys create vitaminc-live-ec-p256     --keyring $R --location $L --purpose asymmetric-signing \
  --default-algorithm ec-sign-p256-sha256
gcloud kms keys create vitaminc-live-ec-p384     --keyring $R --location $L --purpose asymmetric-signing \
  --default-algorithm ec-sign-p384-sha384
gcloud kms keys create vitaminc-live-rsa-pss     --keyring $R --location $L --purpose asymmetric-signing \
  --default-algorithm rsa-sign-pss-2048-sha256
gcloud kms keys create vitaminc-live-rsa-pkcs1   --keyring $R --location $L --purpose asymmetric-signing \
  --default-algorithm rsa-sign-pkcs1-2048-sha256
gcloud kms keys create vitaminc-live-ed25519     --keyring $R --location $L --purpose asymmetric-signing \
  --default-algorithm ec-sign-ed25519
```

Permissions for the identity:

- `roles/cloudkms.cryptoKeyEncrypterDecrypter` on `vitaminc-live-encrypt`.
- `roles/cloudkms.signerVerifier` on the MAC key and the five signing keys.
  This role has `useToSign`, `useToVerify` and `viewPublicKey`.

Credentials: Application Default Credentials. The client finds them
itself.

```sh
gcloud auth application-default login
VITAMINC_KMS_LIVE_GCP=1 VITAMINC_KMS_GCP_PROJECT=<project> VITAMINC_KMS_GCP_LOCATION=global \
  VITAMINC_KMS_GCP_KEY_RING=vitaminc-live \
  cargo test -p vitaminc-kms --features gcp -- gcp::live_tests --nocapture
```

## CI

`.github/workflows/kms-live.yml` has one job for each backend. It runs on
`workflow_dispatch` and each Monday at 04:23 UTC. It does not run on pull
requests: a pull request from a fork gets no secrets, and a pull request
from this repository would use cloud quota and the cloud identities on code
that nobody has reviewed. Run it by hand before you merge a change to an
adapter.

A `gate` job reads the secrets and variables. A backend job runs only if
all of its secrets and variables are set, and the job summary tells which
backends it skipped and why. A job that runs sets the flag to `1`, so a
missing optional value uses its default, and a missing required value
fails the job.

| Job | Repository secrets | Repository variables |
|---|---|---|
| Vault Enterprise | `VAULT_LICENSE` | — |
| Azure Managed HSM | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` | `VITAMINC_KMS_AZURE_HSM_URL`; optional: `VITAMINC_KMS_AZURE_DATA_KEY`, `VITAMINC_KMS_AZURE_MAC_KEY`, `VITAMINC_KMS_AZURE_API_VERSION` |
| Google Cloud KMS | `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT` | `VITAMINC_KMS_GCP_PROJECT`, `VITAMINC_KMS_GCP_LOCATION`, `VITAMINC_KMS_GCP_KEY_RING`; optional: the `VITAMINC_KMS_GCP_*_KEY` names |

Neither cloud job uses a stored key or client secret. Both use the GitHub
OIDC token (`id-token: write`):

- **Azure**: `azure/login` with a federated credential on an Entra ID app
  registration. Set the credential subject to
  `repo:cipherstash/vitaminc:ref:refs/heads/main`. A manual run from another
  branch needs a credential for that branch. No subscription is selected,
  because the Managed HSM data plane needs none. Give the app's service
  principal the role in the Azure section above.
- **Google Cloud**: `google-github-actions/auth` with workload identity
  federation. Make a workload identity pool and an OIDC provider for
  `https://token.actions.githubusercontent.com`, with the attribute
  condition `assertion.repository == 'cipherstash/vitaminc'`. Give the
  principal `roles/iam.workloadIdentityUser` on the service account, and
  give the service account the roles in the Google Cloud section above.
  `GCP_WORKLOAD_IDENTITY_PROVIDER` is the full provider name
  (`projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`).
