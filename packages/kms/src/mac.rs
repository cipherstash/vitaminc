use vitaminc_protected::Protected;

#[allow(async_fn_in_trait)]
pub trait GenerateMac<const N: usize> {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn generate_mac(&self, message: &Protected<Vec<u8>>) -> Result<[u8; N], Self::Error>;
}

/// Returns `Ok(false)` for "didn't verify," never an error — `Self::Error`
/// is reserved for genuine infrastructure failures. Reconciles a real
/// four-way vendor split: AWS throws on a bad MAC (`KMSInvalidMacException`,
/// never returns `false`); Azure and Vault return a plain boolean, even
/// for malformed input; GCP returns a boolean as data too, plus a
/// second-order `verifiedSuccessIntegrity` flag guarding the verdict's own
/// transit integrity, which an adapter must resolve internally (e.g. via
/// retry) before ever returning to the caller.
#[allow(async_fn_in_trait)]
pub trait VerifyMac<const N: usize> {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn verify_mac(
        &self,
        message: &Protected<Vec<u8>>,
        mac: &[u8; N],
    ) -> Result<bool, Self::Error>;
}
