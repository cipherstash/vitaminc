use async_trait::async_trait;
use vitaminc_protected::Paranoid;

#[async_trait]
pub trait AsyncMac {
    type Output: Paranoid;
    type Error;

    async fn finalize_async(self) -> Result<Self::Output, Self::Error>;
}
