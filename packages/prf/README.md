# vitaminc-prf

`vitaminc-prf` provides a serde-style API for deriving structured,
domain-separated pseudorandom values. Inputs cross backend boundaries in
`Protected` containers, maps bind their keys into the derivation context, and
backend output is always awaitable so local and remote batched implementations
share one interface.

```rust
use vitaminc_prf::{HmacSha256Prf, PrfValue};
use vitaminc_protected::Protected;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let prf = HmacSha256Prf::new(Protected::new(vec![7; 32]));
let term = "alice@example.com".prf(prf).await?;
assert_eq!(term.len(), 32);
# Ok(())
# }
```
