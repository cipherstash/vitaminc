// `HmacSha256Prf` owns its key and wipes it when it drops. A `Clone` impl
// would either copy the key or share it behind a hidden `Arc`, and either
// way "wiped when this PRF drops" stops being true. Share with an explicit
// `Arc<HmacSha256Prf>` instead, so the sharing is visible at the call site.
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::PrfKeyInit;
use vitaminc_protected::Protected;

fn main() {
    let prf = HmacSha256Prf::new(Protected::new([7_u8; 32]));
    let _copy = prf.clone();
}
