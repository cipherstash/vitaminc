use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod opaque_debug;
mod timing_safe;

#[proc_macro_derive(OpaqueDebug, attributes(opaque_debug, non_sensitive))]
pub fn derive_opaque_debug(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    opaque_debug::derive_opaque_debug(input)
}

#[proc_macro_derive(TimingSafeEq)]
pub fn derive_timing_safe(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    timing_safe::derive_timing_safe(input)
}
