//! Names for the locals and parameters a derive introduces.
//!
//! The generated impls carry the input's generics and expand in the caller's
//! module, and a derive cannot see that module's items. Two things can then
//! capture a generated binding (a `fn` parameter, a `let` or a match binding)
//! and turn it into a pattern against something else, which fails to compile:
//!
//! - a const parameter of the input, which is in scope in every impl body;
//! - a unit struct, tuple struct or constant in the caller's scope.
//!
//! [`Locals`] handles both. It never hands out a name that appears as an
//! identifier anywhere in the input, which covers the const parameters, and it
//! records every name it hands out so the derive can declare a dummy `fn` of
//! the same name ([`Locals::param_shadows`], [`Locals::body_shadows`]). A
//! dummy `fn` shadows a same-named item in the value namespace, and a binding
//! may shadow a `fn`, so the binding stays a binding.
//!
//! A dummy also captures any value path of its name in the scope it is
//! declared in, so where each kind goes matters:
//!
//! - Body locals ([`Locals::scope`]) get their dummies as items at the top of
//!   the fn body that binds them. Items in a body are visible only inside that
//!   body, so these dummies cannot reach the impl header, the where clause or
//!   the generated bounds.
//! - Fn parameters ([`Locals::param`]) are resolved outside the body, so
//!   their dummies go in the `const _: () = { ... };` block that wraps the
//!   impls, where the impl headers and bounds see them too. The only value
//!   paths there come from the input's own tokens (const generic arguments and
//!   array lengths in field types and the where clause), and no generated name
//!   appears in those tokens, so nothing written in the input is captured.
//!   A value path produced by a macro call inside the input (`[T; m!()]`) is
//!   not visible to the derive and is not covered.
//!
//! A parameter name is reserved for the rest of the expansion, so no body
//! local, whose dummy would shadow the parameter inside the body, can reuse it.
//! Type-namespace lookups (types, traits, the input's own ident) are never
//! affected by a dummy `fn`.

use std::collections::BTreeSet;

use proc_macro2::{Span, TokenStream, TokenTree};
use quote::{format_ident, quote, ToTokens};
use syn::{ext::IdentExt, DeriveInput};

/// Hands out collision-free names for one derive expansion.
pub struct Locals {
    /// Names no new local may take: every identifier in the input, plus every
    /// parameter name handed out so far.
    reserved: BTreeSet<String>,
    /// Parameter names handed out, each of which needs a dummy in the
    /// enclosing `const _` block.
    params: BTreeSet<String>,
    /// Body local names handed out since the last [`Locals::body_shadows`].
    body: BTreeSet<String>,
}

impl Locals {
    pub fn new(input: &DeriveInput) -> Self {
        let mut reserved = BTreeSet::new();
        collect_idents(input.to_token_stream(), &mut reserved);
        Self {
            reserved,
            params: BTreeSet::new(),
            body: BTreeSet::new(),
        }
    }

    /// A name for a fn parameter: `preferred`, or `preferred_N` if that is
    /// reserved. The name is reserved for the rest of the expansion.
    pub fn param(&mut self, preferred: &str, span: Span) -> syn::Ident {
        let ident = self.pick(preferred, span, &BTreeSet::new());
        self.reserved.insert(ident.to_string());
        self.params.insert(ident.to_string());
        ident
    }

    /// A scope for body locals that cannot see each other's bindings, such as
    /// one match arm. Names only have to be unique within a scope.
    pub fn scope(&mut self) -> Scope<'_> {
        Scope {
            locals: self,
            taken: BTreeSet::new(),
        }
    }

    /// Dummies for the parameter names, for the `const _` block around the
    /// impls.
    pub fn param_shadows(&self) -> TokenStream {
        shadows(&self.params)
    }

    /// Dummies for the body locals handed out since the last call, for the top
    /// of the fn body that binds them.
    pub fn body_shadows(&mut self) -> TokenStream {
        shadows(&std::mem::take(&mut self.body))
    }

    fn pick(&self, preferred: &str, span: Span, taken: &BTreeSet<String>) -> syn::Ident {
        let mut name = preferred.to_owned();
        let mut suffix = 0;
        while self.reserved.contains(&name) || taken.contains(&name) {
            suffix += 1;
            name = format!("{preferred}_{suffix}");
        }
        format_ident!("{}", name, span = span)
    }
}

pub struct Scope<'a> {
    locals: &'a mut Locals,
    taken: BTreeSet<String>,
}

impl Scope<'_> {
    /// A name for a body local: `preferred`, or `preferred_N` if that is
    /// reserved or already taken in this scope.
    pub fn bind(&mut self, preferred: &str, span: Span) -> syn::Ident {
        let ident = self.locals.pick(preferred, span, &self.taken);
        self.taken.insert(ident.to_string());
        self.locals.body.insert(ident.to_string());
        ident
    }
}

fn shadows(names: &BTreeSet<String>) -> TokenStream {
    let names = names.iter().map(|name| format_ident!("{}", name));
    quote! { #( #[allow(dead_code, non_snake_case)] fn #names() {} )* }
}

/// Every identifier in `tokens` that can name a value. Lifetimes (`'a`) live
/// in their own namespace and are skipped.
fn collect_idents(tokens: TokenStream, out: &mut BTreeSet<String>) {
    let mut after_quote = false;
    for tt in tokens {
        let is_quote = matches!(&tt, TokenTree::Punct(p) if p.as_char() == '\'');
        match tt {
            TokenTree::Ident(id) if !after_quote => {
                out.insert(id.unraw().to_string());
            }
            TokenTree::Group(g) => collect_idents(g.stream(), out),
            _ => {}
        }
        after_quote = is_quote;
    }
}
