//! Every Rust block in the agent skills under `.claude/skills`, compiled and run
//! as a doctest against the workspace crates. Agents copy these examples as
//! written, so an API change that breaks one fails `cargo test` here rather than
//! shipping a recipe that no longer compiles.
//!
//! Each skill file is one module below. A new skill file with Rust blocks gets a
//! module of its own.

#[doc = include_str!("../../../.claude/skills/misuse-resistance/SKILL.md")]
pub mod misuse_resistance {}

#[doc = include_str!("../../../.claude/skills/misuse-resistance/RUST.md")]
pub mod misuse_resistance_rust {}

#[doc = include_str!("../../../.claude/skills/vitaminc/SKILL.md")]
pub mod vitaminc {}

#[doc = include_str!("../../../.claude/skills/vitaminc/RECIPES.md")]
pub mod vitaminc_recipes {}
