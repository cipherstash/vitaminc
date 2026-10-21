//! The opt-in switch for the tests that talk to a real backend: Vault
//! Enterprise, Azure Managed HSM and Google Cloud KMS. No emulator covers
//! these paths, so the tests need credentials and resources that most
//! machines do not have. See `packages/kms/docs/live-tests.md`.
//!
//! Each backend has one flag, `VITAMINC_KMS_LIVE_<BACKEND>`:
//!
//! - Not set (or empty, `0`, `false`): the test prints one `skipped:` line
//!   and returns early. Rust has no runtime skip, so the test shows as
//!   passed; the line says why it did no work.
//! - `1` or `true`: every variable the backend requires must be set. If one
//!   is missing, the test **fails** and names it, so a CI job with a
//!   missing secret cannot pass by skipping.
//! - Any other value fails too, for the same reason.

use std::collections::BTreeMap;

/// A backend that only the live tests reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    #[cfg(feature = "vault")]
    VaultEnterprise,
    #[cfg(feature = "azure")]
    AzureManagedHsm,
    #[cfg(feature = "gcp")]
    GoogleCloudKms,
}

impl Backend {
    /// The flag that turns this backend's live tests on.
    pub(crate) const fn flag(self) -> &'static str {
        match self {
            #[cfg(feature = "vault")]
            Self::VaultEnterprise => "VITAMINC_KMS_LIVE_VAULT_ENTERPRISE",
            #[cfg(feature = "azure")]
            Self::AzureManagedHsm => "VITAMINC_KMS_LIVE_AZURE",
            #[cfg(feature = "gcp")]
            Self::GoogleCloudKms => "VITAMINC_KMS_LIVE_GCP",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            #[cfg(feature = "vault")]
            Self::VaultEnterprise => "Vault Enterprise",
            #[cfg(feature = "azure")]
            Self::AzureManagedHsm => "Azure Managed HSM",
            #[cfg(feature = "gcp")]
            Self::GoogleCloudKms => "Google Cloud KMS",
        }
    }
}

/// The variables of one enabled backend, read once.
#[derive(Debug)]
pub(crate) struct LiveEnv {
    values: BTreeMap<&'static str, String>,
}

impl LiveEnv {
    /// A variable that [`enabled`] was told is required. It is always set.
    pub(crate) fn required(&self, name: &'static str) -> &str {
        self.values
            .get(name)
            .unwrap_or_else(|| panic!("{name} is not in the list of required variables"))
    }

    /// A variable that [`enabled`] was told is optional, or `default`.
    pub(crate) fn optional<'a>(&'a self, name: &'static str, default: &'a str) -> &'a str {
        self.values.get(name).map_or(default, String::as_str)
    }
}

/// The variables of `backend` when its live tests are on, or `None` (after
/// one `skipped:` line on stderr) when they are off. `test` names the test
/// in that line.
///
/// # Panics
///
/// When the flag is on and a `required` variable is missing or empty, or
/// when the flag has a value that is not on or off.
pub(crate) fn enabled(
    backend: Backend,
    test: &str,
    required: &[&'static str],
    optional: &[&'static str],
) -> Option<LiveEnv> {
    let env = configured(backend, required, optional);
    if env.is_none() {
        eprintln!(
            "skipped: {test} needs {}; set {}=1 to run it (see packages/kms/docs/live-tests.md)",
            backend.description(),
            backend.flag(),
        );
    }
    env
}

/// [`enabled`] with no `skipped:` line, for a caller that has something
/// else to do when the backend is off.
///
/// # Panics
///
/// As [`enabled`].
pub(crate) fn configured(
    backend: Backend,
    required: &[&'static str],
    optional: &[&'static str],
) -> Option<LiveEnv> {
    resolve(backend, required, optional, |name| std::env::var(name).ok())
        .unwrap_or_else(|message| panic!("{message}"))
}

/// [`enabled`] without the process environment, so the decision itself is
/// testable.
fn resolve(
    backend: Backend,
    required: &[&'static str],
    optional: &[&'static str],
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<LiveEnv>, String> {
    let flag = backend.flag();
    match lookup(flag).as_deref().map(str::trim) {
        None | Some("" | "0" | "false") => return Ok(None),
        Some("1" | "true") => {}
        Some(other) => {
            return Err(format!(
                "{flag}={other:?} is not a valid value; set it to 1 to run the {} tests, \
                 or unset it to skip them",
                backend.description()
            ))
        }
    }

    let set = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());

    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|name| set(name).is_none())
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "{flag} is set, but these variables are not: {}. Set them, or unset {flag} \
             to skip the {} tests (see packages/kms/docs/live-tests.md)",
            missing.join(", "),
            backend.description()
        ));
    }

    let values = required
        .iter()
        .chain(optional)
        .filter_map(|&name| set(name).map(|value| (name, value)))
        .collect();
    Ok(Some(LiveEnv { values }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Any one backend serves: the decision is the same for each.
    fn backend() -> Backend {
        #[cfg(feature = "vault")]
        return Backend::VaultEnterprise;
        #[cfg(all(feature = "azure", not(feature = "vault")))]
        return Backend::AzureManagedHsm;
        #[cfg(all(feature = "gcp", not(any(feature = "vault", feature = "azure"))))]
        return Backend::GoogleCloudKms;
    }

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| vars.get(name).cloned()
    }

    const REQUIRED: &[&str] = &["VITAMINC_KMS_TEST_A", "VITAMINC_KMS_TEST_B"];
    const OPTIONAL: &[&str] = &["VITAMINC_KMS_TEST_C"];

    #[test]
    fn no_flag_skips_even_when_the_other_variables_are_set() {
        let env = lookup(&[("VITAMINC_KMS_TEST_A", "a"), ("VITAMINC_KMS_TEST_B", "b")]);

        assert!(resolve(backend(), REQUIRED, OPTIONAL, env)
            .unwrap()
            .is_none());
    }

    #[test]
    fn an_off_flag_skips() {
        for off in ["", "0", "false", " 0 "] {
            let env = lookup(&[(backend().flag(), off)]);
            assert!(
                resolve(backend(), REQUIRED, OPTIONAL, env)
                    .unwrap()
                    .is_none(),
                "{off:?}"
            );
        }
    }

    #[test]
    fn an_on_flag_with_every_variable_runs() {
        for on in ["1", "true"] {
            let env = lookup(&[
                (backend().flag(), on),
                ("VITAMINC_KMS_TEST_A", "a"),
                ("VITAMINC_KMS_TEST_B", "b"),
            ]);

            let env = resolve(backend(), REQUIRED, OPTIONAL, env)
                .unwrap()
                .expect("an on flag must run the tests");
            assert_eq!(env.required("VITAMINC_KMS_TEST_A"), "a");
            assert_eq!(env.optional("VITAMINC_KMS_TEST_C", "default"), "default");
        }
    }

    #[test]
    fn an_on_flag_with_a_missing_variable_fails_and_names_it() {
        let env = lookup(&[
            (backend().flag(), "1"),
            ("VITAMINC_KMS_TEST_A", "a"),
            // Empty is the same as missing: an unset secret in GitHub
            // Actions arrives as an empty string.
            ("VITAMINC_KMS_TEST_B", ""),
        ]);

        let message = resolve(backend(), REQUIRED, OPTIONAL, env).unwrap_err();

        assert!(message.contains("VITAMINC_KMS_TEST_B"), "{message}");
        assert!(!message.contains("VITAMINC_KMS_TEST_A"), "{message}");
        assert!(message.contains(backend().flag()), "{message}");
    }

    #[test]
    fn a_flag_that_is_neither_on_nor_off_fails() {
        let env = lookup(&[(backend().flag(), "yes")]);

        let message = resolve(backend(), REQUIRED, OPTIONAL, env).unwrap_err();

        assert!(message.contains("\"yes\""), "{message}");
    }

    #[test]
    fn an_optional_variable_that_is_set_wins_over_the_default() {
        let env = lookup(&[
            (backend().flag(), "1"),
            ("VITAMINC_KMS_TEST_A", "a"),
            ("VITAMINC_KMS_TEST_B", "b"),
            ("VITAMINC_KMS_TEST_C", "c"),
        ]);

        let env = resolve(backend(), REQUIRED, OPTIONAL, env)
            .unwrap()
            .unwrap();
        assert_eq!(env.optional("VITAMINC_KMS_TEST_C", "default"), "c");
    }
}
