# Security Policy

CipherStash takes the security of our software, infrastructure, and customers extremely seriously.
This document describes the security posture and reporting process for the Vitamin C crates.

## Supported Versions

This repository publishes the `vitaminc` facade crate and its sub-crates (`vitaminc-aead`, `vitaminc-async-traits`, `vitaminc-encrypt`, `vitaminc-kms`, `vitaminc-password`, `vitaminc-permutation`, `vitaminc-protected`, `vitaminc-random`, `vitaminc-traits`, and the internal derive crates).

**Security fixes are released for the latest release line of each crate.** Security reports are welcome for any version, but fixes land in the latest release — if you are on an older version, plan to upgrade to receive them.

Note that these crates are pre-1.0: APIs may change between releases, and some functionality is explicitly marked as work-in-progress in the individual crate READMEs.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in any CipherStash code, service, or dependency:

📧 **Please email: `security@cipherstash.com`**

We request that you **do not publicly disclose** the issue before we have had a chance to investigate and provide a fix.

When reporting, please include (as applicable):

- Description of the vulnerability
- Steps to reproduce or proof-of-concept
- Impact assessment or potential misuse
- Any relevant logs, tool output, or screenshots
- Suggested remediation (if you have one)

We will acknowledge receipt within **48 hours** and provide regular updates until the issue is resolved.

## Disclosure & Response Policy

CipherStash follows a **coordinated responsible disclosure** process:

1. **Submit report** privately via `security@cipherstash.com`.
2. **Acknowledgement** within 48 hours.
3. **Assessment** of severity using CVSS and internal risk models.
4. **Fix development** and patch release in a private branch.
5. **Coordinated disclosure**, including:
   - New patch release(s)
   - Security advisory on GitHub
   - Credit to reporter (optional)

We will never take legal action against good-faith security researchers who follow this policy.

## Scope

The following are **in scope**:

- The `cipherstash/vitaminc` GitHub repository and all crates published from it
- Cryptographic correctness issues: timing side-channels, missing zeroization, nonce misuse, backend divergence between the native and wasm AES implementations
- Documentation or code examples that could lead to insecure usage
- CipherStash's internal infrastructure and other CipherStash products

The following are **out of scope**:

- Social engineering, physical attacks, or denial-of-service
- Attacks requiring privileged access to developer machines or CI/CD infrastructure

## Questions?

For general questions about CipherStash security practices (not security incidents), contact:

📧 **support@cipherstash.com**

For vulnerability disclosures:

📧 **security@cipherstash.com**

---

Thank you for helping keep the CipherStash ecosystem secure.
