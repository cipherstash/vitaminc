# Misuse resistance: research notes

Research base for a misuse-resistance skill (or two) in this repo. Starts from the sources Lindsay Holmwood cited at linux.conf.au 2022, then widens to the rest of the field. Each finding ends with what it implies for API design, so the skill can cite evidence for its rules rather than assert them.

## The talk

**Footguns and factorisation: how to make users of your cryptographic library successful.** Lindsay Holmwood, linux.conf.au 2022, 16 January 2022 (online).

- Video: https://www.youtube.com/watch?v=raCRgJJvyRY
- Slides: https://speakerdeck.com/auxesis/footguns-and-factorisation-how-to-make-users-of-your-cryptographic-library-successful
- Abstract: https://linux.conf.au/schedule/presentation/49/

The talk's closing takeaways:

1. Developers focus on functionality first and performance second, and do not prioritise security. Library authors have to do the hard work up front.
2. Help developers prioritise security with targeted warnings, with frictionless misuse-resistant APIs that work and are secure, and with copious secure code examples.
3. Most security bugs happen on the periphery of a cryptography library, inside the applications that use it.

Two audience questions were left open and are worth carrying into the skill. Lindsay said he had no good answer for improving an API while keeping compatibility (beyond warnings plus a smooth upgrade path, as Keyczar to Tink did). He also said research on whether static types help secure API usage exists but is "contradictory", and never followed up on it publicly.

## Sources cited in the talk

### Developers do not think about security unless primed

Oliveira, D., Rosenthal, M., Morin, N., Yeh, K. C., Cappos, J., & Zhuang, Y. (2014). *It's the psychology stupid: how heuristics explain software vulnerabilities and how priming can illuminate developer's blind spots.* ACSAC 2014, pp. 296–305.

- Developers were shown six vulnerable snippets (buffer overflow, TLS setup, XSS, TOCTOU, SQL injection, brute-force exhaustion) under three conditions: control, primed ("could a developer experience unexpected results?"), and explicit ("this code has a vulnerability").
- Primed developers found security problems at almost twice the rate of unprimed ones.
- Security is not part of the heuristics developers use day to day. They focus on functionality and performance.
- The authors recommend that tools developers already use (IDEs, editors, compilers, static analysis) prime developers on the spot, while they are coding.

*Implication:* do not rely on developers knowing or remembering security rules. Put the signal where the code is written: in types, compile errors and warnings.

### Stack Overflow gives functional, insecure code

Acar, Y., Backes, M., Fahl, S., Kim, D., Mazurek, M. L., & Stransky, C. (2016). *You get where you're looking for: The impact of information sources on code security.* IEEE S&P 2016, pp. 289–305.

- Android developers did four security tasks, each group restricted to one source: Stack Overflow, official docs, books, or free choice.
- Stack Overflow and books gave the highest functional success. Official docs alone gave the lowest, but the most secure results.
- Security success was low (about 38–40%) on secure networking, inter-component communication and storage. Developers rated their own insecure solutions as secure.
- The authors recommend documentation that combines the usefulness of Q&A forums with the security awareness of books and official docs.

*Implication:* official docs must answer task-shaped questions ("how do I store a key?") with copyable code, or developers go elsewhere. Maintainers should mine Stack Overflow (and now LLM transcripts) for questions their docs fail to answer.

### Search ranking pushes insecure code up

Fischer, F., Stachelscheid, Y., & Grossklags, J. (2021). *The effect of Google search on software security: Unobtrusive security interventions via content re-ranking.* ACM CCS 2021, pp. 3070–3084.

- There is at least a 22.8% chance that one of the top three Google results for a crypto question leads to insecure Stack Overflow code, and insecure results get more clicks.
- Re-ranking results by security made participants submit code that was both more secure and more functional, with no change in developer behaviour.

*Implication:* interventions that require no behaviour change work best. The analogue for a library is making the default path the secure path, so a developer who does nothing special gets the secure result.

### Most crypto bugs are in the code that calls the library

Lazar, D., Chen, H., Wang, X., & Zeldovich, N. (2014). *Why does cryptographic software fail? A case study and open problems.* APSys 2014, pp. 1–7.

- Analysed 269 CVEs tagged as cryptographic issues (CWE-310), 2011 to 2014, by impact (plaintext disclosure, man-in-the-middle, brute force, side channel) and layer (primitive, protocol, application).
- 83% of the bugs came from applications misusing crypto libraries; 17% were in the libraries themselves.
- Application-layer bugs accounted for all plaintext disclosures, 86% of man-in-the-middle and 79% of brute-force issues. Side channels occurred only in primitives and protocols.

*Implication:* the API surface is where security is won or lost. A correct primitive behind a misusable interface still produces insecure systems.

### Simplified APIs are more secure, but not enough on their own

Acar, Y., Backes, M., Fahl, S., Garfinkel, S., Kim, D., Mazurek, M. L., & Stransky, C. (2017). *Comparing the usability of cryptographic APIs.* IEEE S&P 2017, pp. 154–171.

The talk's centrepiece, and the paper Lindsay recommended reading if you read only one.

- 256 Python developers did symmetric (key generation, encrypt/decrypt) and asymmetric (key generation, encrypt/decrypt, certificate validation) tasks with one of cryptography.io, Keyczar, PyNaCl, M2Crypto or PyCrypto, using only that library's docs.
- Libraries with simplified interfaces (the first three explicitly aim for usability) produced more secure results. Keyczar solutions were far more likely to be secure, but few were functional at all.
- About 20% of functional solutions were insecure, yet their authors believed they were secure.
- Python experience, security background and library experience did not predict success.
- Code copied from Stack Overflow was about three times more likely to be functional on symmetric tasks.
- The calls into the library were generally secure. Failures came from **peripheral features** the library left to the caller: key storage, password-based key derivation, and insecure inputs copied from examples. Developers lacked the knowledge to see the danger in those inputs.
- Documentation quality and the availability of working examples for peripheral tasks made or broke secure use.

*Implication:* misuse resistance must cover the whole task, not just the core call. Identify what callers implicitly depend on (key generation, key storage, randomness, nonce handling, comparisons, encoding) and either wrap it in the library with secure types or document it exhaustively. Every example in the docs must be secure. A comment saying "insecure, do not use" above an example does not stop people copying it.

### Warnings in the API double secure outcomes

Gorski, P. L., Lo Iacono, L., Wermke, D., Stransky, C., Möller, S., Acar, Y., & Fahl, S. (2018). *Developers deserve security warnings, too: On the effect of integrated security advice on cryptographic API misuse.* SOUPS 2018, pp. 265–281.

- Python developers did symmetric key generation, encryption and key storage with either stock PyCrypto or a patched version that printed a warning when an insecure primitive or parameter was used.
- Functional success was the same in both groups. Secure-and-functional success nearly doubled with warnings.
- Developers whose code triggered a warning were 15 times more likely to convert it to a secure solution.
- Participants rated both versions equally usable.

*Implication:* changing the ergonomics improves security even when the API shape cannot change. This is the priming result from Oliveira et al. delivered at the point of use.

Gorski, P. L., Acar, Y., Lo Iacono, L., & Fahl, S. (2020). *Listen to developers! A participatory design study on security warnings for cryptographic APIs.* CHI 2020, pp. 1–13.

- Focus groups with 25 professional developers designed console warnings for crypto APIs.
- Five elements: message classification, title, code location, link to an external resource, and colour.
- Developers want concise messages with detail linked externally, and context-dependent detail.

*Implication:* a warning or error should name the problem, point at the code, and link to a page that explains the secure alternative. Provide an obvious (not easy) way to opt out, because some callers are forced into legacy parameters by systems they do not control.

### Further reading listed in the slides

- Oliveira, D. S., Lin, T., Rahman, M. S., et al. (2018). *API blindspots: Why experienced developers write vulnerable code.* SOUPS 2018. Java APIs with "blindspots" (misleading names, hidden preconditions) reduced developers' ability to spot vulnerabilities, regardless of experience.
- Brun, Y., Lin, T., Somerville, J. E., Myers, E. M., & Ebner, N. (2023). *Blindspots in Python and Java APIs result in vulnerable code.* ACM TOSEM. Replication with 129 more developers and 22 Python APIs. The effect held in both languages and was stronger in Python. Long-time professionals made as many mistakes as novices. Lindsay pointed to these two papers when asked what the common developer mistakes are: mostly insecure inputs, copied from examples.
- Vance, A., et al. (2018). *What do we really know about how habituation to warnings occurs over time? A longitudinal fMRI study of habituation and polymorphic warnings.* CHI 2018. Repeated identical warnings stop being processed; varying them slows habituation. Relevant to how noisy warnings should be.
- Lo Iacono, L., & Gorski, P. L. (2017). *I do and I understand. Not yet true for security APIs. So sad.* EuroUSEC 2017.
- Mindermann, K., Keck, P., & Wagner, S. (2018). *How usable are Rust cryptography APIs?* IEEE QRS 2018, pp. 143–154. Only about half of the major Rust crypto libraries explicitly aimed at usability and misuse resistance. In a 28-student experiment, participants did better with rust-crypto than with ring, which the authors had expected to be more usable. Recommends better docs, higher-level wrappers over low-level libraries, and better examples.
- Blessing, J., Specter, M. A., & Weitzner, D. J. (2021). *You really shouldn't roll your own crypto: An empirical study of vulnerabilities in cryptographic libraries.* arXiv:2107.04940. Across eight libraries, only 27.2% of vulnerabilities were cryptographic issues and 37.2% were memory safety issues. Complexity correlated strongly with insecurity. (Lindsay referred to this as a 2011 paper in the talk; it is 2021.)

## Wider research

### Measuring misuse in the wild

- Egele, M., Brumley, D., Fratantonio, Y., & Kruegel, C. (2013). *An empirical study of cryptographic misuse in Android applications.* ACM CCS 2013. 10,327 of 11,748 apps (88%) made at least one mistake, such as ECB mode, constant IVs, constant keys or low PBKDF iteration counts.
- Nadi, S., Krüger, S., Mezini, M., & Bodden, E. (2016). *Jumping through hoops: Why do Java developers struggle with cryptography APIs?* ICSE 2016. Developers were confident choosing concepts (encryption vs signatures) but found the APIs too low-level, and wanted task-based APIs that hide algorithm choices.
- Fischer, F., Böttinger, K., Xiao, H., Stransky, C., Acar, Y., Backes, M., & Fahl, S. (2017). *Stack Overflow considered harmful? The impact of copy&paste on Android application security.* IEEE S&P 2017. Insecure crypto snippets from Stack Overflow were found copied into a large share of Play Store apps.
- Georgiev, M., et al. (2012). *The most dangerous code in the world: Validating SSL certificates in non-browser software.* ACM CCS 2012. Certificate validation was broken in many applications because the libraries exposed confusing options with unsafe defaults.
- Patnaik, N., Hallett, J., & Rashid, A. (2019). *Usability smells: An analysis of developers' struggle with crypto libraries.* SOUPS 2019. Analysed about 2,400 Stack Overflow questions on seven libraries, mapped the issues to Green and Smith's principles, and named four "usability smells" where the principles are not observed.
- Hazhirpasand, M., Nierstrasz, O., & Ghafari, M. (2021). *Dazed and confused: What's wrong with crypto libraries?* PST 2021.

### Design principles

- Green, M., & Smith, M. (2016). *Developers are not the enemy! The need for usable security APIs.* IEEE Security & Privacy 14(5), pp. 40–46. Ten principles for usable security APIs, including: integrate crypto into standard APIs so most developers never touch crypto APIs; be powerful enough for non-security needs too; be easy to learn without crypto expertise; do not break the developer's mental model; be usable without documentation; be hard to misuse, with incorrect use producing visible errors; make defaults safe and never ambiguous. The full list is in the paper and should be checked against the original before the skill quotes it.
- Rusty Russell's "hard to misuse" scale (Ottawa Linux Symposium keynote, 2003; blog posts 2008). Ranks interfaces from "impossible to get wrong" and "compiler/linker won't let you get it wrong" at the top, down through "simplest use is correct", "name tells you how to use it", and "do it right or it breaks at runtime", to "the obvious use is wrong" at the bottom. The point is that "hard to misuse" is a stronger goal than "easy to use". Summary: https://technovelty.org/badcode/rusty-russells-hard-to-misuse-rules.html
- Bernstein, D. J., Lange, T., & Schwabe, P. (2012). *The security impact of a new cryptographic library.* LATINCRYPT 2012. The design rationale for NaCl: one high-level `crypto_box` call with no algorithm choices, no data-dependent branches or indices on secrets, and no padding oracles by construction.
- Rogaway, P., & Shrimpton, T. (2006). *A provable-security treatment of the key-wrap problem.* EUROCRYPT 2006. Introduces misuse-resistant authenticated encryption (SIV), the origin of the term in cryptography: nonce reuse degrades gracefully instead of failing catastrophically. See also RFC 8452 (AES-GCM-SIV).
- Len, J., Grubbs, P., & Ristenpart, T. (2021). *Partitioning oracle attacks.* USENIX Security 2021. A decryption error that distinguishes a wrong key from other failures lets an attacker test many candidate keys per query, recovering passwords from non-committing AEADs. Behind rule 7: errors reveal nothing.
- Albertini, A., Duong, T., Gueron, S., Kölbl, S., Luykx, A., & Schmieg, S. (2022). *How to abuse and fix authenticated encryption without key commitment.* USENIX Security 2022. A different kind of misuse: callers assume AEAD properties (key commitment) that the primitive does not give. The API must not let callers believe in guarantees it lacks.
- Type-driven design outside the crypto literature: Yaron Minsky's "make illegal states unrepresentable", and Alexis King's "Parse, don't validate" (2019). These are the language-level tools for climbing Rusty Russell's scale: newtypes, typestate, sealed traits, and constructors that are the only way to obtain a valid value.

### Tooling

- Krüger, S., Späth, J., Ali, K., Bodden, E., & Mezini, M. (2018/2021). *CrySL: An extensible approach to validating the correct usage of cryptographic APIs.* ECOOP 2018 / IEEE TSE 2021. Specification language and static analysis (CogniCrypt) for crypto API rules. Shows how much of the rule set a library could encode in its types instead.
- Kafader, S., & Ghafari, M. (2021). *FluentCrypto: Cryptography in easy mode.* ICSME 2021. A task-based fluent API over Node's crypto module.
- Zhang, Y., et al. *Automatic detection of Java cryptographic API misuses: Are we there yet?* No single detector was best, and developers rejected detector reports more often than they accepted them. Evidence for preventing misuse in the API rather than detecting it afterwards.

### AI assistants and LLM-generated code

Directly relevant because the skill's readers include agents, and agents now write much of the code that calls crypto libraries.

- Perry, N., Srivastava, M., Kumar, D., & Boneh, D. (2023). *Do users write more insecure code with AI assistants?* ACM CCS 2023. Participants with an AI assistant wrote significantly less secure code, including for string encryption, and were more likely to believe it was secure. This is the Acar et al. confidence gap, now amplified.
- *An investigation into misuse of Java security APIs by large language models.* ASIACCS 2024 (arXiv:2404.03823). ChatGPT-generated code misused Java security APIs frequently.
- Elsayed, M., Fulton, K., & Yang, J. (2026). *An empirical security evaluation of LLM-generated cryptographic Rust code.* EASE 2026 workshop (arXiv:2604.27001). 240 Rust samples for AES-256-GCM and ChaCha20-Poly1305 from three models. Only 23.3% compiled. A crypto-specific analyser flagged vulnerabilities in 57% of the compiled samples. Systematic failures were nonce reuse and hallucinated APIs. General-purpose tools (CodeQL) missed the AEAD misuses.
- LLMs as misuse detectors: *Beyond static pattern matching? Rethinking automatic cryptographic API misuse detection in the era of LLMs* (ISSTA 2025, arXiv:2407.16576). Raw LLM reports were over half false positives; constrained scope plus self-validation reached about 90% detection.

*Implication:* models reproduce the same footguns humans do, add hallucinated APIs, and are confidently wrong. Two consequences for this project. First, misuse resistance in types matters more, because the compiler is the one reviewer an agent cannot talk past. Second, a skill is a priming intervention in the Oliveira sense: it puts security context in front of the agent at the moment it writes code.

## Distilled principles

Each principle names its evidence. These are candidates for the skill's rules.

1. **Make the secure path the default and the shortest path.** Developers optimise for "it works". No-behaviour-change interventions work best. (Oliveira 2014; Fischer 2021; Green & Smith 2016)
2. **Climb the hard-to-misuse scale: compile error over runtime error over warning over documentation.** Prefer "won't compile" to "breaks at runtime" to "warns" to "documented". (Russell; Green & Smith "incorrect use produces visible errors")
3. **Own the periphery.** Key generation, key storage, randomness, nonces, password-based derivation, comparison and encoding are where real systems fail. Provide them, typed, in the library. (Acar 2017; Lazar 2014)
4. **Offer tasks, not primitives.** No algorithm, mode, IV or padding choices at the call site unless the caller genuinely needs them. (Nadi 2016; Bernstein 2012)
5. **Do not let callers believe in guarantees the API lacks.** Name and type things for what they actually promise. (API blindspots: Oliveira 2018, Brun 2023; Albertini 2022)
6. **Warn at the point of use, with an obvious but effortful escape hatch.** Name the problem, locate it, link to the fix. Avoid habituation from noisy repeated warnings. (Gorski 2018, 2020; Vance 2018)
7. **Every example is secure, complete, and copyable.** Developers and models copy examples verbatim, including their inputs. (Acar 2016, 2017; Fischer 2017)
8. **Do not trust self-assessed security, human or model.** Verify with tests, test vectors and review. (Acar 2016, 2017; Perry 2023; Elsayed 2026)
9. **Keep it small.** Complexity correlates with vulnerabilities. (Blessing 2021)
10. **Evolve with warnings and a smooth migration path.** Breaking changes are acceptable if the upgrade path is smooth (Keyczar to Tink). (Holmwood 2022 Q&A)

## Where vitaminc already applies these

Snapshot from the crate READMEs, October 2026. Check the code before the skill relies on it.

| Principle | vitaminc today |
|---|---|
| Own the periphery: secret handling | `vitaminc-protected`: `Protected<T>` zeroizes on drop, keeps secrets out of `Debug`, constrains comparison and serialisation |
| Own the periphery: randomness | `vitaminc-random`: `SafeRand` and the `Generatable` derive |
| Own the periphery: passwords | `vitaminc-password`: compile-time length, `Protected` storage, no heap until converted |
| Own the periphery: nonces | `vitaminc-encrypt`: automatic random nonce per encryption; 256-bit keys only |
| Compile error over runtime error | `vitaminc-hmac`: `new` takes `Protected<[u8; 32]>`, so key length is guaranteed by the type and construction cannot fail; runtime-length keys go through a separate fallible `try_from_bytes` |
| No guarantees the API lacks | `vitaminc-context`: one encoding for AAD and PRF context, equal by construction because the views are blanket impls that cannot be hand-written |
| Tasks, not primitives | `vitaminc-aead`: describe a value once as `Encrypt` and walk it into a `Sink`; structural binding rules live once in the sink, not in each caller |
| Typed outputs | `vitaminc-ore` / `vitaminc-normalize`: sealed `OrderPlaintext` only the crate can build; frozen domain labels so values that only look alike do not collide |
| Sensitivity in traits | `vitaminc-traits`: inputs and outputs typed so sensitivity can be reasoned about; all types bound by `Controlled` |

Gaps worth checking against the principles: runtime warnings (principle 6) do not appear to be used anywhere, and whether examples in every README and doc comment meet principle 7 has not been audited.

## Follow-up: replicate Acar et al. 2017 with agents

Acar et al. 2017 has never been replicated with Tink (Keyczar's successor), and the only Rust study (Mindermann 2018) used 28 students. Agents now write a large share of the code that calls crypto libraries, so agents are the participants that matter.

Plan, to come back to: use the skill tester to run the paper's tasks (symmetric key generation, encryption and decryption; asymmetric key generation, encryption and decryption, certificate validation; plus key storage and password-based key derivation, the periphery where the paper found most failures) with agents as participants. Vary the model, the prompt, and the context (no docs, library docs only, with and without the skills below). Compare:

- Tink
- vitaminc on its own
- Stack Encrypt, once it comes together

Measure what the paper measured: functional success, secure success (scored separately, with a crypto-specific rubric rather than a general-purpose analyser, per Elsayed 2026), and the agent's self-assessed security. Also record hallucinated APIs, the failure mode the paper's human participants did not have.

## Proposal for the skill(s)

The goals split cleanly into two audiences with different needs, so two skills make sense:

1. **`misuse-resistance`** (general, for any library author: vitaminc maintainers and outside developers). The distilled principles with their evidence, Rust techniques for each rung of the hard-to-misuse scale (newtypes, typestate, sealed traits, private constructors, `#[must_use]`, compile-fail tests with trybuild), a review checklist, and guidance on docs and examples. Language-agnostic principles first, Rust idioms second, so it is useful outside Rust.
2. **`vitaminc`** (for developers adopting vitaminc in their own code). Maps common tasks and footguns to vitaminc capabilities: "I need to hold a key" leads to `Protected`, "I need random bytes" leads to `SafeRand`, "I need to encrypt a struct" leads to `vitaminc-encrypt` / `vitaminc-aead`. Every example secure and copyable, per principle 7. The first skill links to this one wherever vitaminc provides the secure wrapper.

Internal development uses both: the first when designing vitaminc's own APIs, the second to keep vitaminc's examples and docs honest.
