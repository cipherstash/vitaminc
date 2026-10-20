# Evidence

The studies behind each rule in [SKILL.md](SKILL.md). Cite these when a rule is challenged in review. Fuller notes, with the source of each figure, are in the vitaminc repository at `docs/research/misuse-resistance.md`.

## Why the API carries the burden

- **Lazar et al. 2014**, *Why does cryptographic software fail?* (APSys). Of 269 crypto CVEs, 83% were applications misusing libraries; 17% were in the libraries.
- **Oliveira et al. 2014**, *It's the psychology stupid* (ACSAC). Security is not part of developers' everyday heuristics. Primed developers found about twice as many vulnerabilities.
- **Acar et al. 2016**, *You get where you're looking for* (IEEE S&P). Developers using Stack Overflow produced the most functional and least secure code, and rated insecure solutions as secure.
- **Perry et al. 2023**, *Do users write more insecure code with AI assistants?* (CCS). Participants with an AI assistant wrote less secure code, including for encryption, and were more confident it was secure.
- **Elsayed et al. 2026**, *An empirical security evaluation of LLM-generated cryptographic Rust code* (arXiv:2604.27001). 23.3% of 240 samples compiled; of those, 57% had vulnerabilities, chiefly nonce reuse and hallucinated APIs.

## Per rule

| Rule | Evidence |
|---|---|
| 1. Secure by default | Fischer et al. 2021 (CCS): re-ranking search results by security raised secure and functional outcomes with no behaviour change. Green & Smith 2016: defaults safe and never ambiguous. |
| 2. Tasks, not primitives | Nadi et al. 2016 (ICSE): Java developers found crypto APIs too low-level and asked for task-based ones. Bernstein et al. 2012: NaCl's `crypto_box` offers no algorithm choices. |
| 3. Own the periphery | Acar et al. 2017 (IEEE S&P): calls into the library were mostly secure; failures came from key storage, password-based derivation, and insecure inputs copied from examples. Egele et al. 2013 (CCS): 88% of 11,748 Android apps misused crypto, through mistakes such as ECB mode, constant keys and constant IVs. |
| 4. Secrets as types | Blessing et al. 2021: 37.2% of vulnerabilities in crypto libraries were memory-safety issues. |
| 5. Invalid states unrepresentable | Russell's hard-to-misuse scale: "won't compile" outranks every runtime and documentation measure. Georgiev et al. 2012 (CCS): certificate validation broke where libraries exposed confusing options. |
| 6. Promise only what you deliver | Oliveira et al. 2018 (SOUPS) and Brun et al. 2023 (TOSEM): APIs with misleading names or hidden preconditions caused vulnerabilities regardless of experience. Albertini et al. 2022 (USENIX Security): callers assumed AEAD key commitment that the primitive did not give. |
| 7. Errors reveal nothing | Padding-oracle and partitioning-oracle attacks (Len, Grubbs & Ristenpart 2021) turn distinguishable failures into plaintext recovery. |
| 8. Warn at point of use | Gorski et al. 2018 (SOUPS): API warnings nearly doubled secure outcomes; code that triggered a warning was 15 times more likely to be fixed. Gorski et al. 2020 (CHI): the five parts of a warning. Vance et al. 2018 (CHI): repeated identical warnings stop being processed. |
| 9. Secure, complete examples | Acar et al. 2017: copied code was three times more likely to work, and insecure inputs in examples were copied with it. Fischer et al. 2017 (IEEE S&P): insecure Stack Overflow snippets propagated into Play Store apps. |
| 10. Keep it small | Blessing et al. 2021: library complexity correlated strongly with vulnerability count. |
| 11. Evolve loudly | Holmwood 2022 (linux.conf.au): Keyczar's replacement by Tink as the model of a breaking change with a migration path. |

Experience does not protect against footguns: Acar et al. 2017 found Python, security and library experience did not predict success, and Brun et al. 2023 found long-time professionals made as many mistakes as novices.
