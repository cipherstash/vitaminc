
## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** encrypt a value, not an OrderPlaintext; implement over the sealed plaintext
- **Breaking:** encode every value as the type its column declares, through a column handle
- **Breaking:** compare order terms through the scheme and column, not through Ord

### Documentation

- show encrypt and encrypt_with_context on the methods themselves
- the README's toy scheme refuses short terms and other columns' terms

### Features

- add vitaminc-ore, the sealed order encoding per kind and the scheme trait
- re-export the data model types order takes, and name the chained scheme

### Fixes

- name the index a refused term was for, not always equality
- drop only accents from text order terms, keeping Indic and Thai vowel signs
