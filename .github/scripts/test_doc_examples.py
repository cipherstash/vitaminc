"""Ensure consumer checks exercise visible examples and the locked dependency graph."""
from pathlib import Path
import tempfile
import unittest

from check_doc_examples import check_resolution, example


class DocExamplesTest(unittest.TestCase):
    def test_selects_section_and_block_without_hidden_scaffolding(self):
        text = '''# Guide
## Other
```rust
wrong();
```
## Usage
```rust
first();
```
```rust
# mod dependency { pub fn run() {} }
# #[cfg(feature = "optional")]
# {
dependency::run();
# }
```
## Next
```rust
also_wrong();
```
'''
        self.assertEqual(example(text, 'Usage', 1), 'fn main() {\ndependency::run();\n}\n')

    def test_missing_or_ambiguous_examples_fail(self):
        for text, index in [('## Other\n', 0), ('## Usage\n', 0),
                            ('## Usage\n## Usage\n', 0),
                            ('## Usage\n```rust\n# hidden();\n```\n', 0)]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                example(text, 'Usage', index)

    def test_resolution_rejects_new_dependency_versions_and_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            lock = Path(temp) / 'Cargo.lock'
            lock.write_text('''[[package]]
name = "consumer"
version = "0.0.0"
[[package]]
name = "library"
version = "1.0.0"
source = "registry+example"
''')
            check_resolution(lock, {('library', '1.0.0', 'registry+example')}, 'consumer')
            for allowed in [{('library', '0.9.0', 'registry+example')},
                            {('library', '1.0.0', 'registry+different')}]:
                with self.subTest(allowed=allowed), self.assertRaises(ValueError):
                    check_resolution(lock, allowed, 'consumer')


if __name__ == '__main__':
    unittest.main()
