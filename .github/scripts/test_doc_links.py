"""Regression cases for links rustdoc's own lint does not catch."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from check_doc_links import Checker, Page, external_errors, missing_references


class DocLinksTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'Cargo.toml').write_text('''[workspace]
members = ["example"]
[workspace.package]
version = "1.2.3"
''')
        (self.root / 'example').mkdir()
        (self.root / 'example/Cargo.toml').write_text('''[package]
name = "example"
version.workspace = true
''')
        self.doc = self.root / 'target/doc'
        self.doc.mkdir(parents=True)
        self.rendered = self.root / 'rendered'
        self.rendered.mkdir()
        self.checker = Checker(self.root, self.doc, self.rendered)
        self.readme = self.root / 'README.md'
        self.readme.write_text('# Example\n')
        self.landing = self.doc / 'example/index.html'
        self.landing.parent.mkdir()
        self.landing.write_text('<div id="usage"></div>')

    def test_current_api_links_validate_pages_and_fragments(self):
        self.checker.check(self.readme, 'https://docs.rs/example/latest/example/index.html#usage')
        self.assertFalse(self.checker.errors)
        self.checker.check(self.readme, 'https://docs.rs/example/latest/example/index.html#removed')
        self.checker.check(self.readme, 'https://docs.rs/example/latest/example/struct.Gone.html')
        self.assertEqual(len(self.checker.errors), 2)

    def test_rustdoc_must_not_follow_latest_api(self):
        self.checker.check(self.landing, 'https://docs.rs/example/latest/example/index.html')
        self.assertIn('latest', self.checker.errors[0])
        self.checker.errors.clear()
        self.checker.check(self.landing, 'https://docs.rs/example/1.2.3/example/index.html#usage')
        self.assertFalse(self.checker.errors)

    def test_rust_paths_are_not_url_schemes_or_files(self):
        for href in ['crate::Example', 'example::Trait::method', 'trait@Example']:
            self.checker.check(self.readme, href)
        self.assertEqual(len(self.checker.errors), 3)

    def test_github_main_links_use_checkout_and_allow_directory_listings(self):
        self.checker.check(self.readme, 'https://github.com/cipherstash/vitaminc/tree/main/example')
        self.checker.check(self.readme, 'https://github.com/cipherstash/vitaminc/blob/main/Cargo.toml')
        self.assertFalse(self.checker.errors)
        self.checker.check(self.readme, 'https://github.com/cipherstash/vitaminc/blob/main/missing.md')
        self.assertIn('missing destination', self.checker.errors[0])

    def test_relative_html_links_validate_fragments(self):
        self.checker.check(self.landing, '#usage')
        self.checker.check(self.landing, 'index.html#missing')
        self.assertEqual(len(self.checker.errors), 1)

    def test_escaped_paths_cannot_leave_checkout(self):
        for href in ['../outside.md', 'https://github.com/cipherstash/vitaminc/blob/main/%2e%2e/outside.md']:
            self.checker.check(self.readme, href)
        self.assertEqual(len(self.checker.errors), 2)

    def test_offline_mode_never_fetches_external_links(self):
        with patch('check_doc_links.urlopen', side_effect=AssertionError('network')):
            self.checker.check(self.readme, 'https://example.org/docs#intro')
        self.assertEqual(self.checker.external, {'https://example.org/docs#intro'})
        self.assertFalse(self.checker.errors)

    def test_prose_links_exclude_generated_navigation(self):
        p = Page('<nav><a href="nav">nav</a></nav><div class="docblock">'
                 '<p><a href="api">API</a><br><img src="badge"></p>'
                 '<a href="guide">Guide</a></div><a href="outside">outside</a>', rustdoc=True)
        self.assertEqual(p.links, {'api', 'guide'})

    def test_external_errors_report_failures(self):
        with patch('check_doc_links.urlopen', side_effect=OSError('offline')):
            errors = external_errors({'https://example.org/a', 'https://example.org/a#b'})
        self.assertEqual(len(errors), 1)
        self.assertIn('offline', errors[0])

    def test_undefined_api_references_are_not_silently_rendered_as_text(self):
        text = '''Use [`Client`], [Known], and [`Removed`].
[`Client`]: https://example.org/client
[Known]: https://example.org/known
[Inline](https://example.org/inline)
The JavaScript [[Set]] operation.
```rust
let text = "[`NotALink`]";
```
'''
        self.assertEqual(missing_references(text), {'`Removed`'})


if __name__ == '__main__':
    unittest.main()
