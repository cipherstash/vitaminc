#!/usr/bin/env python3
"""Check shared guides and crate landing-page links against the checkout and built API docs.

Build `cargo doc --workspace --all-features --no-deps` first. Python 3.11+
standard library and rustdoc only. Network requests require --external.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import cache
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import unquote, urldefrag, urlparse
from urllib.request import Request, urlopen

from workspace_metadata import inside, readmes, workspace


def missing_references(text: str) -> set[str]:
    """Find unresolved shorthand API links that Markdown would print literally."""
    text = re.sub(r'^```[^\n]*\n.*?^```[^\n]*$', '', text, flags=re.M | re.S)
    normalize = lambda label: ' '.join(label.split()).lower()
    defined = {normalize(label) for label in re.findall(r'^\[([^\]\n]+)\]:', text, re.M)}
    references = re.findall(r'(?<!\[)\[(`[^`\n]+`|[A-Z][A-Za-z0-9_:]*)\](?![(:\[])', text)
    return {label for label in references if normalize(label) not in defined}


class Page(HTMLParser):
    """Collect links in prose, excluding rustdoc navigation and source listings."""

    def __init__(self, text: str, *, rustdoc: bool = False):
        super().__init__()
        self.ids: set[str] = set()
        self.links: set[str] = set()
        self.rustdoc = rustdoc
        self.stack: list[bool] = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        active = (self.stack[-1] if self.stack else not self.rustdoc)
        active = active or 'docblock' in attrs.get('class', '').split()
        if tag == 'a' and active and 'href' in attrs:
            self.links.add(attrs['href'])
        if tag not in {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                       'link', 'meta', 'param', 'source', 'track', 'wbr'}:
            self.stack.append(active)

    def handle_endtag(self, tag):
        if self.stack:
            self.stack.pop()


class Checker:
    def __init__(self, root: Path, doc: Path, temp: Path):
        self.root, self.doc, self.temp = root.resolve(), doc.resolve(), temp
        self.defaults, self.members = workspace(self.root)
        self.packages = {}
        for member, manifest in self.members.items():
            p = manifest['package']
            if p.get('publish') is False:
                continue
            version = p['version']
            if isinstance(version, dict):
                version = self.defaults['version']
            crate = manifest.get('lib', {}).get('name', p['name'].replace('-', '_'))
            self.packages[p['name']] = (crate, version)
        self.external: set[str] = set()
        self.errors: list[str] = []
        self.checked = 0

    @cache
    def page(self, path: Path) -> Page:
        if path.suffix == '.md':
            # rustdoc's standalone Markdown renderer expects a title first.
            text = path.read_text()
            if not text.startswith('# '):
                text = '# Documentation\n\n' + text
            folder = self.temp / str(len(list(self.temp.iterdir())))
            folder.mkdir()
            source = folder / 'page.md'
            source.write_text(text)
            subprocess.run(['rustdoc', str(source), '--markdown-no-toc', '-o', str(folder)],
                           check=True, capture_output=True, text=True)
            return Page((folder / 'page.html').read_text())
        return Page(path.read_text(), rustdoc=True)

    def destination(self, source: Path, href: str) -> tuple[Path, str] | None:
        """Resolve current-repository and workspace API URLs without the network."""
        u = urlparse(href)
        fragment = unquote(u.fragment)
        if u.scheme in ('http', 'https'):
            parts = unquote(u.path).strip('/').split('/')
            if u.netloc == 'github.com' and parts[:2] == ['cipherstash', 'vitaminc']:
                if len(parts) == 2:
                    return self.root / 'README.md', fragment
                if parts[2:4] in (['blob', 'main'], ['tree', 'main']):
                    return inside(self.root, self.root.joinpath(*parts[4:])), fragment
            if u.netloc == 'docs.rs' and parts[0] in self.packages:
                crate, version = self.packages[parts[0]]
                if len(parts) == 1:
                    return self.doc / crate / 'index.html', fragment
                if parts[1] in ('latest', version):
                    if source.suffix == '.html' and parts[1] == 'latest' and len(parts) > 2:
                        raise ValueError('rustdoc API link targets latest instead of this release')
                    if len(parts) == 2:
                        return self.doc / crate / 'index.html', fragment
                    return inside(self.doc, self.doc.joinpath(*parts[2:])), fragment
            self.external.add(href)
            return None
        if u.scheme == 'mailto':
            return None
        if u.scheme or '::' in u.path or re.match(r'\w+@', u.path):
            raise ValueError('unresolved Rust path or unsupported URL scheme')
        if u.netloc:
            raise ValueError('use an explicit https URL')
        if not u.path:
            return source, fragment
        # Markdown-relative links refer to the original file, not the temp render.
        base = self.root if source.suffix == '.md' else self.doc
        return inside(base, source.parent / unquote(u.path)), fragment

    def check(self, source: Path, href: str):
        try:
            target = self.destination(source, href)
            if target is None:
                return
            path, fragment = target
            if path.is_dir():
                if not fragment:
                    self.checked += 1
                    return
                path = path / ('README.md' if path.is_relative_to(self.root) and
                               not path.is_relative_to(self.doc) else 'index.html')
            if not path.is_file():
                raise ValueError(f'missing destination {path}')
            if fragment and path.suffix in ('.html', '.md') and fragment not in self.page(path).ids:
                raise ValueError(f'missing anchor #{fragment} in {path}')
            self.checked += 1
        except (ValueError, OSError) as error:
            self.errors.append(f'{source.relative_to(self.root) if source.is_relative_to(self.root) else source}: {href}: {error}')

    def run(self):
        sources = readmes(self.root, self.defaults, self.members)
        sources.update(self.root / p for p in ('CONTRIBUTING.md', 'docs/documentation.md')
                       if (self.root / p).is_file())
        # Include specifications and macro guides compiled into Rust docs too.
        for member in self.members:
            for rust in (member / 'src').rglob('*.rs'):
                for path in re.findall(r'include_str!\("([^"\n]+\.md)"\)', rust.read_text()):
                    sources.add(inside(self.root, rust.parent / path))
        for crate, _ in self.packages.values():
            landing = self.doc / crate / 'index.html'
            if not landing.is_file():
                raise ValueError(f'{landing} missing; build workspace docs first')
            sources.add(landing)
        for source in sorted(sources):
            if source.suffix == '.md':
                for label in sorted(missing_references(source.read_text())):
                    self.errors.append(f'{source.relative_to(self.root)}: undefined API reference [{label}]')
            for href in sorted(self.page(source).links):
                self.check(source, href)
        return sources


def external_errors(urls: set[str]) -> list[str]:
    """Check HTTP pages once each, including fragment IDs (opt-in only)."""
    pages: dict[str, set[str]] = {}
    for url in urls:
        base, fragment = urldefrag(url)
        pages.setdefault(base, set()).add(unquote(fragment))

    def fetch(item):
        url, fragments = item
        try:
            request = Request(url, headers={'User-Agent': 'vitaminc-doc-link-check'})
            with urlopen(request, timeout=20) as response:
                if 'text/html' in response.headers.get('Content-Type', ''):
                    page = Page(response.read().decode('utf-8', errors='replace'))
                    missing = (fragments - {''}) - page.ids
                    if missing:
                        return f'{url}: missing anchors {sorted(missing)}'
        except (OSError, ValueError) as error:
            return f'{url}: {error}'
        return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        return [error for error in pool.map(fetch, sorted(pages.items())) if error]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--doc-dir', type=Path, help='default: <root>/target/doc')
    parser.add_argument('--external', action='store_true', help='also check live external websites')
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        with tempfile.TemporaryDirectory(prefix='vitaminc-doc-links-') as temp:
            checker = Checker(root, args.doc_dir or root / 'target/doc', Path(temp))
            sources = checker.run()
            if args.external:
                checker.errors.extend(external_errors(checker.external))
            print(f'Checked {checker.checked} local links in {len(sources)} documentation files; '
                  f'{len(checker.external)} external URLs {"checked" if args.external else "skipped (use --external)"}.')
            for error in checker.errors:
                print(error)
            return bool(checker.errors)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'check_doc_links: {error}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
