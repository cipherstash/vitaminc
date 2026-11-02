#!/usr/bin/env python3
"""Build and run selected README examples as independent consumers.

Each example gets only its declared direct dependencies, with default features
disabled. Dependency versions must come from the workspace lockfile. No workspace
or dependency dev-features are unified into these temporary, standalone packages.
Python 3.11+; run after fetching/building workspace dependencies.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

from workspace_metadata import workspace

# (README, heading, Rust block index within that section, direct dependencies)
EXAMPLES = {
    'encrypt': ('packages/encrypt/README.md', 'Quick Start', 0,
                {'vitaminc-encrypt': [], 'vitaminc-random': []}),
    'random': ('packages/random/README.md', 'Generatable', 0,
               {'vitaminc-random': []}),
    'random-derive': ('packages/random/README.md', 'Generatable', 1,
                      {'vitaminc-random': []}),
    'facade': ('README.md', 'Usage', 0, {'vitaminc': ['protected']}),
    'storage': ('packages/aead-frame/README.md', 'Storage profile (feature `serde`)', 0,
                {'vitaminc-aead-frame': ['serde'], 'vitaminc-protected': []}),
}


def example(text: str, heading: str, index: int) -> str:
    sections = re.split(r'^## (.+)\n', text, flags=re.M)
    matches = [sections[i + 1] for i in range(1, len(sections), 2) if sections[i] == heading]
    if len(matches) != 1:
        raise ValueError(f'expected one section {heading!r}')
    blocks = re.findall(r'^```rust\n(.*?)^```\s*$', matches[0], re.M | re.S)
    if index >= len(blocks):
        raise ValueError(f'missing Rust example {index} under {heading!r}')
    # Compile what users copy. In particular, remove hidden doctest imports,
    # fake facade modules and cfg guards that could conceal missing dependencies.
    lines = []
    for line in blocks[index].splitlines():
        if line == '#' or line.startswith('# '):
            continue
        lines.append(line[1:] if line.startswith('##') else line)
    if not any(line.strip() for line in lines):
        raise ValueError('empty example')
    return 'fn main() {\n' + '\n'.join(lines) + '\n}\n'


def locked_packages(path: Path) -> set[tuple[str, str, str | None]]:
    lock = tomllib.loads(path.read_text())
    return {(p['name'], p['version'], p.get('source')) for p in lock['package']}


def check_resolution(lock: Path, allowed: set, name: str):
    extra = locked_packages(lock) - allowed - {(name, '0.0.0', None)}
    if extra:
        raise ValueError(f'consumer resolved dependencies outside workspace Cargo.lock: {sorted(extra)}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--target', help='compile only for this target; native examples run by default')
    parser.add_argument('--example', choices=EXAMPLES, action='append', help='select cases; default: all')
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        defaults, members = workspace(root)
        packages = {m['package']['name']: path for path, m in members.items()}
        allowed = locked_packages(root / 'Cargo.lock')
        env = dict(os.environ)
        # Share build artifacts, but never dependency resolution or features.
        env['CARGO_TARGET_DIR'] = str(root / 'target/doc-consumers')
        with tempfile.TemporaryDirectory(prefix='vitaminc-doc-consumers-') as temp:
            for case in args.example or EXAMPLES:
                readme, heading, index, dependencies = EXAMPLES[case]
                name = 'doc-consumer-' + case
                directory = Path(temp) / case
                (directory / 'src').mkdir(parents=True)
                manifest = [f'[package]\nname = {json.dumps(name)}\nversion = "0.0.0"',
                            f'edition = {json.dumps(defaults["edition"])}',
                            f'rust-version = {json.dumps(defaults["rust-version"])}',
                            'publish = false\n\n[workspace]\n\n[dependencies]']
                for dependency, features in dependencies.items():
                    manifest.append(f'{dependency} = {{ path = {json.dumps(str(packages[dependency]))}, '
                                    f'default-features = false, features = {json.dumps(features)} }}')
                (directory / 'Cargo.toml').write_text('\n'.join(manifest) + '\n')
                (directory / 'src/main.rs').write_text(example((root / readme).read_text(), heading, index))
                shutil.copyfile(root / 'Cargo.lock', directory / 'Cargo.lock')
                command = ['cargo', '--offline']
                # Resolve the new root against the copied lockfile before executing
                # build scripts; refuse any additional version/source selection.
                subprocess.run(command + ['metadata', '--format-version=1'], cwd=directory,
                               env=env, stdout=subprocess.DEVNULL, check=True)
                check_resolution(directory / 'Cargo.lock', allowed, name)
                mode = ['check', '--target', args.target] if args.target else ['run']
                print(f'Checking README consumer: {case} ({args.target or "native"})', flush=True)
                subprocess.run(command + mode + ['--locked'], cwd=directory, env=env, check=True)
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'check_doc_examples: {error}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
