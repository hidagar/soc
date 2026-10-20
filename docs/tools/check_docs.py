#!/usr/bin/env python3
"""Check local Markdown links, control characters and reference freshness."""
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]


def main():
    files = [ROOT / 'README.md', ROOT / 'AGENTS.md', ROOT / 'CONTRIBUTING.md',
             *sorted((ROOT / 'docs').rglob('*.md')), ROOT / 'deploy/relay/LEEME.md']
    errors = []
    checked = 0
    for path in files:
        if not path.is_file():
            errors.append(f'{path.relative_to(ROOT)}: missing document')
            continue
        text = path.read_text(encoding='utf-8')
        if any(ord(char) < 32 and char not in '\n\r\t' for char in text):
            errors.append(f'{path.relative_to(ROOT)}: control character')
        # Remove code fences; examples can legitimately contain Markdown syntax.
        prose = re.sub(r'^```[^\n]*\n.*?^```\s*$', '', text, flags=re.M | re.S)
        for match in re.finditer(r'(?<!!)\[[^\]\n]+\]\(([^)\n]+)\)', prose):
            target = match.group(1).strip().strip('<>')
            if target.startswith('#') or urlsplit(target).scheme:
                continue
            checked += 1
            candidate = (path.parent / unquote(target.split('#', 1)[0])).resolve()
            if not candidate.is_relative_to(ROOT) or not candidate.exists():
                errors.append(f'{path.relative_to(ROOT)}: broken/outside link: {target}')
    result = subprocess.run([sys.executable, str(ROOT / 'docs/tools/generate_reference.py'), '--check'],
                            cwd=ROOT, check=False)
    if result.returncode:
        errors.append('Static code references are stale')
    if errors:
        print('\n'.join(errors))
        return 1
    print(f'Documentation OK: {len(files)} Markdown files; {checked} local links')
    print('This check does not verify external URLs, rendered layout, permissions or runtime behavior.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
