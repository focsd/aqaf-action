"""Bounded static evidence helpers. Never import or execute assessed project code."""
from __future__ import annotations
import os
import ast
from pathlib import Path
import re

_BLOCK_MARKER = re.compile(r'/\*|\*/')

PACKAGE_MARKERS = ('.git', 'package.json', 'pyproject.toml', 'Cargo.toml', 'Package.swift',
                   'pom.xml', 'settings.gradle', 'settings.gradle.kts', 'go.mod', 'composer.json')


def _metadata_files(root, relative, suffixes):
    """Known metadata locations only; no symlink traversal or unbounded ancestor walk."""
    base = root
    for part in Path(relative).parts:
        base = base / part
        if base.is_symlink():
            return []
    if base.is_file():
        return [base] if base.suffix.lower() in suffixes else []
    if not base.is_dir():
        return []
    found = []
    visited = 0
    for directory, dirs, names in os.walk(base, followlinks=False):
        visited += 1
        if visited > 256:
            break
        dirs[:] = sorted(d for d in dirs if not d.startswith('.') and not (Path(directory)/d).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if not path.is_symlink() and path.is_file() and path.suffix.lower() in suffixes:
                found.append(path)
                if len(found) == 1000:
                    return found
    return found


def _unique_paths(paths):
    # Case-insensitive filesystems can resolve uppercase/lowercase candidates to
    # one file. Preserve the first valid spelling; keep distinct Linux files.
    seen = set(); result = []
    for path in paths:
        try:
            info = path.stat(); identity = (info.st_dev, info.st_ino)
        except OSError:
            continue
        if identity not in seen:
            seen.add(identity); result.append(path)
    return result


def parent_context(root: Path):
    """Consider only the immediate owner of a conventional source slice.

    An independently marked package/repository never inherits its parent's docs.
    Evidence is descriptive file presence, not verified architectural compliance.
    """
    root = root.resolve()
    result = {'root': None, 'architecture_files': [], 'migration_files': []}
    if root.name.lower() not in {'src', 'app', 'lib'} or any((root/name).exists() or (root/name).is_symlink() for name in PACKAGE_MARKERS):
        return result
    parent = root.parent
    documents = []
    for relative in ('architecture.md', 'ARCHITECTURE.md', 'architecture.rst', 'ARCHITECTURE.rst',
                     'docs/architecture.md', 'docs/ARCHITECTURE.md', 'docs/architecture', 'docs/adr'):
        documents.extend(_metadata_files(parent, relative, {'.md', '.rst', '.adoc'}))
    migrations = []
    for relative in ('migrations', 'prisma/migrations', 'alembic/versions', 'db/migrate', 'db/migrations'):
        migrations.extend(_metadata_files(parent, relative, {'.sql', '.py', '.js', '.ts', '.rb', '.php', '.xml', '.json', '.yml', '.yaml'}))
    documents = _unique_paths(documents)
    migrations = _unique_paths(migrations)
    if documents or migrations:
        result = {'root': str(parent),
                  'architecture_files': sorted({'../'+p.relative_to(parent).as_posix() for p in documents}),
                  'migration_files': sorted({'../'+p.relative_to(parent).as_posix() for p in migrations})}
    return result


def code_tokens(text, rust=False):
    """Mask comments and literals for narrow call/attribute heuristics, not parsing.

    Rust block comments nest; Rust raw-string delimiters are preserved while
    finding the closing quote. Template strings are masked as a whole.
    """
    single = r"'(?:\\.|[^'\\])*'" if not rust else r"'(?:\\[^\n]|[^'\\\n])'"
    raw = r'(?P<raw>(?:br|r)(?P<hashes>#{0,255})")|' if rust else ''
    pattern = re.compile(r'//[^\n]*|(?P<block>/\*)|' + raw + r'"(?:\\[\s\S]|[^"\\])*"|' + single + r'|`(?:\\[\s\S]|[^`\\])*`')
    parts = []; offset = 0
    while True:
        match = pattern.search(text, offset)
        if not match:
            parts.append(text[offset:]); break
        parts.append(text[offset:match.start()]); end = match.end()
        if match.group('block'):
            depth = 1
            while depth:
                marker = _BLOCK_MARKER.search(text, end)
                if not marker:
                    end = len(text); break
                depth += 1 if marker.group() == '/*' else -1
                end = marker.end()
        elif rust and match.group('raw'):
            closing = '"' + match.group('hashes')
            position = text.find(closing, end)
            end = len(text) if position < 0 else position + len(closing)
        parts.append(''.join('\n' if c == '\n' else ' ' for c in text[match.start():end]))
        offset = end
    return ''.join(parts)


def rust_test_count(text):
    if not re.search(r'#\s*\[\s*(?:(?:tokio|async_std)\s*::\s*)?test(?:\s*\([^]]*\))?\s*\]', text):
        return 0
    tokens = code_tokens(text, rust=True)
    return len(re.findall(r'#\s*\[\s*(?:(?:tokio|async_std)\s*::\s*)?test(?:\s*\([^]]*\))?\s*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z_]\w*\s*\(', tokens))


def has_warning_call(text, python=False):
    pattern = r'\b(?:console|logger|log)\s*\.\s*warn(?:ing)?\s*\('
    if not re.search(pattern, text): return False
    if python:
        try:
            tree = ast.parse(text)
        except (SyntaxError, RecursionError):
            return False
        return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr in {'warn', 'warning'} and isinstance(n.func.value, ast.Name)
                   and n.func.value.id in {'console', 'logger', 'log'} for n in ast.walk(tree))
    return bool(re.search(pattern, code_tokens(text)))
