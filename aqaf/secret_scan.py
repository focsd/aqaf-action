"""Precision rules for the AQ-CFG-001 hard-coded secret heuristic.

Static and offline. Decides which files are production source and whether a matched literal looks like a credential
rather than a placeholder, an identifier or a lexer token. It never returns the matched value, only file paths."""
from __future__ import annotations
import math
import re

# Matches the previous heuristic: a secret-like key name assigned a quoted literal of at least eight characters.
KEY_VALUE = re.compile(r'(?i)(?:api[_-]?key|secret|token|password|passwd)["\']?\s*[=:]\s*["\']([^"\']{8,})["\']')
STRONG_PATTERNS = [
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----'),
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'),
    re.compile(r'\bsk-[A-Za-z0-9]{32,}\b'),
]

NON_PRODUCTION_SEGMENTS = {
    'test', 'tests', '__tests__', 'spec', 'specs', 'testing', 'testdata', 'test-data', 'fixtures', 'fixture', 'mocks', '__mocks__',
    'example', 'examples', 'sample', 'samples', 'demo', 'demos', 'docs', 'doc', 'e2e', 'benches', 'benchmarks',
    'vendor', 'vendors', 'third_party', 'third-party', 'thirdparty', 'external', 'externals', 'bower_components',
    'node_modules', 'site-packages', 'generated', 'gen',
}
NON_PRODUCTION_NAME = re.compile(r'(?i)(?:\.min\.[a-z]+$|[._-](?:test|tests|spec|mock|fixture)\.[a-z]+$|^test_.*\.py$|_test\.(?:go|py|rs|cpp|cc|c)$'
                                 r'|tests?\.(?:java|kt|swift|cs|rs|php)$|\.generated\.|\.g\.dart$|\.pb\.go$)')
# Well-known bundled libraries that are copied into repositories without a vendor folder.
VENDORED_NAMES = {'esprima.js', 'coffee-script.js', 'jquery.js', 'lodash.js', 'underscore.js', 'moment.js', 'bootstrap.js', 'angular.js'}

PLACEHOLDER = re.compile(r'(?i)(?:your[_-]|<[^>]*>|\$\{|\{\{|%\(|%s|example|placeholder|change[_-]?me|dummy|redacted|xxx|\*\*\*|lorem|\.\.\.|'
                         r'(?<![a-z0-9])(?:test|testing|fake|sample|foo|bar|todo|insert|replace|secret_key_here|password123|abcdef|123456)(?![a-z0-9]))')
ENV_ACCESS = re.compile(r'(?i)(?:process\.env|os\.environ|getenv|env\(|System\.getProperty|ENV\[|import\.meta\.env|config\()')


def is_production_path(rel_path: str) -> bool:
    parts = rel_path.replace('\\', '/').lower().split('/')
    name = parts[-1]
    if name in VENDORED_NAMES or NON_PRODUCTION_NAME.search(name):
        return False
    return not any(seg in NON_PRODUCTION_SEGMENTS for seg in parts[:-1])


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def looks_like_credential(value: str) -> bool:
    """A literal that could be a real credential: no whitespace, not a placeholder/identifier/path/URL, enough variety."""
    if len(value) < 8 or re.search(r'\s', value) or PLACEHOLDER.search(value):
        return False
    if re.match(r'(?i)^[a-z][a-z0-9+.-]*://', value) and '@' not in value:
        return False  # plain URL without embedded credentials
    if value.startswith('@') or re.search(r'\\[(u]', value):
        return False  # decorator/selector or string-interpolation/escape syntax, not a literal secret
    if (re.fullmatch(r'[A-Za-z][A-Za-z0-9]*(?:[_.\-/][A-Za-z0-9]+)+', value) or re.fullmatch(r'[a-z][a-z0-9]*', value)) and not re.search(r'\d{3}', value):
        return False  # snake_case / dotted identifier or path such as authorization_endpoint
    if re.fullmatch(r'[A-Za-z]+', value) and not (re.search(r'[a-z]', value) and re.search(r'[A-Z]', value) and len(value) >= 20):
        return False  # a word or CamelCase identifier
    classes = sum(bool(re.search(p, value)) for p in (r'[a-z]', r'[A-Z]', r'\d', r'[^A-Za-z0-9]'))
    return classes >= 2 and _entropy(value) >= 3.0


def classify(text: str):
    """Return 'strong', 'heuristic' or None for one file's text."""
    for pattern in STRONG_PATTERNS:
        for match in pattern.finditer(text):
            if not PLACEHOLDER.search(match.group(0)):
                return 'strong'
    for match in KEY_VALUE.finditer(text):
        line_start = text.rfind('\n', 0, match.start()) + 1
        line = text[line_start:text.find('\n', match.end()) if text.find('\n', match.end()) != -1 else len(text)]
        if ENV_ACCESS.search(line) or line.lstrip().startswith(('//', '#', '*', '/*')):
            continue
        if looks_like_credential(match.group(1)):
            return 'heuristic'
    return None


def scan_files(items):
    """items: iterable of (relative_path, text). Returns (strong_paths, heuristic_paths, ignored_non_production_count)."""
    strong, heuristic, ignored = [], [], 0
    for path, text in items:
        kind = classify(text)
        if kind is None:
            continue
        if not is_production_path(path):
            ignored += 1
            continue
        (strong if kind == 'strong' else heuristic).append(path)
    return strong, heuristic, ignored
