"""Unscored signals for AI-assisted code and agent-readable guidance (AQAF-058).

Offline, read-only, bounded. Scanned text is data: nothing found in a repository is executed or
followed, and only file paths, counts and package names are reported (never secret values).
"""
from importlib import resources
import json
import re

INSTRUCTION_RX = re.compile(r'(^|/)(agents\.md|claude\.md|gemini\.md|conventions\.md|\.cursorrules|\.windsurfrules|\.clinerules|copilot-instructions\.md|\.cursor/rules/[^/]+|\.claude/[^/]+\.md)$')
AGENT_CONFIG_RX = re.compile(r'(^|/)(\.mcp\.json|mcp\.json|\.cursor/[^/]+(/[^/]+)*|\.claude/[^/]+|prompts?/[^/]+\.(md|txt|json|ya?ml)|\.github/copilot-instructions\.md)$')
CODE_TEST_RX = re.compile(r'(^|/)(test_[^/]+\.py|[^/]+_test\.py|[^/]+\.(test|spec)\.(js|jsx|ts|tsx|mjs))$')
PY_ASSERT = re.compile(r'\bassert\b|self\.assert|pytest\.raises|pytest\.fail|\.assert_|assertRaises|unittest\.main')
JS_ASSERT = re.compile(r'\bexpect\s*\(|\bassert[\.\(]|\.should\b|\bt\.(is|true|deepEqual|equal|throws)\b|toMatchSnapshot')
PY_TEST_DEF = re.compile(r'^\s*(async\s+)?def\s+test', re.M)
JS_TEST_DEF = re.compile(r'\b(it|test)\s*(\.\w+)?\s*\(')
INTERNAL_ENDPOINT = re.compile(r'https?://(?:[\w-]+\.)*(?:internal|corp|intranet|lan|local)\b|https?://(?:10\.\d+|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+', re.I)
CODE_SUFFIXES = {'.py', '.js', '.ts', '.tsx', '.jsx', '.go', '.rs', '.java', '.kt', '.swift', '.rb', '.php', '.cs', '.c', '.cc', '.cpp', '.h'}
DUP_WINDOW = 8
DUP_MIN_BLOCKS = 50
MAX_DUP_FILES = 300
MAX_BYTES = 200000
TRIVIAL = re.compile(r'^\s*(?:[{}()\[\];,]*|import\b.*|from\b.*import\b.*|#.*|//.*|/?\*.*|use\b.*;|package\b.*|return;?|end|else|\}\s*else\s*\{)\s*$')
MISSING_MIN = 2


def snapshot():
    return json.loads(resources.files('aqaf').joinpath('data/pypi_names.json').read_text(encoding='utf8'))


def clean(text, limit=120):
    """Evidence is data from a repository: strip control characters and bound the length."""
    return re.sub(r'[\x00-\x1f\x7f`]+', ' ', str(text))[:limit]


def _rel(p, root):
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


def _instruction_refs(text):
    refs = set()
    for tok in re.findall(r'`([^`\n]{2,120})`', text):
        tok = tok.strip().rstrip('.,;:)')
        tok = re.sub(r':\d+(-\d+)?$', '', tok)
        if re.search(r'[\s*?<>{}$|&=~()\\]', tok) or tok.startswith(('-', '/', '.env', 'http', '@', '#')) or '://' in tok or '..' in tok:
            continue
        if tok.startswith(('.', '_')) and '/' not in tok:
            continue  # an extension or suffix such as .md or _test.go, not a path
        if tok.startswith('.') or 'node_modules' in tok.split('/'):
            continue  # hidden and dependency folders are normally ignored by the scan
        if '/' in tok or re.search(r'\.(py|js|ts|tsx|jsx|json|md|toml|ya?ml|go|rs|sh|swift|kt|java|rb|php)$', tok):
            if tok.count('.') > 4:
                continue
            refs.add(tok.rstrip('/'))
    return refs


def _lev1(a, b):
    """True when a and b differ by exactly one insertion, deletion or substitution."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    s, l = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(s) and s[i] == l[i]:
        i += 1
    return s[i:] == l[i + 1:]


def python_dependencies(names_files, read):
    deps = set()
    for rel, p in names_files:
        base = rel.rsplit('/', 1)[-1].lower()
        try:
            text = read(p)[:MAX_BYTES]
        except Exception:
            continue
        if re.fullmatch(r'requirements[\w.-]*\.txt', base):
            for line in text.splitlines():
                m = re.match(r'\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~;@]|$)', line)
                if m and not line.lstrip().startswith(('-', '#')):
                    deps.add(m.group(1))
        elif base == 'pyproject.toml':
            for block in re.findall(r'^dependencies\s*=\s*\[(.*?)\]', text, re.S | re.M):
                for s in re.findall(r'["\']([A-Za-z0-9][A-Za-z0-9._-]*)', block):
                    deps.add(s)
            m = re.search(r'^\[tool\.poetry\.dependencies\]\n(.*?)(?=^\[|\Z)', text, re.S | re.M)
            if m:
                for k in re.findall(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=', m.group(1), re.M):
                    if k.lower() != 'python':
                        deps.add(k)
    return {re.sub(r'[-_.]+', '-', d.lower()) for d in deps}


def evaluate(files, root, code_count, read, content_only):
    names = [(_rel(p, root), p) for p in files]
    lower = [(r.lower(), r, p) for r, p in names]
    path_set = {r for r, _ in names}
    basenames = {r.rsplit('/', 1)[-1] for r in path_set}
    top = {r.split('/')[0] for r in path_set}
    suffixes = set()
    dirs = {r.rsplit('/', 1)[0] for r in path_set if '/' in r}
    for d in list(dirs):
        while '/' in d:
            d = d.rsplit('/', 1)[0]
            dirs.add(d)
    for entry in path_set | dirs:
        parts = entry.split('/')
        for i in range(len(parts)):
            suffixes.add('/'.join(parts[i:]))
    out = {}

    def na(reason):
        return {'status': 'not_applicable', 'evidence': reason}

    def res(ok, good, bad):
        return {'status': 'present' if ok else 'absent', 'evidence': good if ok else bad}

    small = content_only or code_count < 20
    instr = [(r, p) for low, r, p in lower if INSTRUCTION_RX.search(low)]

    out['AQS-AI-001'] = na('fewer than 20 code files or content-only scan') if small else (
        res(True, ', '.join(clean(r) for r, _ in instr[:5]), '') if instr else res(False, '', 'no AGENTS.md, CLAUDE.md, .cursorrules, copilot-instructions or equivalent found'))

    if not instr:
        out['AQS-AI-002'] = na('no agent instruction file to check')
    else:
        missing = []
        checked = 0
        for r, p in instr[:10]:
            try:
                text = read(p)[:MAX_BYTES]
            except Exception:
                continue
            base_dir = r.rsplit('/', 1)[0] if '/' in r else ''
            for ref in sorted(_instruction_refs(text)):
                checked += 1
                cands = {ref, (base_dir + '/' + ref) if base_dir else ref}
                if any(c in path_set or c in dirs for c in cands):
                    continue
                if ref in suffixes:
                    continue  # exists below some folder (packages, crates, apps) rather than at the root
                if '/' not in ref:
                    pass
                elif not re.search(r'\.\w{1,5}$', ref) and ref.split('/')[0] not in top:
                    continue  # no extension and an unknown first folder: probably not a path (for example audio/wav)
                missing.append(f'{r} -> {ref}')
        if checked == 0:
            out['AQS-AI-002'] = na('instruction files name no repository paths')
        else:
            ok = len(missing) < MISSING_MIN
            out['AQS-AI-002'] = res(ok, f'{checked} paths named in instruction files; {len(missing)} not found in the scanned files',
                                    f'{len(missing)} of {checked} paths named in instruction files are not in the scanned files: ' + '; '.join(clean(m) for m in missing[:5]))

    tests = [(r, p) for low, r, p in lower if CODE_TEST_RX.search(low)]
    if content_only or not tests:
        out['AQS-AI-004'] = na('no Python or JavaScript/TypeScript test files')
    else:
        empty = []
        for r, p in tests[:400]:
            try:
                text = read(p)[:MAX_BYTES]
            except Exception:
                continue
            py = r.endswith('.py')
            has_tests = bool((PY_TEST_DEF if py else JS_TEST_DEF).search(text))
            if has_tests and not (PY_ASSERT if py else JS_ASSERT).search(text):
                empty.append(r)
        out['AQS-AI-004'] = res(not empty, f'{len(tests)} test files each contain an assertion',
                                f'{len(empty)} of {len(tests)} test files define tests but contain no assertion: ' + '; '.join(clean(x) for x in empty[:5]))

    configs = [(r, p) for low, r, p in lower if AGENT_CONFIG_RX.search(low) or INSTRUCTION_RX.search(low)]
    if not configs:
        out['AQS-AI-005'] = na('no agent or prompt configuration files')
    else:
        from .secret_scan import classify
        hits = []
        for r, p in configs[:100]:
            try:
                text = read(p)[:MAX_BYTES]
            except Exception:
                continue
            kind = classify(text)
            if kind:
                hits.append(f'{r} (credential-like value, {kind})')
            if INTERNAL_ENDPOINT.search(text):
                hits.append(f'{r} (internal endpoint)')
        out['AQS-AI-005'] = res(not hits, f'{len(configs)} agent or prompt files checked; none holds a credential-like value or internal endpoint',
                                f'{len(hits)} agent or prompt file findings (values are not shown): ' + '; '.join(clean(h) for h in hits[:5]))

    if small:
        out['AQS-AI-006'] = na('fewer than 20 code files or content-only scan')
    else:
        seen = {}
        shared = 0
        code = [(r, p) for low, r, p in lower if p.suffix.lower() in CODE_SUFFIXES and not CODE_TEST_RX.search(low)][:MAX_DUP_FILES]
        for r, p in code:
            try:
                text = read(p)[:MAX_BYTES]
            except Exception:
                continue
            lines = [re.sub(r'\s+', ' ', l.strip()) for l in text.splitlines()]
            lines = [l for l in lines if l and not TRIVIAL.match(l)]
            local = set()
            for i in range(len(lines) - DUP_WINDOW + 1):
                key = hash('\n'.join(lines[i:i + DUP_WINDOW]))
                if key in local:
                    continue
                local.add(key)
                first = seen.setdefault(key, r)
                if first != r:
                    shared += 1
        out['AQS-AI-006'] = res(shared < DUP_MIN_BLOCKS, f'{shared} repeated {DUP_WINDOW}-line blocks shared between files (limit {DUP_MIN_BLOCKS})',
                                f'{shared} repeated {DUP_WINDOW}-line blocks appear in more than one source file')

    pyfiles = [(r, p) for low, r, p in lower if re.search(r'(^|/)(requirements[\w.-]*\.txt|pyproject\.toml)$', low)]
    deps = python_dependencies(pyfiles, read) if pyfiles else set()
    if not deps:
        out['AQS-AI-007'] = na('no Python dependency declarations found (npm and other ecosystems are not covered)')
    else:
        snap = snapshot()
        known = set(snap['names'])
        near, unknown = [], 0
        for d in sorted(deps):
            if d in known:
                continue
            unknown += 1
            if len(d) >= 7:
                m = next((k for k in known if abs(len(k) - len(d)) <= 1 and _lev1(d, k)), None)
                if m:
                    near.append(f'{d} ~ {m}')
        lim = f'package-name snapshot dated {snap["snapshot_date"]}; names newer than it are unknown to it'
        out['AQS-AI-007'] = res(not near, f'{len(deps)} declared; {unknown} not in the snapshot (unverified, not judged); none resembles a popular name ({lim})',
                                f'{len(near)} declared names resemble a popular package but differ by one character: ' + '; '.join(clean(n) for n in near[:5]) + f' ({lim})')
    return out
