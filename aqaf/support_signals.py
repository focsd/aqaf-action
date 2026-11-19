"""Unscored post-release support signals (AQAF-057).

Read-only and bounded: looks at file names and a few documentation files. Never executes target code,
never changes score or score_breakdown. A signal that does not apply to the project says so instead of
reporting a lack.
"""
from importlib import resources
import json
import re

MIN_CODE = 20
LARGE_CODE = 50
LIB_PROFILES = {'npm_library', 'php_package', 'ruby_gem'}
SERVICE_PROFILES = {'saas_or_web_app', 'api_backend', 'ai_pipeline', 'scraper_data_pipeline'}
WEB_PROFILES = {'saas_or_web_app', 'api_backend'}
VERSIONED = ('package.json', 'pyproject.toml', 'cargo.toml', 'composer.json', 'setup.py', 'setup.cfg')
LOCKS = {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb', 'cargo.lock', 'go.sum',
         'poetry.lock', 'uv.lock', 'pipfile.lock', 'composer.lock', 'gemfile.lock'}
DOC_TEXT = {'.md', '.rst', '.txt', '.adoc'}
MAX_DOC_BYTES = 200000
MAX_CODE_READS = 400
HEALTH_EXTS = {'.py', '.js', '.ts', '.go', '.rs', '.java', '.kt', '.rb', '.php', '.cs', '.yml', '.yaml', '.json'}


def definitions():
    return json.loads(resources.files('aqaf').joinpath('data/support_signals.json').read_text(encoding='utf8'))['signals']


def _names(files, root):
    out = []
    for p in files:
        try:
            r = p.relative_to(root).as_posix()
        except ValueError:
            r = p.as_posix()
        out.append((r, r.lower(), p.name.lower()))
    return out


def _any(names, pattern, top_only=False):
    rx = re.compile(pattern)
    for rel, low, base in names:
        depth_ok = low.count('/') <= 1 or low.startswith(('.github/', 'docs/', 'doc/'))
        if rx.search(low if not top_only else base) and (not top_only or depth_ok):
            return rel
    return None


def _versioned(names, _read=None):
    for rel, low, base in names:
        if base in VERSIONED and low.count('/') == 0:
            return rel
        if base.endswith('.gemspec') and low.count('/') == 0:
            return rel
    return None


def evaluate(files, root, product, code_count, read, content_only=False, scope_note=None):
    """Return one record per signal: status is present, absent or not_applicable."""
    names = _names(files, root)
    base_names = {b for _, _, b in names}
    version_file = _versioned(names, read)
    is_lib = product in LIB_PROFILES or product == 'c_cpp_library'
    docs = [(rel, p) for (rel, low, base), p in zip(names, files) if p.suffix.lower() in DOC_TEXT and (low.count('/') == 0 or low.startswith(('docs/', 'doc/', '.github/')))]
    doc_blob = None

    def blob():
        nonlocal doc_blob
        if doc_blob is None:
            parts = []
            for rel, p in docs[:60]:
                try:
                    parts.append(read(p)[:MAX_DOC_BYTES].lower())
                except Exception:
                    pass
            doc_blob = '\n'.join(parts)
        return doc_blob

    def na(reason):
        return {'status': 'not_applicable', 'evidence': reason}

    def pr(status, evidence):
        return {'status': status, 'evidence': evidence}

    out = {}
    small = code_count < MIN_CODE
    skip_small = f'fewer than {MIN_CODE} code files; a small project is not asked for this'
    skip_large = f'fewer than {LARGE_CODE} code files; a project this size is not asked for this'

    def gate(*, versioned=False, profiles=None, minimum=MIN_CODE):
        if content_only:
            return na('content-only scan: repository files are not representative')
        if code_count < minimum:
            return na(skip_small if minimum == MIN_CODE else skip_large)
        if versioned and not version_file:
            return na('no publishable version declared at the repository root')
        if profiles is not None and product not in profiles:
            return na(f'profile {product} is not one of {", ".join(sorted(profiles))}')
        return None

    r = gate(versioned=True)
    if r is None:
        hit = _any(names, r'(^|/)(changelog|history|news|releases?)(\.[a-z]+)?$|^docs?/(releases?|changelog)', top_only=False)
        r = pr('present', hit) if hit else pr('absent', 'no CHANGELOG, HISTORY, NEWS or RELEASES file found')
    out['AQS-REL-001'] = r

    r = gate(profiles=LIB_PROFILES | {'api_backend'})
    if r is None:
        text = blob()
        hit = re.search(r'semantic version|semver|deprecat|breaking change', text)
        r = pr('present', 'compatibility wording found in repository documentation') if hit else pr('absent', 'no compatibility or deprecation wording in README, CHANGELOG or docs')
    out['AQS-REL-002'] = r

    r = gate(profiles=LIB_PROFILES | {'api_backend'}, minimum=LARGE_CODE)
    if r is None:
        hit = next((rel for rel, low, b in names if re.search(r'migrat|upgrad', low) and b.endswith(tuple(DOC_TEXT))), None)
        r = pr('present', hit) if hit else pr('absent', 'no migration or upgrade notes found')
    out['AQS-REL-003'] = r

    r = gate()
    if r is None and is_lib:
        r = na('libraries are not asked to commit a lockfile')
    if r is None:
        has_manifest = bool({'package.json', 'cargo.toml', 'go.mod', 'pyproject.toml', 'requirements.txt', 'pipfile'} & base_names)
        if not has_manifest:
            r = na('no dependency manifest found')
        else:
            lock = next((rel for rel, _, b in names if b in LOCKS), None)
            if lock is None:
                for (rel, low, b), p in zip(names, files):
                    if re.fullmatch(r'requirements[\w.-]*\.txt', b):
                        try:
                            if re.search(r'^[\w.\-\[\]]+==', read(p), re.M):
                                lock = rel
                                break
                        except Exception:
                            pass
            r = pr('present', lock) if lock else pr('absent', 'no lockfile or pinned requirements file found')
    out['AQS-REP-001'] = r

    r = gate(minimum=LARGE_CODE)
    if r is None:
        hit = _any(names, r'(^|/)(codeowners|maintainers|owners|governance|authors)(\.[a-z]+)?$')
        r = pr('present', hit) if hit else pr('absent', 'no CODEOWNERS, MAINTAINERS, OWNERS, GOVERNANCE or AUTHORS file found')
    out['AQS-OWN-001'] = r

    r = gate(versioned=True)
    if r is None:
        hit = _any(names, r'(^|/)security(\.[a-z]+)?$')
        hit = hit if hit and (hit.count('/') == 0 or hit.lower().startswith(('.github/', 'docs/'))) else None
        r = pr('present', hit) if hit else pr('absent', 'no SECURITY.md found at the root, in .github or in docs')
    out['AQS-OWN-002'] = r

    r = gate(minimum=LARGE_CODE)
    if r is None:
        hit = _any(names, r'(^|/)contributing(\.[a-z]+)?$')
        r = pr('present', hit) if hit else pr('absent', 'no CONTRIBUTING file found')
    out['AQS-OWN-003'] = r

    r = gate(profiles=SERVICE_PROFILES)
    if r is None:
        hit = _any(names, r'(^|/)(runbook|operations|deploy|deployment|oncall|playbook)(\.[a-z]+)?$|^docs?/(runbooks?|ops|operations|deploy\w*|oncall)(/|\.)')
        r = pr('present', hit) if hit else pr('absent', 'no runbook, operations or deployment notes found')
    out['AQS-OPS-001'] = r

    r = gate(profiles=WEB_PROFILES)
    if r is None:
        hit = None
        rx = re.compile(r'health|readyz|readiness|liveness')
        reads = 0
        for (rel, low, b), p in zip(names, files):
            if p.suffix.lower() in HEALTH_EXTS or b.startswith('dockerfile'):
                reads += 1
                if reads > MAX_CODE_READS:
                    break
                try:
                    if rx.search(read(p)[:MAX_DOC_BYTES].lower()):
                        hit = rel
                        break
                except Exception:
                    pass
        r = pr('present', hit) if hit else pr('absent', 'no health, readiness or liveness wording found in code or configuration')
    out['AQS-OPS-002'] = r

    r = gate()
    if r is None:
        hit = _any(names, r'(^|/)(arc42|adrs?|decisions?|c4|structurizr)(/|\.|$)|workspace\.dsl|\.c4$|(^|/)(0\d{3}|adr)[-_ ][\w-]+\.md$|^docs?/(arch|architecture)/(decisions?|adr)')
        if hit is None:
            text = blob()
            m = re.search(r'arc42|\bc4 model|\bmadr\b|architecture decision record', text)
            hit = 'documentation cites ' + m.group(0) if m else None
        r = pr('present', hit) if hit else pr('absent', 'no arc42, ADR/MADR or C4 material found')
    out['AQS-FORM-001'] = r
    from .ai_signals import evaluate as evaluate_ai
    out.update(evaluate_ai(files, root, code_count, read, content_only))
    return out


def signals_report(files, root, product, code_count, read, content_only=False):
    results = evaluate(files, root, product, code_count, read, content_only)
    records = []
    for d in definitions():
        res = results[d['id']]
        records.append({'id': d['id'], 'name': d['name'], 'category': d['category'], 'status': res['status'], 'evidence': res['evidence'],
                        'scored': False, 'applies': d['applies'], 'standards': [{k: e[k] for k in ('standard', 'item', 'title', 'match')} for e in d['standards']],
                        'rule_page': 'https://aqaf.focsd.com/rules/' + d['id'].lower() + '/'})
    from .ai_signals import snapshot
    snap = snapshot()
    return {'data': {'pypi_name_snapshot': {'date': snap['snapshot_date'], 'source': snap['source'], 'names': snap['count']}},
            'limitations': ['AQS-AI-007 compares Python dependency names with a bundled snapshot dated ' + snap['snapshot_date'] + '; packages published later are unknown to it, and npm and other ecosystems are not covered. No network access is used.'],
            'note': 'Unscored. These signals describe post-release support risk and never change score or score_breakdown. not_applicable means the project is too small or of another kind for the signal to be reasonable.',
            'signals': records}
