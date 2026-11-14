#!/usr/bin/env python3
"""
AQAF local scanner.

This is intentionally lightweight and dependency-free. It does not replace language-specific tools such as ArchUnit,
dependency-cruiser, SonarQube, Semgrep, or gitleaks. It gives Codex and humans a first architecture-quality report.
"""
from __future__ import annotations
import argparse, ast, hashlib, json, os, re, sys
from pathlib import Path
from collections import Counter, defaultdict
from . import __version__
from .registry import Registry, ProfileError, read_doc
from .evidence import parent_context, rust_test_count, has_warning_call

def _metadata():
    """Bundled source index; gracefully return empty if a developer copy is incomplete."""
    base = Path(__file__).resolve().parent / 'data'
    try:
        rules = {v['id']: v for v in json.loads((base / 'catalog.json').read_text(encoding='utf-8'))}
        sources = {v['id']: v for v in json.loads((base / 'source_registry.json').read_text(encoding='utf-8'))}
        return rules, sources
    except (OSError, ValueError, KeyError):
        return {}, {}


SKIP_DIRS = {'.git', '.hg', '.svn', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', '.gradle', 'target', 'vendor'}
CODE_EXTS = {'.gs','.py','.js','.jsx','.ts','.tsx','.php','.java','.kt','.kts','.cs','.go','.rs','.swift','.m','.mm','.cpp','.c','.h'}
SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*["\'][^"\']{8,}["\']'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'(?i)-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----'),
]
AI_TERMS = ['ollama','openai','anthropic','langchain','llama','whisper','embedding','rag','prompt','model_name']
WP_TERMS = ['add_action','add_filter','register_activation_hook','woocommerce','wp_enqueue_script']

RULE_META = {
 'AQ-DOC-001': ('medium','Architecture decisions should be documented'),
 'AQ-DEP-001': ('high','Core/domain logic should not depend on infrastructure details'),
 'AQ-MOD-001': ('high','Feature or domain modules should have clear ownership'),
 'AQ-TST-001': ('high','Architecture-sensitive areas need tests before refactoring'),
 'AQ-CFG-001': ('high','Configuration and secrets should be externalized'),
 'AQ-OBS-001': ('medium','Operational code should include logging and explicit error handling'),
 'AQ-DATA-001': ('high','Data ownership and migrations should be explicit'),
 'AQ-WP-001': ('high','WordPress hooks should be thin and delegate to services'),
 'AQ-AND-001': ('high','Android UI state and business logic should be separated'),
 'AQ-AI-001': ('high','AI providers, prompts, and models should be configurable and reproducible'),
 'AQ-CI-001': ('medium','New code should pass automated quality gates'),
 'AQ-SWIFT-001': ('high','Swift UI should not own business workflows'),
 'AQ-SWIFT-002': ('medium','Swift features/packages should express boundaries when growing'),
 'AQ-RUST-001': ('high','Rust binary entrypoints should be thin'),
 'AQ-RUST-002': ('high','Unsafe Rust should be isolated, documented, and tested'),
 'AQ-RUST-003': ('medium','Rust dependency risk should be audited'),
 'AQ-EXT-001': ('high','Browser extension permissions should be proportionate'),
 'AQ-GAS-001': ('medium','Google Apps Script triggers should delegate external IO'),
 'AQ-NPM-001': ('medium','Node library should declare a stable public entrypoint'),
}

class Finding:
    def __init__(self, rule_id, severity, title, evidence, risk, recommendation, confidence='medium'):
        self.rule_id=rule_id; self.severity=severity; self.title=title
        self.evidence=evidence; self.risk=risk; self.recommendation=recommendation; self.confidence=confidence
    def to_dict(self): return self.__dict__

def iter_files(root: Path, respect_gitignore=True, policy='typed'):
    from .scope import Scope
    yield from Scope(root,respect_gitignore=respect_gitignore,policy=policy).build().files


def rel(p, root):
    try: return str(p.relative_to(root))
    except Exception: return str(p)

def read_text(p):
    try: return p.read_text(encoding='utf-8', errors='ignore')
    except Exception: return ''

def unknown_component_message(component,scope,limit=20):
    """Name what --component accepts, and say when the requested path is a candidate the assessment did not select."""
    valid=sorted({x for n in scope.nodes for x in (n['id'],n['root'])})
    shown=', '.join(valid[:limit])+(f' ... ({len(valid)} values)' if len(valid)>limit else '')
    message=f'Unknown component/root: {component}. Valid components: {shown}'
    candidate=next((a for a in getattr(scope,'ambiguous_roots',[]) if a.get('root')==component),None)
    if candidate:
        message+=f'. {component} is a candidate root that was not selected ({candidate.get("reason")}); {len(scope.ambiguous_roots)} such candidates are listed under projects.ambiguous_roots in the JSON report'
    return message


def scan(root: Path, profile: str = "auto", registry=None, pack: str = "auto", capabilities=(), review_signals=False, respect_gitignore=True, scope_policy='typed', scope_config=None,
         inventory_all=False, component=None, review_options=None, session=None, review_knowledge=False):
    from .scope import Scope
    scope=session or Scope(root,respect_gitignore,scope_policy,scope_config,inventory_all).build()
    root=scope.root
    files=scope.files
    if component:
        selected=next((n for n in scope.nodes if n['id']==component or n['root']==component),None)
        if selected is None:raise ValueError(unknown_component_message(component,scope))
        root=scope.root if selected['root']=='.' else scope.root/selected['root']
        files=[r['path'] for r in scope.records if r['owner']==selected['id']]
    read=scope.text
    code=[p for p in files if p.suffix.lower() in CODE_EXTS]
    # Exclude AQAF's own scanner when it has been copied into a target repo; otherwise it can bias product detection.
    app_code=[p for p in code if p.name.lower() != 'aqaf.py']
    detection_code = app_code if app_code else code
    exts=Counter(p.suffix.lower() for p in files)
    names={p.name.lower() for p in files}
    path_text='\n'.join(rel(p,root).lower() for p in files)
    sample_text='\n'.join(read(p)[:2000].lower() for p in detection_code[:250])

    findings=[]
    signals=[]

    # Data-only registry makes product types additive without changing the scanner core.
    reg = registry or Registry()
    detected_product, evidence_signals, detection_confidence, candidates = reg.detect(files,root,detection_code,pack,reader=scope.text)
    product = detected_product
    if profile != 'auto':
        chosen=reg.get_profile(profile)
        if pack!='auto' and profile not in reg.get_pack(pack)['profiles']:
            raise ProfileError(f'Profile {profile} is not a member of pack {pack}')
        product=profile
        detection_confidence='user-selected'
    chosen=reg.get_profile(product)
    target=chosen['target_architecture']
    signals=evidence_signals
    technologies=sorted({x for x in ['python' if '.py' in exts else None,
        'javascript' if {'.js','.jsx','.ts','.tsx'} & exts.keys() else None,
        'swift' if '.swift' in exts else None,'rust' if '.rs' in exts else None,
        'kotlin' if {'.kt','.kts'} & exts.keys() else None,
        'php' if '.php' in exts else None,'csharp' if '.cs' in exts else None]
        if x})
    for c in capabilities:
        if not re.fullmatch(r'[a-z][a-z0-9_]{1,63}',c):
            raise ValueError(f'Invalid capability: {c}')

    context = parent_context(root)

    # docs/ADRs
    has_arch_docs = any('adr' in rel(p,root).lower() or 'architecture' in rel(p,root).lower() for p in files if p.suffix.lower() in {'.md','.adoc','.rst'})
    has_arch_docs = has_arch_docs or bool(context['architecture_files'])
    if not has_arch_docs:
        findings.append(Finding('AQ-DOC-001','medium','No architecture decision records or architecture docs found',
            'No files with ADR/architecture naming were found.',
            'Important architecture choices may be forgotten or repeatedly debated.',
            'Add docs/architecture and start recording important decisions with ADRs.', 'high'))

    # tests
    test_files=[p for p in files if re.search(r'(^|/|\\)(tests?|__tests__)(/|\\)', str(p).lower()) or re.search(r'(test_|_test\.|\.spec\.|\.test\.)', p.name.lower())]
    inline_rust_tests = sum(rust_test_count(read(p)) for p in code if p.suffix.lower() == '.rs' and p not in test_files)
    test_evidence = len(test_files) + inline_rust_tests
    # One actual inline test is meaningful for a tiny crate; keep the size-based warning.
    minimum_tests = max(1 if inline_rust_tests else 3, len(code)//50)
    if test_evidence==0:
        findings.append(Finding('AQ-TST-001','high','No tests detected',
            'No conventional test files or test directories were found.',
            'Architecture refactoring becomes risky because behavior is not protected.',
            'Add characterization tests around critical workflows before structural refactoring.', 'high'))
    elif test_evidence < minimum_tests:
        findings.append(Finding('AQ-TST-001','medium','Low visible test density',
            f'{len(test_files)} test-like files' + (f' and {inline_rust_tests} inline Rust tests' if inline_rust_tests else '') + f' for {len(code)} code files.',
            'Important behavior may be unprotected during AI-generated changes.',
            'Add tests for the modules affected by upcoming architecture work.', 'medium'))

    # CI
    has_ci=any('.github/workflows' in rel(p,root).lower() or p.name.lower() in {'gitlab-ci.yml','.gitlab-ci.yml','circle.yml'} for p in files)
    if not has_ci:
        findings.append(Finding('AQ-CI-001','medium','No CI workflow detected',
            'No common CI configuration was found.',
            'New architecture regressions may be introduced without automated feedback.',
            'Add CI for tests, linting, and AQAF scan.', 'high'))

    # secrets/config
    secret_hits=[]
    for p in code[:1000]:
        txt=read(p)
        for pat in SECRET_PATTERNS:
            if pat.search(txt):
                secret_hits.append(rel(p,root)); break
    if secret_hits:
        findings.append(Finding('AQ-CFG-001','high','Possible hard-coded secret or sensitive config detected',
            'Potential secret-like pattern in: '+', '.join(secret_hits[:10]),
            'Secrets in code can leak credentials and make deployment unsafe.',
            'Move secrets/config to environment variables or a secret manager; rotate any exposed credentials.', 'medium'))

    # module boundaries
    module_dirs = [d for d in ['modules','features','domains','domain','application','infrastructure','adapters','services','src'] if (root/d).exists()]
    if len(code)>30 and not any((root/d).exists() for d in ['modules','features','domain','domains','application']) and (component or len(scope.nodes)==1):
        findings.append(Finding('AQ-MOD-001','high','Growing codebase lacks obvious domain/feature module boundaries',
            f'{len(code)} code files found, but no conventional modules/features/domain/application boundary directories.',
            'Feature additions may spread logic across unrelated files, increasing change blast radius.',
            'Introduce feature/domain modules and document module contracts before adding many more features.', 'medium'))

    # dependency direction heuristic
    dep_hits=[]
    for p in code:
        rp=rel(p,root).lower()
        if any(seg in ('/' + rp.replace('\\','/')) for seg in ['/domain/','/core/']):
            txt=read(p).lower()
            volatile=['sqlalchemy','django','flask','requests','boto3','firebase','androidx','wordpress','wp_','openai','ollama','stripe']
            if any(v in txt for v in volatile):
                dep_hits.append(rel(p,root))
    if dep_hits:
        findings.append(Finding('AQ-DEP-001','high','Core/domain code appears coupled to infrastructure or framework details',
            'Potential volatile imports/references in: '+', '.join(dep_hits[:10]),
            'Core logic becomes harder to test, replace, or reuse.',
            'Move concrete provider/framework/database calls to infrastructure adapters and expose ports/interfaces to core.', 'medium'))

    # logging/error handling heuristic
    operational_terms=['requests.','fetch(','axios','subprocess','open(','write_text','read_text','sqlite','psycopg','mysql','smtplib','shutil','ffmpeg','yt-dlp']
    operational_files=[]; logging_files=0
    for p in code:
        txt=read(p).lower()
        if any(t in txt for t in operational_terms): operational_files.append(p)
        if any(t in txt for t in ['logging.','logger.','console.error','log.error','print(']) or has_warning_call(txt, python=p.suffix.lower()=='.py'): logging_files+=1
    if operational_files and logging_files < max(1, len(operational_files)//5):
        findings.append(Finding('AQ-OBS-001','medium','Operational code has little visible logging',
            f'{len(operational_files)} files appear to touch IO/network/processes; logging appears in {logging_files} files.',
            'Failures may be hard to diagnose in production or on user machines.',
            'Add structured logs around network, filesystem, subprocess, and provider boundaries.', 'low'))

    # data migrations
    if product in {'saas_or_web_app','ai_pipeline','api_backend'}:
        has_db=any(x in sample_text for x in ['sqlite','postgres','mysql','sqlalchemy','prisma','typeorm','sequelize','mongoose'])
        has_migrations=any('migration' in rel(p,root).lower() or 'alembic' in rel(p,root).lower() or 'prisma/migrations' in rel(p,root).lower() for p in files)
        has_migrations = has_migrations or bool(context['migration_files'])
        if has_db and not has_migrations:
            findings.append(Finding('AQ-DATA-001','high','Database usage detected without obvious migration strategy',
                'Database-related terms were found, but no migration directory/tooling was detected.',
                'Schema changes may be unsafe or undocumented as the product grows.',
                'Add migration tooling and document data ownership, retention, and backup expectations.', 'medium'))

    # WP
    if product=='wordpress_plugin':
        root_php=[p for p in code if p.suffix=='.php' and p.parent==root]
        big=[p for p in root_php if p.stat().st_size>25000]
        if big or not any((root/d).exists() for d in ['src','includes','app']):
            findings.append(Finding('AQ-WP-001','high','WordPress plugin may have hook-heavy or root-file-heavy structure',
                'Root PHP files or missing src/includes structure suggest plugin logic may be concentrated around hooks.',
                'Hook-heavy plugins become hard to test and maintain.',
                'Keep hooks thin and delegate behavior to service classes; add nonce/capability/security checks.', 'medium'))

    # Android
    if product=='android':
        has_vm=any('viewmodel' in rel(p,root).lower() for p in code)
        has_multi=sum(1 for p in files if p.name.lower() in {'build.gradle','build.gradle.kts'})>1
        if not has_vm or not has_multi:
            findings.append(Finding('AQ-AND-001','medium','Android structure may need stronger UI/business separation or modularization',
                f'ViewModel files detected: {has_vm}. Multiple Gradle modules detected: {has_multi}.',
                'Growing Android apps become difficult to test when UI, state, and data logic are mixed.',
                'Use ViewModels/repositories/use cases; consider feature modules for larger apps.', 'medium'))

    # AI
    if product=='ai_pipeline':
        prompt_files=[p for p in files if 'prompt' in rel(p,root).lower() and p.suffix.lower() in {'.md','.txt','.yaml','.yml','.json'}]
        has_cache=any('cache' in rel(p,root).lower() for p in files)
        if not prompt_files or not has_cache:
            findings.append(Finding('AQ-AI-001','high','AI pipeline lacks obvious prompt registry or cache/resume structure',
                f'Prompt files: {len(prompt_files)}. Cache-related paths found: {has_cache}.',
                'AI output may be hard to reproduce, debug, or resume after failure.',
                'Centralize prompts/model config and store intermediate pipeline artifacts.', 'medium'))


    # Swift
    if product=='swift_app':
        swift_files=[p for p in code if p.suffix.lower()=='.swift']
        ui_terms=['struct ', ' view {', ': view', 'uiviewcontroller', 'nsviewcontroller']
        io_terms=['urlsession', 'filemanager', 'sqlite', 'coredata', 'userdefaults', 'keychain', 'openai', 'ollama', 'firebase', 'alamofire', 'stripe']
        ui_io=[]
        for p in swift_files:
            txt=read(p).lower()
            rp=rel(p,root).lower()
            if any(u in txt for u in ui_terms) and any(i in txt for i in io_terms):
                ui_io.append(rel(p,root))
        if ui_io:
            findings.append(Finding('AQ-SWIFT-001','high','Swift UI layer appears to own IO or business workflows',
                'Possible UI+IO coupling in: '+', '.join(ui_io[:10]),
                'SwiftUI views or UIKit controllers with direct IO/business logic become hard to test and refactor safely.',
                'Move workflows to ViewModel/store/use case/service; inject protocols/adapters and add state/service tests.', 'medium'))
        has_packages=any('package.swift'==p.name.lower() for p in files) or 'packages/' in path_text
        has_features=any(seg in path_text for seg in ['features/','feature/','modules/'])
        if len(swift_files)>25 and not (has_packages or has_features):
            findings.append(Finding('AQ-SWIFT-002','medium','Growing Swift project lacks obvious feature/package boundaries',
                f'{len(swift_files)} Swift files found without obvious Packages/Features/modules structure.',
                'AI-generated changes may spread across unrelated UI and service code.',
                'Introduce feature folders or Swift packages and document module contracts.', 'medium'))

    # Rust
    if product=='rust_app':
        rust_files=[p for p in code if p.suffix.lower()=='.rs']
        main=root/'src'/'main.rs'
        lib=root/'src'/'lib.rs'
        if main.exists():
            mt=read(main)
            main_lines=len([ln for ln in mt.splitlines() if ln.strip() and not ln.strip().startswith('//')])
            if main_lines>180 or (not lib.exists() and len(rust_files)>3):
                findings.append(Finding('AQ-RUST-001','high','Rust binary entrypoint may contain too much core logic',
                    f'src/main.rs has about {main_lines} non-comment lines; src/lib.rs exists: {lib.exists()}.',
                    'Large main.rs files are harder to unit-test and reuse; AI refactors become riskier.',
                    'Move core workflows into src/lib.rs/modules or workspace crates; keep main.rs thin.', 'medium'))
        unsafe_hits=[]
        for p in rust_files:
            txt=read(p)
            if 'unsafe ' in txt or 'unsafe{' in txt.replace(' ',''):
                # crude safety comment check near unsafe
                if 'SAFETY:' not in txt and 'Safety:' not in txt:
                    unsafe_hits.append(rel(p,root))
        if unsafe_hits:
            findings.append(Finding('AQ-RUST-002','high','Unsafe Rust detected without obvious SAFETY documentation',
                'Unsafe code in: '+', '.join(unsafe_hits[:10]),
                'Unsafe code can bypass Rust safety guarantees; hidden assumptions may become production bugs.',
                'Isolate unsafe code, add SAFETY comments/invariants and tests; consider Miri/fuzzing for critical paths.', 'medium'))
        has_cargo_lock='cargo.lock' in names
        has_deny='deny.toml' in names or 'cargo-deny' in sample_text or 'cargo deny' in path_text
        if has_cargo_lock and not has_deny:
            findings.append(Finding('AQ-RUST-003','medium','Rust dependency audit policy not detected',
                'Cargo.lock found, but no deny.toml/cargo-deny policy was detected.',
                'Advisories, duplicate crates, disallowed licenses, or source issues may be missed.',
                'Add cargo-deny or equivalent dependency/security/license checks to CI.', 'medium'))

    # New specialized extension detectors. They are opt-in per selected product profile
    # and are transparent heuristics, not comprehensive security assessments.
    if product == 'browser_extension':
        for manifest in (p for p in files if p.name.lower()=='manifest.json'):
            try:
                m=json.loads(read(manifest))
                if not isinstance(m,dict) or 'manifest_version' not in m: continue
                perms=m.get('host_permissions',[])+m.get('permissions',[])
                if not isinstance(perms,list): continue
                broad=sorted(str(v) for v in perms if v in ('<all_urls>','*://*/*','http://*/*','https://*/*'))
                if broad:
                    findings.append(Finding('AQ-EXT-001','high','Broad extension host permissions need justification',
                        f'{rel(manifest,root)} declares: {", ".join(broad)}',
                        'Broad permissions increase the potential impact of extension defects or compromise.',
                        'Reduce host permissions or use optional permissions and document why scope is required.', 'high'))
            except (ValueError,TypeError): pass
    if product == 'google_apps_script':
        for p in code:
            if p.suffix.lower() not in {'.js','.gs'}: continue
            content=read(p)
            # Only nearby text around a trigger signature is inspected; avoids pretending to parse the JS AST.
            for match in re.finditer(r'function\s+(onEdit|onOpen|doGet|doPost)\s*\(',content):
                neighborhood=content[match.start():match.start()+900]
                if 'UrlFetchApp.fetch(' in neighborhood or 'GmailApp.sendEmail(' in neighborhood:
                    findings.append(Finding('AQ-GAS-001','medium','Trigger/web entrypoint may own network/email IO',
                        f'{rel(p,root)}: {match.group(1)} near external service invocation',
                        'When entrypoints contain integration logic, retries, quotas and tests become harder to isolate.',
                        'Keep entrypoint thin and delegate to an injected service; verify actual function boundaries.', 'low'))
                    break
    if product == 'npm_library':
        for p in files:
            if p.parent==root and p.name=='package.json':
                try:
                    data=json.loads(read(p))
                    if not any(data.get(k) for k in ('exports','main','bin')):
                        findings.append(Finding('AQ-NPM-001','medium','No explicit library export or executable entrypoint detected',
                            'package.json has none of exports, main, bin.',
                            'Consumers may rely on ambiguous package entrypoints.',
                            'Define an intentional public API entrypoint or command; test the packed tarball.', 'medium'))
                except ValueError: pass

    # score
    score=100
    for f in findings:
        score -= {'high':12,'medium':7,'low':3}.get(f.severity,5)
    score=max(0,score)
    lang_summary={k:v for k,v in exts.most_common(15)}
    result={
        'aqaf_version': __version__,
        'assessor': 'static-heuristic',
        'score_kind': 'provisional_nonvalidated_heuristic_index',
        'not_a_certification': True,
        'profile_confidence': detection_confidence,
        'detected_product_type': detected_product,
        'limitations': ['Static structure and regex heuristics only', 'Does not execute target repository code', 'No measured runtime behavior, threat modeling, or performance tests', 'File absence is not proof a capability is absent', 'Index is not independently calibrated or certified'],
        'root':str(root),
        'context_evidence': context,
        'product_type':product,
        'selected_pack':pack,
        'product_profile_status':chosen['status'],
        'product_profile_coverage':chosen['coverage'],
        'detection_candidates':candidates,
        'technologies':technologies,
        'declared_capabilities':sorted(set(capabilities)),
        'recommended_target_architecture':target,
        'score':score,
        'files_scanned':len(files),
        'code_files':len(code),
        'extensions':lang_summary,
        'signals':signals,
        'findings':[f.to_dict() for f in findings]
    }
    # Methodological references are context, not validation or endorsement of detectors.
    catalog, registry = _metadata()
    source_ids = set()
    for f in result['findings']:
        refs = catalog.get(f['rule_id'], {}).get('source_ids', [])
        f['source_ids'] = refs
        source_ids.update(refs)
    result['source_registry'] = [
        {'id': sid, 'title': registry[sid]['title'], 'url': registry[sid]['url'], 'type': registry[sid]['type']}
        for sid in sorted(source_ids) if sid in registry
    ]
    # Child classifications and context are descriptive, not averaged scores.
    for node in scope.nodes:
        owned=[r['path'] for r in scope.records if r['owner']==node['id']]
        child_root=scope.root if node['root']=='.' else scope.root/node['root']
        child_code=[p for p in owned if p.suffix.lower() in CODE_EXTS]
        child_profile,child_signals,confidence,_=reg.detect(owned,child_root,child_code,pack,reader=scope.text)
        if node.get('profile_override'):
            reg.get_profile(node['profile_override']);child_profile=node['profile_override'];confidence='user-selected'
        node['classification']={'product_type':child_profile,'confidence':confidence,'signals':child_signals}
        own_tests=[p for p in owned if re.search(r'(^|/)(tests?|__tests__)/|(?:test_|_test\.|\.test\.|\.spec\.)',p.relative_to(child_root).as_posix())]
        own_docs=[p.relative_to(scope.root).as_posix() for p in owned if p.suffix.lower() in {'.md','.rst','.adoc'} and re.search(r'(?i)architecture|(?:^|/)adr(?:/|$)',p.relative_to(scope.root).as_posix())]
        parent_ids=set();parent=node.get('parent')
        while parent:
            parent_ids.add(parent);parent=next((n.get('parent') for n in scope.nodes if n['id']==parent),None)
        inherited_docs=[r['relative'] for r in scope.records if r['owner'] in parent_ids and r['path'].suffix.lower() in {'.md','.rst','.adoc'} and re.search(r'(?i)architecture|(?:^|/)adr(?:/|$)',r['relative'])]
        inherited_ci=[r['relative'] for r in scope.records if r['owner'] in parent_ids and '.github/workflows/' in r['relative']]
        node['assessment']={'code_files':len(child_code),'test_like_files':len(own_tests),'architecture_files':own_docs,'inherited_architecture':inherited_docs,'inherited_ci':inherited_ci,
                            'status':'selected_source_only' if child_code else 'no_collected_core_code',
                            'runtime_tests_executed':False,'score':None}
    result['projects']=scope.graph
    result['extensions_full']=dict(sorted(exts.items()))
    scope_metadata=scope.report()
    if review_signals:
        from .review import review_files
        result['review'] = review_files(files, root, scope=scope, **(review_options or {}))
    result['scope']=scope_metadata
    result['scope']['analysis_root']=str(root)
    from .unknowns import scan_unknowns
    result['unknowns']=scan_unknowns(result)
    result['scope']['selected_component']=component
    result['score_scope']='selected_container_source_not_an_average_of_children'
    result['assessment_state']='source_collected' if code else 'no_collected_core_code'
    result['limitations'].append('Scored absence hints describe the selected scope; unsupported or excluded source is not verified.')
    if review_knowledge:
        from .knowledge import review_agenda
        result['review_knowledge']=review_agenda(scope,product,paths=files)
    return result

def md_report(r):
    lines=[]
    lines.append('# AQAF Architecture Report')
    lines.append('')
    lines.append(f"**AQAF version:** {r['aqaf_version']}")
    lines.append(f"**Product type:** {r['product_type']}")
    lines.append(f"**Pack:** {r.get('selected_pack','auto')} | **Detector coverage:** {r.get('product_profile_coverage','unknown')}")
    lines.append(f"**Technologies:** {', '.join(r.get('technologies',[])) or 'not classified'}")
    lines.append(f"**Declared capabilities:** {', '.join(r.get('declared_capabilities',[])) or 'none'}")
    lines.append(f"**Provisional heuristic index:** {r['score']} / 100 (NOT a validated quality score or certification)")
    lines.append(f"**Product classification:** {r['profile_confidence']} confidence; inferred {r['detected_product_type']}")
    lines.append(f"**Recommended target:** {r['recommended_target_architecture']}")
    lines.append(f"**Files scanned:** {r['files_scanned']} total, {r['code_files']} code files")
    lines.append('')
    context = r.get('context_evidence', {})
    if context.get('root'):
        lines.append('## Parent context (metadata only)')
        lines.append('Conventional source-slice parent: ' + context['root'])
        for key in ('architecture_files', 'migration_files'):
            for path in context.get(key, []): lines.append('- ' + path)
        lines.append('Presence is not proof of adequacy; parent source code was not scanned.')
        lines.append('')
    if 'scope' in r:
        scope=r['scope']
        lines.extend(['## Scope and project coverage','',
          'Policy: '+scope['policy']+'; respect .gitignore: '+str(scope['respect_gitignore']),
          'Assessment state: '+r.get('assessment_state','unknown')+'; index applies only to selected source.',
          'Discovered roots: '+str(len(r.get('projects',{}).get('nodes',[]))),
          'Pruned subtrees are not a full physical census unless explicitly inventoried.',
          'Scope outcomes: '+json.dumps(scope['counts'],sort_keys=True),''])
        for node in r.get('projects',{}).get('nodes',[]):
            lines.append('- '+node['id']+' / '+node['root']+' / '+node['relationship']+' / '+str(node['files_collected'])+' owned-candidate files')
        lines.append('')
    lines.append('## Extension summary')
    lines.append('')
    for ext,count in r.get('extensions_full',r['extensions']).items(): lines.append(f'- `{ext or "[no extension]"}`: {count}')
    lines.append('')
    lines.append('## Findings')
    lines.append('')
    if not r['findings']:
        lines.append('No major AQAF findings detected by the lightweight scanner. This does not mean the architecture is perfect; run language-specific tools and human review.')
    for i,f in enumerate(r['findings'],1):
        lines.append(f"### {i}. {f['rule_id']} — {f['title']}")
        lines.append('')
        lines.append(f"- **Severity:** {f['severity']}")
        lines.append(f"- **Confidence:** {f['confidence']}")
        if f.get('source_ids'): lines.append(f"- **Foundational sources (not detector validation):** {', '.join(f['source_ids'])}")
        lines.append(f"- **Observed evidence:** {f['evidence']}")
        lines.append(f"- **Risk:** {f['risk']}")
        lines.append(f"- **Recommendation:** {f['recommendation']}")
        lines.append('')
    if r.get('suppressed_findings'):
        lines.append(f"## Suppressed findings ({len(r['suppressed_findings'])})")
        lines.append('Suppression does not verify safety; each entry requires a written reason.')
        lines.append('')
        for f in r['suppressed_findings']:
            lines.append(f"- {f['rule_id']} ({f['fingerprint'][:12]}): {f['suppression_reason']}")
        lines.append('')
    if r.get('unknowns'):
        from .unknowns import markdown as unknowns_markdown
        lines.extend(unknowns_markdown(r['unknowns']))
    if (r.get('baseline') or {}).get('resolved'):
        lines.append(f"## Resolved since baseline ({len(r['baseline']['resolved'])})")
        lines.append('Findings present in the baseline report that this scan no longer reports. Suppressed findings are not counted as resolved.')
        lines.append('')
        for f in r['baseline']['resolved']:
            lines.append(f"- {f['rule_id']} ({f['severity']}): {f['title']}")
        lines.append('')
    if r.get('source_registry'):
        lines.append('## Source references')
        lines.append('These sources contextualize the architectural concern, but do **not** endorse AQAF or prove detector accuracy.')
        for src in r['source_registry']:
            lines.append(f"- {src['id']}: {src['title']} — {src['url']}")
        lines.append('')
    if 'review_knowledge' in r:
        from .knowledge import markdown_agenda
        lines.extend(markdown_agenda(r['review_knowledge']))
    if 'review' in r:
        review = r['review']
        lines.append('## Experimental unscored review')
        lines.append('Static observations and unreviewed candidates; no confirmed defects, score impact or baseline gates.')
        for signal in review['signals']:
            location = signal['locations'][0]
            lines.append(f"- {signal['check_id']} / {signal['kind']} — {location['path']}:{location['line']}:{location['column']}: {signal['observed_fact']}")
            for control in signal['observed_controls']: lines.append('  - Observed control: ' + control)
            for unknown in signal['unknowns']: lines.append('  - Unknown: ' + unknown)
            lines.append('  - Next characterization: ' + signal['next_test'])
        coverage=review['scope']
        lines.append('Review files: '+str(coverage.get('files_eligible','unknown'))+' eligible, '+str(coverage['files_attempted'])+' attempted, '+str(coverage.get('files_assessed','unknown'))+' assessed with partial language support.')
        if coverage.get('zero_attempt_reason'):lines.append('Zero-attempt reason: '+coverage['zero_attempt_reason'])
        lines.extend(['','| Component | Language | Eligible | Attempted | Assessed |','|---|---|---:|---:|---:|'])
        for group in coverage.get('groups',[]):lines.append('| '+group['owner']+' | '+group['language']+' | '+str(group['eligible'])+' | '+str(group['attempted'])+' | '+str(group['assessed'])+' |')
        lines.append('')
        lines.append('Review scope outcomes: ' + json.dumps(review['scope']['outcomes'], sort_keys=True))
        for limit in review['limitations']: lines.append('- ' + limit)
        lines.append('Review sources contextualize concerns, not detector accuracy or endorsement:')
        for source in review['source_registry']: lines.append(f"- {source['id']}: {source['title']} — {source['url']}")
        lines.append('')
    lines.append('## Limitations')
    for limit in r['limitations']:
        lines.append('- ' + limit)
    lines.append('')
    lines.append('## Next Codex prompt')
    lines.append('')
    lines.append('```text')
    lines.append('Read AGENTS.md and ARCHITECTURE_REPORT.md. Do not edit files yet. Turn the top 3 AQAF findings into a safe, tests-first refactor roadmap with small commits and rollback strategy.')
    lines.append('```')
    lines.append('')
    return '\n'.join(lines)

def fingerprint(f):
    """Stable enough for baseline comparison when rule + summarized evidence stay unchanged."""
    payload = f['rule_id'] + '\0' + f['evidence']
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def add_fingerprints(report):
    for f in report['findings']:
        f['fingerprint'] = fingerprint(f)
    return report


def apply_suppressions(report, config_path):
    report['suppressed_findings'] = []
    if not config_path.exists():
        return report
    try:
        data = json.loads(config_path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ValueError(f'Invalid suppression configuration {config_path}: {exc}') from exc
    entries = data.get('suppressions', [])
    if not isinstance(entries, list):
        raise ValueError('suppressions must be a list')
    for item in entries:
        if not isinstance(item, dict) or not item.get('rule_id') or not str(item.get('reason','')).strip():
            raise ValueError('Each suppression requires rule_id and nonempty reason')
    retained = []
    for f in report['findings']:
        matched = next((x for x in entries if x['rule_id'] == f['rule_id'] and (not x.get('fingerprint') or x['fingerprint'] == f['fingerprint'])), None)
        if matched:
            f['suppression_reason'] = matched['reason']
            report['suppressed_findings'].append(f)
        else:
            retained.append(f)
    report['findings'] = retained
    return report


def add_baseline_diff(report, baseline_path):
    if baseline_path is None:
        report['baseline'] = None
        for f in report['findings']:
            f['status'] = 'unbaselined'
        return report
    try:
        old = json.loads(baseline_path.read_text(encoding='utf-8'))
        previous = {f.get('fingerprint') or fingerprint(f) for f in old['findings']}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f'Invalid baseline JSON: {exc}') from exc
    for f in report['findings']:
        f['status'] = 'existing' if f['fingerprint'] in previous else 'new'
    current = {f['fingerprint'] for f in report['findings']} | {f.get('fingerprint') for f in report.get('suppressed_findings', [])}
    resolved = [{'rule_id': f.get('rule_id'), 'title': f.get('title'), 'severity': f.get('severity'), 'fingerprint': f.get('fingerprint') or fingerprint(f)}
                for f in old['findings'] if (f.get('fingerprint') or fingerprint(f)) not in current]
    report['baseline'] = {'file': str(baseline_path), 'new_findings': sum(f['status']=='new' for f in report['findings']),
                          'resolved': resolved,
                          'counts': {'new': sum(f['status']=='new' for f in report['findings']), 'existing': sum(f['status']=='existing' for f in report['findings']), 'resolved': len(resolved)}}
    return report


def sarif_report(r):
    # SARIF 2.1.0 subset; useful for IDE/CI ingestion. Most heuristic findings are not line-specific.
    results=[]
    for f in r['findings']:
        results.append({
            'ruleId': f['rule_id'], 'level': {'high':'error','medium':'warning','low':'note'}.get(f['severity'],'note'),
            'message': {'text': f['title'] + '. Evidence: ' + f['evidence'] + '. Recommendation: ' + f['recommendation']},
            'partialFingerprints': {'primaryLocationLineHash': f['fingerprint']},
            'properties': {'confidence': f['confidence'], 'baselineStatus': f.get('status','uncompared'), 'assessmentType': 'heuristic'},
        })
    return {'version':'2.1.0', '$schema':'https://json.schemastore.org/sarif-2.1.0.json', 'runs':[{
        'tool':{'driver':{'name':'AQAF', 'version':__version__,
          'rules':[{'id': k, 'name':k, 'shortDescription':{'text':v[1]}} for k,v in RULE_META.items()]}},
        'results':results,
        'properties':{'disclaimer':'Heuristic architecture hints, not security findings or a validated score.',
                      **({'review_knowledge':r['review_knowledge']} if 'review_knowledge' in r else {}),
                      **({'aqafReview':r['review']} if 'review' in r else {}),
                      **({'aqafScope':r['scope'],'aqafProjects':r['projects']} if 'scope' in r else {})}
    }]}


def registry_command(argv):
    ap=argparse.ArgumentParser(prog='aqaf '+argv[0],description='Inspect declarative profile/pack manifests')
    ap.add_argument('action',choices=['list','show','validate'])
    ap.add_argument('identifier',nargs='?',help='Profile ID / pack ID / JSON path')
    ap.add_argument('--profile-dir',action='append',default=[])
    ap.add_argument('--pack-dir',action='append',default=[])
    args=ap.parse_args(argv[1:])
    kind=argv[0]
    if args.action=='validate':
        if kind!='profiles' or not args.identifier:
            ap.error('Only `profiles validate path/to/file.json` is supported')
        try:
            doc=read_doc(Path(args.identifier),'profile')
            print(json.dumps({'valid':True,'id':doc['id']},indent=2))
        except ProfileError as e: ap.error(str(e))
        return 0
    try:
        reg=Registry(args.profile_dir,args.pack_dir)
        store=reg.profiles if kind=='profiles' else reg.packs
        if args.action=='show':
            if not args.identifier: ap.error('show requires an ID')
            if args.identifier not in store: raise ProfileError(f'Unknown {kind}: {args.identifier}')
            print(json.dumps(store[args.identifier],indent=2))
        else:
            print(json.dumps([{'id':v['id'],'name':v['name'],'status':v.get('status','mixed_coverage'),
                'coverage':v.get('coverage','mixed_coverage')} for v in sorted(store.values(),key=lambda d:d['id'])],indent=2))
    except ProfileError as e: ap.error(str(e))
    return 0


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    from . import project_commands
    if project_commands.matches(argv):return project_commands.main(argv)
    if project_commands.wants_group_help(argv):return project_commands.group_help(argv)
    if argv and argv[0] in ('profiles','packs'): return registry_command(argv)
    ap=argparse.ArgumentParser(description='AQAF local architecture scanner (heuristic, non-certifying)')
    ap.add_argument('repo', nargs='?', default='.', help='Repository path')
    ap.add_argument('--version', action='version', version='AQAF '+ __version__)
    ap.add_argument('--format', choices=['md','json','sarif','all'], default='md')
    ap.add_argument('--output','-o', default='-')
    ap.add_argument('--profile', default='auto', help='Registry profile ID; see `aqaf profiles list`')
    ap.add_argument('--pack', default='auto', help='Limit auto-detection to a pack; see `aqaf packs list`')
    ap.add_argument('--profile-dir', action='append', default=[], help='Additional data-only JSON profile directory')
    ap.add_argument('--pack-dir', action='append', default=[], help='Additional data-only JSON pack directory')
    ap.add_argument('--capability', action='append', default=[], help='Declared contextual capability (repeatable)')
    ap.add_argument('--gitignore', action=argparse.BooleanOptionalAction, default=True, help='Respect root/nested .gitignore by default; --no-gitignore explicitly opts out')
    ap.add_argument('--scope-policy', choices=['typed','legacy'], default='typed', help='Type-aware ownership/exclusions or historical directory rules')
    ap.add_argument('--scope-config', help='Operator-selected bounded JSON scope configuration')
    ap.add_argument('--inventory-all', action='store_true', help='Also count metadata in pruned subtrees; never analyze their bodies')
    ap.add_argument('--component', help='Analyze only one discovered component ID or root-relative path')
    ap.add_argument('--review-max-files', type=int, default=1000, help='Maximum experimental file attempts per scan')
    ap.add_argument('--review-max-bytes', type=int, default=20000000, help='Maximum experimental source bytes per scan')
    ap.add_argument('--review-file-bytes', type=int, default=256000, help='Maximum experimental bytes per file')
    ap.add_argument('--review-cursor-in', help='Validate bounded full-content continuation state from an earlier page')
    ap.add_argument('--review-cursor-out', help='Write new immutable continuation state outside the source')
    ap.add_argument('--review-offset', type=int, default=0, help='Deterministic selection offset; separately reported partial coverage')
    ap.add_argument('--review-knowledge',action='store_true',help='Optional book-informed human review agenda; unknown/unscored, no target execution')
    ap.add_argument('--review-signals', action='store_true', help='Opt-in bounded multi-language review observations; experimental and unscored')
    ap.add_argument('--baseline', help='Earlier AQAF JSON report for new/existing comparison')
    ap.add_argument('--config', help='Path to local .aqaf.json suppression config; defaults to <repo>/.aqaf.json')
    ap.add_argument('--fail-on', choices=['off','new-high','new-medium'], default='off', help='Optional CI gate for findings; requires a baseline')
    args=ap.parse_args(argv)
    repo=Path(args.repo).resolve()
    if not repo.is_dir():
        ap.error(f'Repository is not a directory: {repo}')
    if args.fail_on!='off' and not args.baseline:
        ap.error('--fail-on requires --baseline to avoid gating historic heuristic findings')
    try:
        registry=Registry(args.profile_dir,args.pack_dir)
        if args.pack!='auto': registry.get_pack(args.pack)
        from .scope import config_document
        if args.review_max_files<1 or args.review_max_bytes<1 or args.review_file_bytes<1 or args.review_offset<0:raise ValueError('Review budgets must be positive; offset must be nonnegative')
        if args.review_file_bytes>1500000 or args.review_max_files>100000 or args.review_max_bytes>256000000:raise ValueError('Review budget exceeds bounded maximum')
        session=None
        if args.review_cursor_in or args.review_cursor_out:
            if not args.review_signals:raise ValueError('Continuation requires --review-signals')
            if args.component:raise ValueError('Use a scoped root/configuration for continuation; --component continuation is not supported')
            from .scope import Scope
            from .cursor import identity,load
            session=Scope(repo,args.gitignore,args.scope_policy,config_document(args.scope_config),args.inventory_all).build()
            cursor_options={'max_files':args.review_max_files,'max_total_bytes':args.review_max_bytes,'max_file_bytes':args.review_file_bytes}
            cursor_identity=identity(session,cursor_options)
            if args.review_cursor_in:
                if args.review_offset:raise ValueError('Choose a cursor or an explicit offset, not both: the cursor already carries the next offset')
                args.review_offset=load(args.review_cursor_in,cursor_identity)
        r=add_fingerprints(scan(repo,args.profile,registry,args.pack,args.capability,review_signals=args.review_signals,
            respect_gitignore=args.gitignore,scope_policy=args.scope_policy,scope_config=config_document(args.scope_config),
            inventory_all=args.inventory_all,component=args.component,session=session,review_knowledge=args.review_knowledge,
            review_options={'max_files':args.review_max_files,'max_total_bytes':args.review_max_bytes,'max_file_bytes':args.review_file_bytes,'offset':args.review_offset}))
        if args.review_signals and r.get('review'):
            # Say whether this page ends the continuation, so callers do not page until a cap.
            page_scope=r['review']['scope']
            reached=min(page_scope['files_eligible'],args.review_offset+page_scope['files_attempted'])
            page_scope['files_remaining']=page_scope['files_eligible']-reached
            page_scope['complete']=page_scope['files_remaining']==0
            if args.review_offset and not page_scope['files_attempted'] and page_scope['complete']:page_scope['page_note']='continuation_complete: no eligible files remain after this offset'
        if args.review_cursor_out:
            from .cursor import write
            # Include byte/size failures in the page; never silently merge older pages.
            write(args.review_cursor_out,session,cursor_identity,min(r['review']['scope']['files_eligible'],args.review_offset+r['review']['scope']['files_attempted']),r['review']['scope']['files_eligible'])
        r=apply_suppressions(r,Path(args.config).resolve() if args.config else repo/'.aqaf.json')
        r=add_baseline_diff(r,Path(args.baseline) if args.baseline else None)
    except (ValueError, ProfileError) as exc:
        ap.error(str(exc))
    if args.format=='all':
        if args.output=='-':ap.error('--format all requires --output DIRECTORY')
        from .artifacts import write_bundle
        try:write_bundle(r,Path(args.output))
        except (ValueError,OSError) as exc:ap.error(str(exc))
        print('Wrote report.json, report.md and report.sarif to '+args.output)
        return 2 if args.fail_on!='off' and any(f['status']=='new' and f['severity'] in ({'high'} if args.fail_on=='new-high' else {'high','medium'}) for f in r['findings']) else 0
    out=json.dumps(r,indent=2) if args.format=='json' else json.dumps(sarif_report(r),indent=2) if args.format=='sarif' else md_report(r)
    if args.output=='-': print(out)
    else:
        dest=Path(args.output)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(out,encoding='utf-8')
        print(f'Wrote {dest}')
    if args.fail_on != 'off':
        allowed={'new-high':{'high'},'new-medium':{'high','medium'}}[args.fail_on]
        if any(f['status']=='new' and f['severity'] in allowed for f in r['findings']):
            return 2
    return 0

if __name__ == '__main__': sys.exit(main())
