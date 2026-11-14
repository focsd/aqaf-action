"""One read-only inventory, ownership policy and evidence-driven source plan.

Target metadata is data. No ignore/config/manifest can expand the authorized root,
run a command, or cause symlink traversal. Pruned subtrees are not falsely counted
as fully inventoried; --inventory-all requests a full metadata-only census.
"""
from __future__ import annotations
from collections import Counter,OrderedDict,defaultdict
import fnmatch
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import stat
from .ignore import parse_ignore,ignore_decision,ignore_evidence,MAX_IGNORE_BYTES,MAX_RULES
from .projects import node_for,graph,archived,marker_family,safe_relative,MAX_PROJECTS

LEGACY_SKIP={'.git','.hg','.svn','node_modules','.venv','venv','__pycache__','dist','build','.next','.gradle','target','vendor'}
HARD_SKIP={'.git','.hg','.svn'}
DEPENDENCIES={'node_modules','vendor','.pnpm-store','.npm','.nuget','.rustup','.tox','.nox','.eggs','site-packages','.intellijPlatform','.rustup'}
# A project that declares one of these build tools emits its compiled bundles into out/ (electron-vite, electron-forge).
BUILD_TOOL_CONFIG=r'(?:electron\.vite\.config|forge\.config)\.(?:[cm]?[jt]s)'
GENERATED={'__pycache__','dist','build','.next','.gradle','target','.nuxt','.svelte-kit','.kotlin','.cxx','TestResults','.build','.swiftpm','CMakeFiles','.vs'}
METADATA={'.DS_Store','Thumbs.db','desktop.ini'}
LANGUAGES={'.js':'javascript','.mjs':'javascript','.cjs':'javascript','.ts':'typescript','.mts':'typescript','.cts':'typescript',
 '.jsx':'jsx','.tsx':'tsx','.gs':'javascript','.py':'python','.kt':'kotlin','.kts':'kotlin','.java':'java','.cs':'csharp',
 '.php':'php','.rs':'rust','.ps1':'powershell','.psm1':'powershell','.sh':'shell','.bash':'shell','.zsh':'shell',
 '.sql':'sql','.html':'html','.htm':'html','.swift':'swift','.go':'go','.c':'c','.cpp':'cpp','.cc':'cpp','.h':'c_header',
 '.m':'objective_c','.mm':'objective_cpp','.rb':'ruby','.pl':'perl','.pm':'perl','.groovy':'groovy','.r':'r',
 '.bat':'cmd','.cmd':'cmd','.command':'shell'}
ROLE_ORDER={'production':0,'source':1,'unknown':2,'tooling':3,'tests':4,'docs':5,'fixture':6,'archive':7,'generated':8,'dependency':9,'metadata':10}
MAX_CONFIG_BYTES=131072
MAX_FILES=500000
MAX_MANIFESTS=2048
CACHE_BYTES=64*1024*1024


def matches(relative,patterns):
    return any(fnmatch.fnmatchcase(relative,p) or (p.endswith('/**') and relative==p[:-3]) for p in patterns)


class ScopeConfig(dict):
    """Effective JSON plus explicitly supplied control-file provenance."""
    control=None


def config_document(path):
    if path is None:return {}
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_CONFIG_BYTES:raise ValueError('Scope configuration must be a bounded regular JSON file')
    try:data=json.loads(path.read_text(encoding='utf-8'))
    except (OSError,ValueError,RecursionError) as exc:raise ValueError('Invalid scope configuration') from exc
    document=ScopeConfig(validate_config(data));document.control={'path':str(path.absolute()),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'kind':'operator_scope_config'}
    return document


def validate_config(data):
    if not isinstance(data,dict):raise ValueError('Scope configuration must be an object')
    if set(data)-{'schema_version','include','exclude','source_roots','projects','roles','review_roles','sql_dialect'}:raise ValueError('Unknown scope configuration field')
    if data.get('schema_version',1)!=1:raise ValueError('Unsupported scope configuration version')
    for key in ('include','exclude','source_roots'):
        values=data.get(key,[])
        if not isinstance(values,list) or len(values)>256 or not all(safe_relative(p) for p in values):raise ValueError('Scope '+key+' must be bounded root-relative paths/patterns')
    roles=data.get('roles',{})
    if not isinstance(roles,dict) or len(roles)>256 or not all(safe_relative(p) and r in ROLE_ORDER for p,r in roles.items()):raise ValueError('Invalid scope roles')
    projects=data.get('projects',[])
    if not isinstance(projects,list) or len(projects)>128:raise ValueError('Invalid scope projects')
    for item in projects:
        if not isinstance(item,dict) or set(item)-{'root','profile','source_roots'} or not safe_relative(item.get('root')):raise ValueError('Invalid declared project')
        if item.get('profile') is not None and not re.fullmatch('[a-z][a-z0-9_]{1,63}',str(item['profile'])):raise ValueError('Invalid declared project profile')
        values=item.get('source_roots',[])
        if not isinstance(values,list) or not all(safe_relative(p) for p in values):raise ValueError('Invalid project source roots')
    rr=data.get('review_roles',['production','source','unknown','tooling'])
    if not isinstance(rr,list) or not all(r in ROLE_ORDER for r in rr):raise ValueError('Invalid review roles')
    if data.get('sql_dialect','unknown') not in {'unknown','sqlite','postgresql','mysql','sqlserver'}:raise ValueError('Unsupported SQL dialect')
    return data


class ReadCache:
    def __init__(self,root,max_bytes=None):
        self.root=root;self.max_bytes=max_bytes;self.enabled=True;self.entries=OrderedDict();self.size=0;self.hits=0;self.reads=0;self.bytes_read=0;self.failures=Counter();self.dir_fds=OrderedDict();self.evidence={}

    def close(self):
        for fd in self.dir_fds.values():
            try:os.close(fd)
            except OSError:pass
        self.dir_fds.clear()

    def __del__(self):self.close()

    def _open(self,relative):
        if os.open in os.supports_dir_fd and hasattr(os,'O_NOFOLLOW'):
            parent=PurePosixPath(relative).parent.as_posix()
            if parent not in self.dir_fds:
                fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:
                    for part in PurePosixPath(parent).parts:
                        child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
                except BaseException:os.close(fd);raise
                self.dir_fds[parent]=fd
                while len(self.dir_fds)>64:
                    _,old=self.dir_fds.popitem(last=False);os.close(old)
            self.dir_fds.move_to_end(parent)
            fd=os.open(PurePosixPath(relative).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.dir_fds[parent])
            if not stat.S_ISREG(os.fstat(fd).st_mode):os.close(fd);raise OSError('Not a regular source file')
            return os.fdopen(fd,'rb')
        candidate=self.root
        for part in PurePosixPath(relative).parts:
            candidate=candidate/part
            if candidate.is_symlink():raise OSError('Source symlink rejected')
        return candidate.open('rb')

    def read(self,path,limit=1500001):
        path=Path(path)
        try:relative=path.relative_to(self.root)
        except ValueError:return b''
        key=relative.as_posix();cached=self.entries.get(key) if self.enabled else None
        if cached and (cached[1] or len(cached[0])>=limit):
            self.hits+=1;self.entries.move_to_end(key);return cached[0][:limit]
        remaining=self.max_bytes-self.bytes_read if self.max_bytes is not None else limit+1
        if remaining<=0:
            self.failures['read_budget']+=1;return b''
        read_limit=min(limit+1,remaining)
        try:
            with self._open(key) as stream:raw=stream.read(read_limit)
        except OSError:self.failures['unreadable_or_symlink']+=1;return b''
        self.reads+=1;self.bytes_read+=len(raw);complete=len(raw)<=limit and not (read_limit<limit+1 and len(raw)==read_limit)
        if not complete and read_limit<limit+1:self.failures['read_budget']+=1
        raw=raw[:limit]
        self.evidence[key]={'path':key,'sha256':hashlib.sha256(raw).hexdigest(),'complete':complete,'bytes':len(raw)}
        old=self.entries.pop(key,None)
        if old:self.size-=len(old[0])
        if self.enabled and len(raw)<=CACHE_BYTES:
            self.entries[key]=(raw,complete);self.size+=len(raw)
            while self.size>CACHE_BYTES:
                _,value=self.entries.popitem(last=False);self.size-=len(value[0])
        return raw

    def text(self,path,limit=1500001):return self.read(path,limit).decode('utf8','ignore')


def folder_reason(relative,name,families,names=None):
    parts=PurePosixPath(relative).parts
    if name in HARD_SKIP:return 'vcs_metadata'
    if name in DEPENDENCIES or name in {'.venv','venv'}:return 'dependency_installation'
    if re.fullmatch(r'(?:pyodide|monaco_support)(?:_[A-Za-z0-9.-]+)?',name):return 'browser_runtime_dependency'
    if name in {'Pods','DerivedData','.dart_tool'}:return 'platform_dependency_or_generated'
    if name.startswith('cmake-build-'):return 'native_generated_output'
    if name in GENERATED or name.startswith('.cache') or name in {'.pytest_cache','.ruff_cache','.mypy_cache','.nox','.idea','.codex-logs'}:return 'generated_or_cache'
    if '.yarn' in parts and any(p in {'cache','unplugged','sdks'} for p in parts[parts.index('.yarn')+1:]):return 'node_dependency_store'
    if '.cargo' in parts and any(p in {'registry','git','bin'} for p in parts[parts.index('.cargo')+1:]):return 'rust_dependency_toolchain'
    if name in {'bin','obj'} and 'dotnet' in families:return 'dotnet_generated_output'
    if name in {'archives','archive','backups','backup','snapshots','__MACOSX','.tmp-import'}:return 'archive_or_metadata'
    if any(re.search(r'(?i)(?:canary-source|release-stage|windows-release|staging-copy)',p) for p in parts):return 'generated_project_copy'
    if name in {'submissions','uploaded_zip_contents','dropins'}:return 'submitted_project_corpus'
    if name in {'wp-admin','wp-includes'} and 'wordpress' in families:return 'wordpress_core_dependency'
    if 'wordpress' in families and len(parts)>=2 and parts[-2]=='wp-content' and name in {'plugins','themes','uploads'}:return 'wordpress_deployed_package'
    if name in {'extensions','plugins'} and names and any(n.endswith('.jar') for n in names):return 'installed_extension_cache'
    if names:
        if 'packages.xml' in names and {'build-tools','platform-tools','platforms'} & set(names):return 'android_sdk_toolchain'
        if 'pyvenv.cfg' in names or (re.match(r'^\.?venv[_-]',name) and {'Lib','lib','Scripts','bin'} & set(names)):return 'python_environment'
        if name=='packages' and any(n.endswith(('.nupkg','.nuspec')) for n in names):return 'restored_nuget_packages'
        if 'packages' in parts[:-1] and re.search(r'\.\d+\.\d+',name) and any(n.endswith('.nuspec') for n in names) and not any(n.endswith('.csproj') for n in names):return 'restored_nuget_packages'
    return None


def file_role(relative):
    p=PurePosixPath(relative);parts=p.parts
    if p.name in METADATA or p.name.startswith('._') or '__MACOSX' in parts:return 'metadata'
    if p.name=='.gitignore':return 'metadata'
    if p.suffix.lower()=='.swift' and any(x.lower()=='tests' for x in parts[:-1]):return 'tests'
    if any(x in {'tests','test','__tests__'} for x in parts[:-1]) or re.search(r'(^test_|_test\.|\.test\.|\.spec\.)',p.name):return 'tests'
    if any(x in {'fixtures','__fixtures__'} for x in parts[:-1]):return 'fixture'
    if any(x in {'docs','references'} for x in parts[:-1]) or p.suffix.lower() in {'.md','.rst','.adoc'}:return 'docs'
    if any(x in {'tools','scripts','artifacts','.github'} for x in parts[:-1]):return 'tooling'
    if any(x in {'src','app','lib','apps','services','crates','modules','features','domain','application'} for x in parts[:-1]):return 'production'
    return 'unknown'


class Scope:
    def __init__(self,root,respect_gitignore=True,policy='typed',config=None,inventory_all=False,max_directories=1000000,max_entries=2000000,max_depth=256,max_read_bytes=None):
        self.root=Path(root).resolve();self.respect_gitignore=respect_gitignore;self.policy=policy
        self.walk_limits=(max_directories,max_entries,max_depth);self.max_read_bytes=max_read_bytes
        if policy not in {'typed','legacy'}:raise ValueError('Unknown scope policy')
        self.config_control=getattr(config,'control',None);self.config=validate_config(config or {});self.inventory_all=inventory_all;self.cache=ReadCache(self.root,max_read_bytes)
        self.files=[];self.records=[];self.by_path={};self.nodes=[];self.exclusions=[];self.ignore_sources=[];self.diagnostics=[]
        self.counts=Counter();self.all_extensions=Counter();self.collected_extensions=Counter();self.role_counts=Counter();self._seen=0
        self.graph={};self.source_plan=[];self.ambiguous_roots=[];self._ignored_rules=0
        self.include=self.config.get('include',[]);self.exclude=self.config.get('exclude',[])

    def _can_descend_include(self,relative):
        for pattern in self.include:
            prefix=re.split(r'[*?\[]',pattern,maxsplit=1)[0].rstrip('/')
            if not prefix or prefix==relative or prefix.startswith(relative+'/') or relative.startswith(prefix+'/'):return True
        return False

    def _excluded(self,relative,reason,directory=False,evidence=None):
        self.counts[('pruned_directories:' if directory else 'excluded_files:')+reason]+=1
        if len(self.exclusions)<2000:self.exclusions.append({'path':relative,'reason':reason,'kind':'directory' if directory else 'file',**({'evidence':evidence} if evidence else {})})

    def build(self):
        stack=[(self.root,[],set(),None)]
        while stack:
            directory,parent_rules,parent_families,inherited=stack.pop();relative=directory.relative_to(self.root).as_posix()
            if self.counts['directories_visited']>=self.walk_limits[0] or self.counts['entries_visited']>=self.walk_limits[1]:
                self.diagnostics.append({'path':relative,'reason':'scope_traversal_budget'});break
            if len(directory.relative_to(self.root).parts)>self.walk_limits[2]:
                self.diagnostics.append({'path':relative,'reason':'scope_depth_budget'});continue
            self.counts['directories_visited']+=1
            try:
                with os.scandir(directory) as scan:
                    entries=[]
                    for entry in scan:
                        if self.counts['entries_visited']>=self.walk_limits[1]:
                            self.diagnostics.append({'path':relative,'reason':'scope_traversal_budget'});break
                        entries.append(entry);self.counts['entries_visited']+=1
                    entries.sort(key=lambda e:e.name)
            except OSError:
                self.diagnostics.append({'path':relative,'reason':'unreadable_directory'});continue
            names={e.name for e in entries};rules=parent_rules;families=set(parent_families)
            if relative!='.' and self.policy=='typed' and not inherited:
                why=folder_reason(relative,directory.name,families,names)
                if why and not self._can_descend_include(relative):
                    self._excluded(relative,why,True)
                    if not self.inventory_all:continue
                    inherited=why
            if self.respect_gitignore and '.gitignore' in names and (not inherited or (inherited not in {'gitignore','operator_exclude','vcs_metadata'} and self._can_descend_include(relative))):
                control=directory/'.gitignore'
                if not control.is_symlink():
                    before_failures=sum(self.cache.failures.values())
                    raw=self.cache.read(control,MAX_IGNORE_BYTES+1);rp=control.relative_to(self.root).as_posix()
                    if sum(self.cache.failures.values())!=before_failures:raise ValueError('Unreadable .gitignore; refusing to broaden scope: '+rp)
                    parsed,error=parse_ignore(raw,rp)
                    if self._ignored_rules+len(parsed)>MAX_RULES:error='gitignore_rule_limit';parsed=[]
                    self._ignored_rules+=len(parsed);rules=parent_rules+parsed;self.ignore_sources.append(ignore_evidence(raw,rp))
                    if error:raise ValueError('Cannot safely apply '+rp+': '+error+'; review this ignore file or explicitly use --no-gitignore')
            visible_names=[]
            for entry in entries:
                rp=entry.name if relative=='.' else relative+'/'+entry.name
                ignored,_=ignore_decision(rp,entry.is_dir(follow_symlinks=False),rules) if self.respect_gitignore else (False,None)
                if not ignored and not entry.is_symlink():visible_names.append(entry.name)
            node=None
            if (not inherited or (inherited not in {'gitignore','operator_exclude','vcs_metadata'} and matches(relative,self.include))) and len(self.nodes)<MAX_PROJECTS and self.counts['manifests_read']<MAX_MANIFESTS:
                node=node_for(directory,relative,visible_names,self.cache.text,root=relative=='.')
                if node and (relative=='.' or not archived(relative)):
                    # Marker plus source/entrypoint proximity; avoid package metadata alone.
                    credible=relative=='.' or bool(set(visible_names)&{'src','app','lib','index.js','main.py','main.go','Program.cs','main.rs'}) or any(Path(n).suffix.lower() in LANGUAGES for n in visible_names)
                    self.counts['manifests_read']+=len(node['evidence'])
                    if credible:
                        self.nodes.append(node);families.update(node['families'])
                    elif len(self.ambiguous_roots)<512:self.ambiguous_roots.append({'root':relative,'families':node['families'],'evidence':node['evidence'],'reason':'marker_without_nearby_source','confidence':'low'})
            elif not inherited:self.diagnostics.append({'path':relative,'reason':'project_discovery_limit'})
            children=[]
            for entry in entries:
                path=Path(entry.path);rp=path.relative_to(self.root).as_posix()
                try:info=entry.stat(follow_symlinks=False)
                except OSError:self._excluded(rp,'unreadable_metadata');continue
                if stat.S_ISLNK(info.st_mode):self.counts['symlinks_skipped']+=1;continue
                is_dir=stat.S_ISDIR(info.st_mode)
                ignored,ignore_ref=ignore_decision(rp,is_dir,rules) if self.respect_gitignore else (False,None)
                reason=inherited
                if ignored:reason='gitignore'
                elif matches(rp,self.exclude):reason='operator_exclude'
                elif not reason and is_dir:
                    if self.policy=='legacy':reason='legacy_directory' if entry.name in LEGACY_SKIP or entry.name.startswith('.cache') else None
                    else:
                        reason=folder_reason(rp,entry.name,families)
                        if not reason and entry.name=='out' and any(re.fullmatch(BUILD_TOOL_CONFIG,e.name) for e in entries):reason='generated_framework_build_output'
                if is_dir:
                    if reason and reason not in {'gitignore','operator_exclude','vcs_metadata'} and self._can_descend_include(rp):
                        children.append((path,rules,families,reason));continue
                    if reason:
                        self._excluded(rp,reason,True,ignore_ref)
                        if self.inventory_all:children.append((path,rules,families,reason))
                    else:children.append((path,rules,families,None))
                    continue
                if not stat.S_ISREG(info.st_mode):self._excluded(rp,'unsupported_file_type');continue
                self._seen+=1;self.all_extensions[path.suffix.lower()]+=1
                included=matches(rp,self.include)
                if included and reason not in {'gitignore','operator_exclude','vcs_metadata'}:reason=None
                role=file_role(rp) if self.policy=='typed' else 'unknown'
                for pattern,override in self.config.get('roles',{}).items():
                    if matches(rp,[pattern]):role=override
                if not reason and self.respect_gitignore and entry.name=='.gitignore':reason='ignore_control_metadata'
                if not reason and self.policy=='typed' and role=='metadata':reason='os_metadata'
                if not reason and self.policy=='typed' and entry.name in {'.pnp.cjs','.pnp.loader.mjs'} and 'node' in families and not included:reason='node_generated_installation'
                if not reason and self.policy=='typed' and (entry.name.endswith('.min.js') or entry.name.endswith('.min.css')) and not included:reason='generated_minified'
                if not reason and self.policy=='typed' and role=='fixture' and not included:reason='fixture_corpus'
                if not reason and info.st_size>1500000:reason='core_file_size_limit'
                if not reason and len(self.records)>=MAX_FILES:reason='inventory_file_limit'
                if reason:self._excluded(rp,reason,evidence=ignore_ref);continue
                record={'path':path,'relative':rp,'size':info.st_size,'mtime_ns':info.st_mtime_ns,'role':role,
                        'owner':'root','language':LANGUAGES.get(path.suffix.lower(),'other'),'priority':(2,rp)}
                record['authorship']='operator_selected' if included else 'unknown'
                if not path.suffix and info.st_size<=1500000:
                    from .adapters import shebang_language
                    inferred=shebang_language(self.cache.text(path,256))
                    if inferred:record['language']=inferred;record['language_basis']='bounded_shebang'
                self.records.append(record);self.by_path[path]=record;self.collected_extensions[path.suffix.lower()]+=1;self.role_counts[role]+=1
            stack.extend(reversed(children))
        if not self.nodes:self.nodes=[node_for(self.root,'.',[],self.cache.text,True)]
        for declared in self.config.get('projects',[]):
            relative=declared['root'];path=self.root/relative
            if not self._safe_path(path) or not path.is_dir():raise ValueError('Declared project must be an existing non-symlink root inside scan')
            existing=next((n for n in self.nodes if n['root']==relative),None)
            if existing is None:
                existing=node_for(path,relative,[],self.cache.text,True);existing['id']=__import__('aqaf.projects',fromlist=['project_id']).project_id(relative);existing['root']=relative;self.nodes.append(existing)
            existing['relationship']='operator_declared';existing['confidence']='user_selected';existing['profile_override']=declared.get('profile')
            existing['source_hints'].extend({'path':x,'kind':'operator_declared'} for x in declared.get('source_roots',[]))
        self.graph=graph(self.nodes,self.records,self.root)
        self.graph['ambiguous_roots']=self.ambiguous_roots
        self._priority_plan()
        self.records.sort(key=lambda r:r['relative'] if self.policy=='legacy' else r['priority'])
        self.files=[r['path'] for r in self.records]
        return self

    def _safe_path(self,path):
        try:relative=path.relative_to(self.root)
        except ValueError:return False
        candidate=self.root
        for part in relative.parts:
            candidate/=part
            if part=='..' or candidate.is_symlink():return False
        return True

    def _priority_plan(self):
        for node in self.nodes:
            prefix='' if node['root']=='.' else node['root']+'/'
            for hint in node['source_roots']:
                rp=prefix+hint['path'];self.source_plan.append({'path':rp,'owner':node['id'],**{k:v for k,v in hint.items() if k!='path'}})
        for rp in self.config.get('source_roots',[]):
            path=self.root/rp
            if not self._safe_path(path):raise ValueError('Unsafe source priority path')
            self.source_plan.append({'path':rp,'owner':'root','kind':'operator_declared','confidence':'user_selected','exists':path.exists()})
            if not path.exists():self.diagnostics.append({'path':rp,'reason':'stale_operator_source_root'})
        # Only bounded architecture/ADR documents provide weak path hints, never instructions.
        documents=[r for r in self.records if r['path'].suffix.lower() in {'.md','.rst','.adoc'} and re.search(r'(?i)architecture|(?:^|/)adr(?:/|$)',r['relative'])]
        for record in documents[:64]:
            raw=self.cache.read(record['path'],32768);text=raw.decode('utf8','ignore')
            for candidate in re.findall(r'`([^`\n]{1,128})`',text)[:64]:
                if not safe_relative(candidate) or any(c in candidate for c in '*? $;&|<>'):continue
                path=self.root/candidate
                if not self._safe_path(path):continue
                if path.exists():self.source_plan.append({'path':candidate,'owner':record['owner'],'kind':'architecture_hint','confidence':'low','evidence':record['relative'],'sha256':hashlib.sha256(raw).hexdigest()})
                elif '/' in candidate:self.diagnostics.append({'path':candidate,'reason':'stale_architecture_hint','evidence':record['relative']})
        manifest_evidence={e['path']:e['sha256'] for node in self.nodes for e in node['evidence']}
        config_digest=hashlib.sha256(json.dumps(self.config,sort_keys=True).encode()).hexdigest()
        for hint in self.source_plan:
            if hint['kind']=='operator_declared':hint['effective_config_sha256']=config_digest
            elif hint.get('evidence') in manifest_evidence:hint['sha256']=manifest_evidence[hint['evidence']]
            elif hint['kind']=='conventional':hint['evidence']='conventional_layout_fallback'
        for r in self.records:
            hints=[h for h in self.source_plan if r['relative']==h['path'] or r['relative'].startswith(h['path'].rstrip('/')+'/')]
            rank=min((0 if h['kind']=='operator_declared' else 1 if h['kind']=='entrypoint' else 2 if h['kind']=='architecture_hint' else 3 for h in hints),default=4)
            r['priority']=(rank,ROLE_ORDER.get(r['role'],2),r['relative'])
            if hints:r['priority_evidence']=[{'path':h['path'],'kind':h['kind']} for h in hints[:8]]

    def selection_complete(self):
        incomplete={'unreadable_directory','scope_traversal_budget','scope_depth_budget','project_discovery_limit'}
        return not self.cache.failures and not any(d['reason'] in incomplete for d in self.diagnostics) and not self.counts['excluded_files:unreadable_metadata'] and not self.counts['excluded_files:inventory_file_limit']

    def selected(self,roles=None):
        """Version 1 selection shared by code, documentation and discovery."""
        return [r for r in self.records if roles is None or r['role'] in roles]

    def provenance(self):
        return {'schema_version':1,'selection':self.report(),'read_inputs':sorted(self.cache.evidence.values(),key=lambda r:r['path'])}

    def record(self,path):return self.by_path.get(Path(path),{})

    def text(self,path,limit=1500001):
        if Path(path) not in self.by_path:return ''
        return self.cache.text(path,limit)

    def raw(self,path,limit=1500001):
        if Path(path) not in self.by_path:return b''
        return self.cache.read(path,limit)

    def report(self):
        import unicodedata
        normalized=defaultdict(list)
        for record in self.records:normalized[unicodedata.normalize('NFC',record['relative'])].append(record['relative'])
        collisions=[{'display_path':key,'original_paths':values} for key,values in sorted(normalized.items()) if len(values)>1]
        exclusions=[]
        for entry in self.exclusions:
            candidates=[n for n in self.nodes if n['root']=='.' or entry['path']==n['root'] or entry['path'].startswith(n['root']+'/')]
            owner=max(candidates,key=lambda n:(n['root']!='.',len(n['root']))) if candidates else self.nodes[0]
            reason=entry['reason']
            role='metadata' if reason in {'os_metadata','ignore_control_metadata','vcs_metadata'} or entry['path'].split('/')[0]=='__MACOSX' else 'archive' if reason=='archive_or_metadata' else 'dependency' if any(s in reason for s in ['dependency','toolchain','environment','nuget']) else 'generated' if any(s in reason for s in ['generated','cache','minified']) else 'fixture' if 'fixture' in reason or 'corpus' in reason else 'excluded_unknown'
            exclusions.append({**entry,'role':role,'owner':owner['id'],'confidence':'operator_selected' if reason=='operator_exclude' else 'heuristic_policy',
                'policy_evidence':{'policy':self.policy,'owner_families':owner['families'],'reason_code':reason}})
        return {'selection_complete':self.selection_complete(),'operator_control':self.config_control,'selection_api_version':1,'unicode_display_collisions':collisions[:1000],'effective_config_sha256':hashlib.sha256(json.dumps(self.config,sort_keys=True).encode()).hexdigest(),'schema_version':1,'policy':self.policy,'respect_gitignore':self.respect_gitignore,
                'gitignore_sources':self.ignore_sources,'gitignore_tracked_status':'not_consulted_patterns_apply_to_all_paths',
                'gitignore_scope':'authorized_root_and_descendants_only','physical_census_complete':self.inventory_all and not self.diagnostics and not self.counts['excluded_files:unreadable_metadata'],
                'visited_regular_files':self._seen,'collected_files':len(self.files),'visited_extensions':dict(sorted(self.all_extensions.items())),
                'collected_extensions':dict(sorted(self.collected_extensions.items())),'roles':dict(sorted(self.role_counts.items())),
                'counts':dict(sorted(self.counts.items())),'exclusions':exclusions,'exclusion_details_truncated':sum(v for k,v in self.counts.items() if k.startswith(('pruned_directories:','excluded_files:')))>len(self.exclusions),
                'diagnostics':self.diagnostics[:2000],'source_plan':self.source_plan[:2000],
                'limits':{'max_directories':self.walk_limits[0],'max_entries':self.walk_limits[1],'max_depth':self.walk_limits[2],'max_read_bytes':self.max_read_bytes,'max_selected_files':MAX_FILES,'max_projects':MAX_PROJECTS,'max_manifest_bytes':131072,'source_cache_bytes':CACHE_BYTES},
                'read_cache':{'hits':self.cache.hits,'file_reads':self.cache.reads,'bytes_read':self.cache.bytes_read,'failures':dict(self.cache.failures)},
                'limitations':['Ownership and architecture are inferred from bounded static evidence, not verified intent.',
                               'Pruned subtrees have unknown descendant counts unless inventory_all was selected.',
                               'Source is read once per cache entry, not an atomic whole-repository snapshot; kit integrity is separate.',
                               'Global gitignore, Git index tracked status, .git/info/exclude and patterns outside the authorized root are not read.']}
