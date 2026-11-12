"""Passive, bounded project graph and source-root evidence; never run manifests."""
from __future__ import annotations
import fnmatch
import hashlib
import json
from pathlib import Path,PurePosixPath
import re
try:
    import tomllib
except ImportError:  # Python 3.9/3.10 retain bounded metadata presence evidence.
    tomllib=None

MARKERS={'package.json':'node','pyproject.toml':'python','setup.py':'python','setup.cfg':'python','Cargo.toml':'rust',
         'composer.json':'php','go.mod':'go','Package.swift':'swift','CMakeLists.txt':'native','pom.xml':'java',
         'settings.gradle':'android','settings.gradle.kts':'android','build.gradle':'android','build.gradle.kts':'android',
         'appsscript.json':'apps_script'}
SOURCES={'src','app','lib','apps','services','crates','modules','features','domain','application','infrastructure','adapters'}
ARCHIVE_SEGMENTS={'archive','archives','backup','backups','snapshots','submissions','fixtures','__fixtures__','dropins','uploaded_zip_contents','.tmp-import'}
MAX_PROJECTS=512
MAX_MANIFEST_BYTES=131072


def marker_family(name):
    if name in MARKERS:return MARKERS[name]
    if name.endswith(('.csproj','.fsproj','.vbproj','.sln','.slnx')):return 'dotnet'
    if name.endswith('.psd1'):return 'powershell'
    return None


def archived(relative):
    return any(p.lower() in ARCHIVE_SEGMENTS or re.search(r'(?i)(?:canary-source|release-stage|windows-release|staging-copy)',p) for p in PurePosixPath(relative).parts)


def project_id(relative):
    # Keep identity independent of marker contents; relocation is separately reported.
    return 'root' if relative=='.' else 'project-'+hashlib.sha256(relative.encode()).hexdigest()[:16]


def metadata(path,relative,read):
    text=read(path,MAX_MANIFEST_BYTES+1)
    if len(text.encode('utf8','replace'))>MAX_MANIFEST_BYTES:return {},'oversized_manifest'
    try:
        if path.name in {'package.json','composer.json','appsscript.json'}:
            doc=json.loads(text)
            return (doc,None) if isinstance(doc,dict) else ({},'unsupported_manifest_shape')
        if path.name in {'pyproject.toml','Cargo.toml'}:
            if tomllib:return tomllib.loads(text),None
            return {},'toml_parser_unavailable'
    except (ValueError,RecursionError):return {},'unparseable_manifest'
    return {},None


def node_for(directory,relative,names,read,root=False):
    markers=sorted(n for n in names if marker_family(n) and (directory/n).is_file() and not (directory/n).is_symlink())
    families=sorted({marker_family(n) for n in markers})
    if 'wp-config.php' in names and {'wp-content','wp-includes'} & set(names):families.append('wordpress')
    if not root and not families:return None
    evidence=[];declared=[];declared_sources=[];unknowns=[]
    for name in markers[:32]:
        path=directory/name;rp=name if relative=='.' else relative+'/'+name
        text=read(path,MAX_MANIFEST_BYTES+1)
        evidence.append({'path':rp,'sha256':hashlib.sha256(text.encode('utf8','replace')).hexdigest(),'kind':'manifest_presence'})
        data,error=metadata(path,rp,read)
        if error:unknowns.append({'path':rp,'reason':error})
        if name=='package.json':
            members=data.get('workspaces',[])
            if isinstance(members,dict):members=members.get('packages',[])
            if isinstance(members,list):declared.extend(x for x in members if isinstance(x,str))
            for key in ('main','source'):
                value=data.get(key)
                if isinstance(value,str):declared_sources.append({'path':value,'evidence':rp,'kind':'entrypoint'})
        if name=='Cargo.toml':
            workspace=data.get('workspace',{})
            if isinstance(workspace,dict):declared.extend(x for x in workspace.get('members',[]) if isinstance(x,str))
            for key in ('lib','bin'):
                values=data.get(key,[])
                if isinstance(values,dict):values=[values]
                if isinstance(values,list):
                    for value in values:
                        if isinstance(value,dict) and isinstance(value.get('path'),str):declared_sources.append({'path':value['path'],'evidence':rp,'kind':'entrypoint'})
        if name=='pyproject.toml':
            tool=data.get('tool',{})
            uv=tool.get('uv',{}) if isinstance(tool,dict) else {}
            workspace=uv.get('workspace',{}) if isinstance(uv,dict) else {}
            if isinstance(workspace,dict):declared.extend(x for x in workspace.get('members',[]) if isinstance(x,str))
        if name.endswith(('.csproj','.fsproj','.vbproj')):
            if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():unknowns.append({'path':rp,'reason':'xml_entities_rejected'})
            else:
                for value in re.findall(r'<(?:Compile|Content)\b[^>]*\bInclude=["\']([^"\']+)',text)[:128]:
                    value=value.replace('\\','/')
                    if safe_relative(value) and not any(c in value for c in '$*?'):declared_sources.append({'path':value,'evidence':rp,'kind':'entrypoint'})
                    else:unknowns.append({'path':rp,'reason':'dynamic_build_source_path'})
        if name.endswith('.sln'):
            for value in re.findall(r'["\']([^"\']+\.(?:csproj|fsproj|vbproj))["\']',text)[:256]:
                value=PurePosixPath(value.replace('\\','/')).parent.as_posix()
                if value!='.':declared.append(value)
        if name.startswith('settings.gradle'):
            # Literal include calls only; no Gradle or arbitrary Kotlin evaluation.
            for match in re.finditer(r'(?m)^\s*include\s*(?:\(([^\n)]*)\)|([^\n]+))',text):
                declared.extend(x.lstrip(':').replace(':','/') for x in re.findall(r'["\']([^"\']+)["\']',match.group(1) or match.group(2)))
    if 'pnpm-workspace.yaml' in names:
        rp=('' if relative=='.' else relative+'/')+'pnpm-workspace.yaml';text=read(directory/'pnpm-workspace.yaml',65537)
        # Strict list literals only. YAML aliases/tags/flow mappings are unresolved.
        if len(text)>65536 or re.search(r'(?m)^\s*[^#\n]*[&!{}]',text):unknowns.append({'path':rp,'reason':'unsupported_workspace_yaml'})
        else:
            declared.extend(m.group(1).strip('"\'') for m in re.finditer(r'(?m)^\s+-\s+([^#\n]+?)\s*$',text))
            evidence.append({'path':rp,'sha256':hashlib.sha256(text.encode()).hexdigest(),'kind':'workspace_literals'})
    valid=[]
    for value in declared[:512]:
        if safe_relative(value):valid.append(value)
        else:unknowns.append({'reason':'unsafe_workspace_path','path':relative})
    return {'id':project_id(relative),'root':relative,'families':sorted(set(families)),'parent':None,
            'relationship':'registered_root' if root else 'inferred_project','confidence':'medium' if markers else 'low',
            'evidence':evidence,'workspace_patterns':sorted(set(valid)),'source_hints':declared_sources,
            'unknowns':unknowns,'source_roots':[],'classification':None}


def safe_relative(value):
    return (isinstance(value,str) and 0<len(value)<=512 and not value.startswith(('/','\\')) and
            '\\' not in value and '\x00' not in value and ':' not in value and '..' not in PurePosixPath(value).parts)


def graph(nodes,files,root):
    nodes=sorted(nodes,key=lambda n:(len(PurePosixPath(n['root']).parts) if n['root']!='.' else 0,n['root']))
    for node in nodes:
        if node['root']=='.':continue
        parents=[p for p in nodes if p is not node and (p['root']=='.' or node['root'].startswith(p['root']+'/'))]
        parent=max(parents,key=lambda n:len(n['root'])) if parents else None
        if parent:
            node['parent']=parent['id'];relative=node['root'] if parent['root']=='.' else node['root'][len(parent['root'])+1:]
            declared=any(fnmatch.fnmatchcase(relative,p) for p in parent['workspace_patterns'])
            node['relationship']='operator_declared' if node.get('relationship')=='operator_declared' else 'workspace_member' if declared else 'independent_embedded'
            if declared:node['confidence']='high'
    by_id={n['id']:n for n in nodes}
    for record in files:
        candidates=[n for n in nodes if n['root']=='.' or record['relative'].startswith(n['root']+'/')]
        owner=max(candidates,key=lambda n:(n['root']!='.',len(n['root']))) if candidates else nodes[0]
        record['owner']=owner['id']
    for node in nodes:
        owned=[r for r in files if r['owner']==node['id']]
        base=root if node['root']=='.' else root/node['root']
        hints=[]
        for name in sorted(SOURCES):
            path=base/name
            if path.is_dir() and not path.is_symlink():hints.append({'path':name,'kind':'conventional','confidence':'low'})
        for hint in node['source_hints']:
            if safe_relative(hint['path']):
                path=base/hint['path']
                if path.exists() and not any((root/Path(*path.relative_to(root).parts[:i])).is_symlink() for i in range(1,len(path.relative_to(root).parts)+1)):hints.append({**hint,'confidence':'medium'})
                else:node['unknowns'].append({'path':hint['path'],'reason':'stale_manifest_source_hint'})
        node['source_roots']=hints
        node['files_collected']=len(owned)
        node['roles']=dict(sorted(__import__('collections').Counter(r['role'] for r in owned).items()))
    return {'schema_version':1,'nodes':nodes,'limits':{'max_projects':MAX_PROJECTS},
            'limitations':['Inferred roots and roles are static metadata, not verified ownership or runtime architecture.',
                           'Dynamic workspace/build expressions are unresolved; declarations never authorize external paths.',
                           'No aggregate child quality index is calculated.']}
