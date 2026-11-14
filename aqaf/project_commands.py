"""Additive, explicitly selected project/docs command family."""
import argparse
import csv
import html
import io
import json
from pathlib import Path
import sys
import sqlite3
from .catalogue import Catalogue,default_database
from .scope import Scope,config_document
from .discovery import discover,render_table
from .documentation import check
from .portfolio import suggestions,explanation,local_model

PROJECT_ACTIONS={'discover','list','show','refresh','compare','suggest','import','label','relocate','export','browse','explain'}

GROUPS={'projects':{'discover':'find project folders under one or more roots (--register stores candidates)',
                    'list':'list registered project instances','show':'show one instance with history and decisions',
                    'refresh':'re-read selected sources and update static facts','compare':'compare two instances or find candidates',
                    'suggest':'evidence-backed reuse and documentation suggestions','explain':'explain suggestions (optionally with a loopback model)',
                    'import':'import earlier assessment reports','label':'record a decision (approved, excluded, purpose ...)',
                    'relocate':'point an instance at its new location','export':'write the catalogue as json or csv','browse':'write an offline html catalogue'},
        'docs':{'check':'static documentation review of one project folder'}}
FORMATS={'discover':['json','table','csv'],'check':['json','table','csv'],'list':['json','csv','html'],'export':['json','csv','html'],'browse':['html','json']}


def wants_group_help(argv):
    """`aqaf projects`, `aqaf docs`, either with -h/--help, or an unknown action. A real folder with that name is still scanned."""
    if not argv or argv[0] not in GROUPS:return False
    if argv[1:2] in (['-h'],['--help']):return True
    return not Path(argv[0]).is_dir() and (len(argv)==1 or not argv[1].startswith('-'))


def group_help(argv):
    group=argv[0];actions=GROUPS[group]
    lines=[f'usage: aqaf {group} ACTION [options]','',f'AQAF {group} actions (run `aqaf {group} ACTION --help` for options):']
    lines+=[f'  {name:<10} {text}' for name,text in sorted(actions.items())]
    lines+=['',f'A folder named `{group}` is still scanned as a repository: aqaf ./{group}']
    wanted=argv[1:2] in (['-h'],['--help'])
    unknown=[a for a in argv[1:2] if not a.startswith('-')]
    print('\n'.join(lines),file=sys.stdout if wanted else sys.stderr)
    if unknown and not wanted:print(f'aqaf {group}: error: unknown action {unknown[0]!r}',file=sys.stderr)
    return 0 if wanted else 2


def matches(argv):
    return len(argv)>1 and ((argv[0]=='projects' and argv[1] in PROJECT_ACTIONS) or (argv[0]=='docs' and argv[1]=='check'))

def browser(document):
    # Offline self-contained HTML, no CDNs, no source body, textContent only.
    payload=json.dumps(document,ensure_ascii=True).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    return '''<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"><title>AQAF local catalogue</title>
<style>body{font:16px system-ui;margin:2rem}td,th{padding:.5rem;text-align:left;vertical-align:top}tr:nth-child(even){background:#eee}pre{white-space:pre-wrap}</style>
<h1>AQAF local catalogue</h1><p>Static export. Unavailable locations retain history. Dates do not establish quality. All observations remain unconfirmed.</p>
<label>Filter type, capability, location, status, family or label <input id="filter"></label><p id="count"></p><table><thead><tr><th>Project / location</th><th>Status / type / capabilities</th><th>History / decisions / relationships</th></tr></thead><tbody id="rows"></tbody></table>
<script>const data='''+payload+''';const rows=document.getElementById('rows');function render(){rows.replaceChildren();let n=0;for(const r of data.instances){if(!JSON.stringify(r).toLowerCase().includes(document.getElementById('filter').value.toLowerCase()))continue;n++;const tr=document.createElement('tr');for(const value of [r.path,JSON.stringify({status:r.status,type:r.metadata.type,capabilities:r.runs.length?r.runs[r.runs.length-1].document?.facts?.facets:null,git:r.metadata.git?r.metadata.git.repositories.map(g=>({path:g.path,kind:g.kind,remotes:g.remotes.map(x=>x.url),commit:g.commit?g.commit.sha.slice(0,7)+' '+g.commit.date.slice(0,10)+' '+g.commit.subject:null})):null}),JSON.stringify({included_at:r.included_at,last_verified:r.last_verified,snapshots:r.snapshots.length,decisions:r.decisions,relationships:r.relationships,suggestions:r.suggestions,runs:r.runs.map(x=>({date:x.created_at,status:x.status,dependencies:x.document?.facts?.dependencies}))})]){const td=document.createElement('td');td.textContent=value;tr.append(td)}rows.append(tr)}document.getElementById('count').textContent=n+' instances';}document.getElementById('filter').oninput=render;render();</script>'''

def main(argv):
    group,action=argv[:2]
    ap=argparse.ArgumentParser(prog='aqaf '+group+' '+action)
    ap.add_argument('--database',type=Path,default=default_database())
    choices=FORMATS.get(action,['json'])
    ap.add_argument('--format',choices=choices,default=choices[0],help='Output format for this action: '+', '.join(choices))
    ap.add_argument('--output',type=Path,help='Create a new report outside source roots')
    ap.add_argument('--overwrite',action='store_true',help='Replace an existing regular file given to --output (atomic); never a symlink, directory or file inside a source tree')
    ap.add_argument('--scope-config',type=Path)
    if action=='discover':
        ap.add_argument('roots',nargs='+',type=Path);ap.add_argument('--register',action='store_true')
        ap.add_argument('--no-gitignore',action='store_true');ap.add_argument('--include-archives',action='store_true')
        ap.add_argument('--include-installed-plugins',action='store_true');ap.add_argument('--exclude',action='append',default=[])
        ap.add_argument('--include-installed-extensions',action='store_true',help="List folders inside a browser profile's Extensions directory (by default they are installed extensions, not projects)")
        ap.add_argument('--git',action='store_true',help='Add git repositories (root, nested, submodules), remotes, branch, latest commit and shared-remote links; runs read-only git with repository config neutralised')
        ap.add_argument('--progress',action='store_true',help='Write a progress line to stderr about every 5 seconds')
        ap.add_argument('--min-probability',type=float,default=0.0,help='Hide (and do not register) candidates whose root probability is below this value, e.g. 0.8; they are still counted')
        ap.add_argument('--exit-codes',choices=['default','distinct'],default='default',help='distinct: partial results exit 11, leaving 2 for usage errors')
        for flag,n in [('max-depth',24),('max-directories',100000),('max-entries',1000000),('max-projects',2000),('max-files-per-project',500),('max-bytes',16000000)]:ap.add_argument('--'+flag,type=int,default=n)
    elif group=='docs':
        ap.add_argument('root',type=Path);ap.add_argument('--generated-route',action='append',default=[]);ap.add_argument('--audience')
        ap.add_argument('--exit-codes',choices=['default','distinct'],default='default',help='distinct: partial results exit 11, leaving 2 for usage errors')
    elif action=='import':ap.add_argument('paths',nargs='+',type=Path)
    elif action in {'show','label','relocate'}:
        ap.add_argument('id')
        if action=='label':ap.add_argument('key');ap.add_argument('value')
        if action=='relocate':ap.add_argument('path',type=Path)
    elif action in {'list','browse','export'}:
        for flag in ('type','capability','status','location','family','label'):ap.add_argument('--'+flag)
    elif action=='refresh':ap.add_argument('ids',nargs='*')
    elif action=='compare':ap.add_argument('a');ap.add_argument('b',nargs='?')
    elif action in {'suggest','explain'}:
        ap.add_argument('--need');ap.add_argument('--id')
        if action=='explain':
            ap.add_argument('--local-model-url');ap.add_argument('--model')
            ap.add_argument('--timeout',type=float,default=30,help='Seconds to wait for the local model (5-600, default 30)')
            ap.add_argument('--no-think',action='store_true',help='Ask the local model not to use its thinking mode (sends think=false)')
    args=ap.parse_args(argv[2:]);db=None;roots=[]
    if action=='explain' and not args.local_model_url and (args.no_think or args.timeout!=30):ap.error('--timeout and --no-think need --local-model-url')
    try:
        config=config_document(args.scope_config)
        if group=='docs':
            roots=[args.root];scope=Scope(args.root,config=config).build()
            try:
                roots=[scope.root];doc=check(args.root,scope=scope,generated_routes=args.generated_route,audience=args.audience)
            finally:scope.cache.close()
        elif action=='discover':
            roots=args.roots;limits={k:getattr(args,k) for k in ('max_depth','max_directories','max_entries','max_projects','max_files_per_project','max_bytes')}
            if any(n<=0 for n in limits.values()):raise ValueError('Limits must be positive')
            if not 0<=args.min_probability<=1:raise ValueError('--min-probability must be between 0 and 1')
            doc=discover(roots,scope_config=config,respect_gitignore=not args.no_gitignore,include_archives=args.include_archives,include_installed_plugins=args.include_installed_plugins,exclude=args.exclude,progress=sys.stderr if args.progress else None,min_probability=args.min_probability,include_installed_extensions=args.include_installed_extensions,git=args.git,**limits)
            if args.register:
                for root in roots:
                    if root.resolve() in args.database.resolve().parents:raise ValueError('Keep database outside searched roots')
                db=Catalogue(args.database)
                doc['registered_candidates']=[db.register(r,'candidate') for r in doc['projects']]
        else:
            db=Catalogue(args.database)
            roots=[Path(r['path']) for r in db.list()]
            if action=='import':doc={'schema_version':1,'imported_records':sum(db.import_evidence(p) for p in args.paths)}
            elif action=='list':doc=db.view()
            elif action=='show':doc=db.show(args.id)
            elif action=='refresh':doc={'schema_version':1,'results':db.refresh(args.ids,config=config)}
            elif action=='compare':doc=db.compare(args.a,args.b) if args.b else {'schema_version':1,'candidates':db.candidates(args.a)}
            elif action=='label':db.decide(args.id,args.key,args.value);doc=db.show(args.id)
            elif action=='relocate':doc=db.relocate(args.id,args.path)
            elif action in {'suggest','explain'}:
                doc=suggestions(db,need=args.need,instance_id=args.id)
                if action=='explain':doc=explanation(doc,model=local_model(args.local_model_url,args.model,timeout=args.timeout,think=False if args.no_think else None) if args.local_model_url else None)
            elif action=='browse':doc=db.view()
            else:doc=db.export()
        if group=='docs' or action=='discover':doc['exit_reason']='partial' if doc.get('status')=='partial' else 'ok'
        if action in {'list','browse','export'} and any(getattr(args,k) for k in ('type','capability','status','location','family','label')):
            doc=db.view();selected=[]
            for row in doc['instances']:
                profile=row['metadata'].get('type') or {}
                facets=row['runs'][-1].get('document',{}).get('facts',{}).get('facets') or {} if row['runs'] else {}
                if args.type and profile.get('profile')!=args.type:continue
                if args.capability and not any(f['facet']==args.capability for f in facets.get('facts',[])):continue
                if args.status and row['status']!=args.status:continue
                if args.location and args.location.casefold() not in row['path'].casefold():continue
                if args.family and row['project_id']!=args.family:continue
                if args.label and row['decisions'].get('label')!=args.label:continue
                selected.append(row)
            doc['instances']=selected
        fmt='html' if action=='browse' else args.format
        if fmt=='table' and action=='discover':text=render_table(doc)
        elif fmt=='html':
            if 'instances' not in doc:raise ValueError('HTML export requires projects browse/export')
            if db and action not in {'list','browse','export'}:doc=db.view()
            text=browser(doc)
        elif fmt=='csv':
            if db:records=doc.get('instances',db.list())
            else:records=doc.get('projects',doc.get('findings',[]))
            fields=sorted({k for r in records for k in r});out=io.StringIO();writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
            for r in records:writer.writerow({k:json.dumps(v) if isinstance(v,(dict,list)) else v for k,v in r.items()})
            text=out.getvalue()
        else:text=json.dumps(doc,indent=2,ensure_ascii=True)+'\n'
        if db:roots=[Path(r['path']) for r in db.list()]
        if args.output:
            dest=args.output.expanduser().absolute()
            # Export is a database read; detached historical locations must not
            # trigger filesystem probes. Scans reject source symlinks; preserve
            # both the literal destination and its resolved operator-selected path.
            import os
            destinations={Path(os.path.abspath(dest)),dest.resolve()}
            boundaries={Path(os.path.abspath(r)) for r in roots}
            for row in doc.get('instances',[]):
                if row.get('canonical_path'):boundaries.add(Path(row['canonical_path']))
            if any(d==r or r in d.parents for r in boundaries for d in destinations):raise ValueError('Report destination must be outside source trees')
            if args.overwrite and (dest.exists() or dest.is_symlink()):
                if dest.is_symlink() or not dest.is_file():raise ValueError('--overwrite replaces only an existing regular file')
                import tempfile
                fd,temporary=tempfile.mkstemp(prefix='.aqaf-report-',dir=dest.parent)
                try:
                    with os.fdopen(fd,'w',encoding='utf8') as stream:stream.write(text)
                    os.replace(temporary,dest)
                finally:Path(temporary).unlink(missing_ok=True)
            else:
                with dest.open('x',encoding='utf8') as stream:stream.write(text)
            print(str(dest))
        else:print(text,end='')
        if getattr(args,'exit_codes','default')=='distinct':return 11 if doc.get('status')=='partial' else 0
        return 2 if doc.get('status')=='partial' else 0
    except (ValueError,OSError,sqlite3.Error) as exc:ap.error(str(exc))
    finally:
        if db:db.close()
