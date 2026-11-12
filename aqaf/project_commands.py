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

def matches(argv):
    return len(argv)>1 and ((argv[0]=='projects' and argv[1] in PROJECT_ACTIONS) or (argv[0]=='docs' and argv[1]=='check'))

def browser(document):
    # Offline self-contained HTML, no CDNs, no source body, textContent only.
    payload=json.dumps(document,ensure_ascii=True).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    return '''<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"><title>AQAF local catalogue</title>
<style>body{font:16px system-ui;margin:2rem}td,th{padding:.5rem;text-align:left;vertical-align:top}tr:nth-child(even){background:#eee}pre{white-space:pre-wrap}</style>
<h1>AQAF local catalogue</h1><p>Static export. Unavailable locations retain history. Dates do not establish quality. All observations remain unconfirmed.</p>
<label>Filter type, capability, location, status, family or label <input id="filter"></label><p id="count"></p><table><thead><tr><th>Project / location</th><th>Status / type / capabilities</th><th>History / decisions / relationships</th></tr></thead><tbody id="rows"></tbody></table>
<script>const data='''+payload+''';const rows=document.getElementById('rows');function render(){rows.replaceChildren();let n=0;for(const r of data.instances){if(!JSON.stringify(r).toLowerCase().includes(document.getElementById('filter').value.toLowerCase()))continue;n++;const tr=document.createElement('tr');for(const value of [r.path,JSON.stringify({status:r.status,type:r.metadata.type,capabilities:r.runs.length?r.runs[r.runs.length-1].document?.facts?.facets:null}),JSON.stringify({included_at:r.included_at,last_verified:r.last_verified,snapshots:r.snapshots.length,decisions:r.decisions,relationships:r.relationships,suggestions:r.suggestions,runs:r.runs.map(x=>({date:x.created_at,status:x.status,dependencies:x.document?.facts?.dependencies}))})]){const td=document.createElement('td');td.textContent=value;tr.append(td)}rows.append(tr)}document.getElementById('count').textContent=n+' instances';}document.getElementById('filter').oninput=render;render();</script>'''

def main(argv):
    group,action=argv[:2]
    ap=argparse.ArgumentParser(prog='aqaf '+group+' '+action)
    ap.add_argument('--database',type=Path,default=default_database())
    ap.add_argument('--format',choices=['json','table','csv','html'],default='json')
    ap.add_argument('--output',type=Path,help='Create a new report outside source roots')
    ap.add_argument('--scope-config',type=Path)
    if action=='discover':
        ap.add_argument('roots',nargs='+',type=Path);ap.add_argument('--register',action='store_true')
        ap.add_argument('--no-gitignore',action='store_true');ap.add_argument('--include-archives',action='store_true')
        ap.add_argument('--include-installed-plugins',action='store_true');ap.add_argument('--exclude',action='append',default=[])
        for flag,n in [('max-depth',24),('max-directories',100000),('max-entries',1000000),('max-projects',2000),('max-files-per-project',500),('max-bytes',16000000)]:ap.add_argument('--'+flag,type=int,default=n)
    elif group=='docs':
        ap.add_argument('root',type=Path);ap.add_argument('--generated-route',action='append',default=[]);ap.add_argument('--audience')
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
        if action=='explain':ap.add_argument('--local-model-url');ap.add_argument('--model')
    args=ap.parse_args(argv[2:]);db=None;roots=[]
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
            doc=discover(roots,scope_config=config,respect_gitignore=not args.no_gitignore,include_archives=args.include_archives,include_installed_plugins=args.include_installed_plugins,exclude=args.exclude,**limits)
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
                if action=='explain':doc=explanation(doc,model=local_model(args.local_model_url,args.model) if args.local_model_url else None)
            elif action=='browse':doc=db.view()
            else:doc=db.export()
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
            with dest.open('x',encoding='utf8') as stream:stream.write(text)
            print(str(dest))
        else:print(text,end='')
        return 2 if doc.get('status')=='partial' else 0
    except (ValueError,OSError,sqlite3.Error) as exc:ap.error(str(exc))
    finally:
        if db:db.close()
