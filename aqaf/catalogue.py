"""Opt-in host-local portfolio storage. Scanned trees are always read-only."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from datetime import datetime,timezone
from difflib import SequenceMatcher
import re
from .scope import Scope

SCHEMA=1

def remote_keys(instance):
    """Normalised git remotes recorded by `projects discover --git` for an instance."""
    repos=(instance['metadata'].get('git') or {}).get('repositories') or []
    return {remote['key'] for repo in repos for remote in repo['remotes']}
def now():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def encode(value):return json.dumps(value,sort_keys=True,ensure_ascii=True)
def stable(value):return hashlib.sha256(value.encode()).hexdigest()
def default_database():
    import sys
    if sys.platform=='darwin':base=Path.home()/'Library/Application Support'
    elif os.name=='nt':base=Path(os.environ.get('LOCALAPPDATA',Path.home()/'AppData/Local'))
    else:base=Path(os.environ.get('XDG_DATA_HOME',Path.home()/'.local/share'))
    return base/'AQAF/projects.sqlite3'

def engine_identity():
    root=Path(__file__).parent;h=hashlib.sha256()
    for p in sorted(root.rglob('*')):
        if p.suffix in {'.py','.json'} and '__pycache__' not in p.parts:
            h.update(p.relative_to(root).as_posix().encode()+b'\0'+p.read_bytes())
    return h.hexdigest()

def snapshot(scope,max_bytes=256000000,engine=None):
    entries=[];used=0;complete=True
    for r in sorted(scope.records,key=lambda x:x['relative']):
        if used+r['size']>max_bytes:complete=False;break
        raw=scope.raw(r['path']);used+=len(raw)
        if len(raw)!=r['size']:complete=False
        entries.append({'path':r['relative'],'sha256':hashlib.sha256(raw).hexdigest(),
                        'normalized_newlines_sha256':hashlib.sha256(raw.replace(b'\r\n',b'\n').replace(b'\r',b'\n')).hexdigest() if b'\x00' not in raw else None,
                        'role':r['role'],'language':r['language'],'bytes':len(raw)})
    controls=list(scope.ignore_sources)
    if scope.config_control:controls.append(scope.config_control)
    for name in ('.aqaf.json',):
        p=scope.root/name
        if p.is_symlink():
            complete=False;controls.append({'path':name,'state':'symlink_control_unread'})
        elif p.is_file():
            raw=scope.cache.read(p,131073);whole=len(raw)==p.stat().st_size;complete=complete and whole
            controls.append({'path':name,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'complete_file':whole})
    identity={'root_context':str(scope.root),'entries':entries,'controls':controls,'config':scope.config,'policy':scope.policy,
              'respect_gitignore':scope.respect_gitignore,'engine':engine or engine_identity()}
    return {'schema_version':1,'digest':stable(encode(identity)),'entries':entries,'controls':controls,
            'engine':identity['engine'],'scope':scope.report(),'bytes':used,
            'complete':complete and scope.selection_complete(),
            'integrity_scope':'selected_inputs_and_controls_not_whole_folder'}

class Catalogue:
    def __init__(self,path=None):
        self.path=Path(path or default_database()).expanduser().absolute()
        if self.path.is_symlink():raise ValueError('Catalogue symlink rejected')
        self.path.parent.mkdir(parents=True,exist_ok=True)
        if not self.path.exists():self.path.touch(mode=0o600)
        self.connection=sqlite3.connect(str(self.path));self.connection.row_factory=sqlite3.Row
        try:
            version=self.connection.execute('pragma user_version').fetchone()[0]
            if version>SCHEMA:raise ValueError('Catalogue schema is newer than this engine')
            if version<SCHEMA:
                if self.path.stat().st_size:
                    backup=self.path.with_name(self.path.name+'.before-v1.bak')
                    if backup.exists():raise ValueError('Migration backup already exists')
                    dest=sqlite3.connect(str(backup));self.connection.backup(dest);dest.close()
                with self.connection:
                    self.connection.execute('BEGIN IMMEDIATE')
                    for statement in [
                        'create table if not exists projects(id text primary key,name text not null)',
                        'create table if not exists volumes(id text primary key,label text)',
                        '''create table if not exists instances(id text primary key,project_id text,path text unique,volume_id text,
                        source_id text,included_at text,included_at_basis text,first_seen text,last_seen text,last_verified text,
                        status text,metadata text)''',
                        'create table if not exists snapshots(id integer primary key,instance_id text,created_at text,digest text,document text)',
                        'create table if not exists runs(id integer primary key,instance_id text,created_at text,kind text,status text,document text)',
                        'create table if not exists capability_facts(id text primary key,instance_id text,document text)',
                        'create table if not exists facts(cache_key text primary key,document text)',
                        'create table if not exists relationships(id text primary key,source_id text,target_id text,kind text,document text)',
                        'create table if not exists findings(id text primary key,instance_id text,document text)',
                        'create table if not exists suggestions(id text primary key,instance_id text,document text)',
                        'create table if not exists decisions(instance_id text,key text,value text,primary key(instance_id,key))']:
                        self.connection.execute(statement)
                    for table,columns in {'projects':['id','name'],'instances':['id','project_id','path','included_at','status','metadata'],'snapshots':['id','instance_id','document'],'capability_facts':['id','instance_id','document']}.items():
                        existing={r[1] for r in self.connection.execute('pragma table_info('+table+')')}
                        if not set(columns)<=existing:raise ValueError('Incompatible catalogue table: '+table)
                    self.connection.execute('pragma user_version=1')
        except BaseException:
            self.connection.close();raise
    def close(self):self.connection.close()
    def register(self,record,kind='registered'):
        path=Path(record['path']).expanduser()
        if not path.is_absolute():raise ValueError('Absolute source path required')
        path=path.absolute()
        ident='instance-'+stable(str(path))[:24];project='project-'+stable(str(path))[:24]
        old=self.connection.execute('select id from instances where path=?',(str(path),)).fetchone()
        if old:
            existing=self.show(old['id']);merged={**existing['metadata'],**record}
            with self.connection:
                self.connection.execute("update instances set metadata=?,included_at=coalesce(included_at,?),included_at_basis=case when included_at is null then ? else included_at_basis end,status=case when status='candidate' and ?='registered' then 'registered' else status end where id=?",
                    (encode(merged),record.get('included_at'),record.get('included_at_basis','unknown'),kind,old['id']))
            return old['id']
        volume=str(Path(*path.parts[:3])) if path.parts[1:2]==('Volumes',) else 'host'
        date=now()
        with self.connection:
            self.connection.execute('insert or ignore into volumes values (?,?)',(stable(volume),volume))
            self.connection.execute('insert into projects values (?,?)',(project,record.get('display_name',path.name)))
            self.connection.execute('insert into instances values (?,?,?,?,?,?,?,?,?,?,?,?)',
                (ident,project,str(path),stable(volume),record.get('id'),record.get('included_at'),
                 record.get('included_at_basis','unknown'),date,None,None,kind,encode(record)))
        return ident
    def decide(self,ident,key,value):
        if not self.connection.execute('select 1 from instances where id=?',(ident,)).fetchone():raise ValueError('Unknown instance')
        if key not in {'label','canonical','ownership','purpose','logical_project','excluded','approved'}:raise ValueError('Unknown decision key')
        with self.connection:
            self.connection.execute('insert or replace into decisions values (?,?,?)',(ident,key,str(value)))
            if key=='logical_project':
                if not self.connection.execute('select 1 from projects where id=?',(value,)).fetchone():raise ValueError('Unknown logical project')
                self.connection.execute('update instances set project_id=? where id=?',(value,ident))
    def relocate(self,ident,path):
        before=self.show(ident);path=Path(path).expanduser().absolute()
        if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('Source symlink rejected')
        volume=str(Path(*path.parts[:3])) if path.parts[1:2]==('Volumes',) else 'host'
        with self.connection:
            self.connection.execute('insert or ignore into volumes values (?,?)',(stable(volume),volume))
            self.connection.execute('update instances set path=?,volume_id=?,status=? where id=?',(str(path),stable(volume),'relocated_unverified',ident))
            self.connection.execute('insert into runs(instance_id,created_at,kind,status,document) values (?,?,?,?,?)',(ident,now(),'relocation','unverified',encode({'from':before['path'],'to':str(path)})))
        return self.show(ident)

    def list(self):
        return [dict(x) for x in self.connection.execute('select i.*,p.name from instances i join projects p on p.id=i.project_id order by path')]
    def show(self,ident):
        row=self.connection.execute('select * from instances where id=?',(ident,)).fetchone()
        if not row:raise ValueError('Unknown instance: '+ident)
        result=dict(row);result['metadata']=json.loads(result['metadata'])
        result['relationships']=[json.loads(x['document']) for x in self.connection.execute('select document from relationships where source_id=?',(ident,))]
        result['decisions']={x['key']:x['value'] for x in self.connection.execute('select * from decisions where instance_id=?',(ident,))}
        for key,table in [('snapshots','snapshots'),('runs','runs')]:
            result[key]=[{**dict(x),'document':json.loads(x['document'])} for x in self.connection.execute('select * from '+table+' where instance_id=? order by id',(ident,))]
        return result
    def import_evidence(self,path,kind='historical'):
        path=Path(path);count=0
        if path.is_dir():
            datefile=path/'.aqaf-source-dates.json'
            dates=json.loads(datefile.read_text()).get('sources',{}) if datefile.is_file() and not datefile.is_symlink() else {}
            for p in sorted(path.iterdir()):
                if p.is_symlink():continue
                if p.name.endswith('.aqaf-source.json'):count+=self.import_evidence(p)
                elif p.is_dir() and not p.name.startswith('.'):
                    self.register({'id':p.name,'path':str(p.absolute()),'provenance':str(path),**dates.get(p.name,{})},'registered');count+=1
            return count
        if path.is_symlink() or path.stat().st_size>64000000:raise ValueError('Evidence must be bounded regular JSON')
        doc=json.loads(path.read_text());records=[]
        if isinstance(doc,list):records=doc
        elif not isinstance(doc,dict):raise ValueError('Evidence must be a JSON object or record list')
        elif doc.get('kind')=='aqaf-source-reference':records=[doc]
        elif isinstance(doc.get('projects'),list):records=doc['projects']
        elif isinstance(doc.get('projects'),dict):
            records=[{'id':i,'path':doc.get('source_paths',{}).get(i),'assessment':v} for i,v in doc['projects'].items()]
        elif isinstance(doc.get('sources'),list):records=doc['sources']
        else:raise ValueError('Unrecognized evidence document')
        for record in records:
            if not isinstance(record,dict) or not isinstance(record.get('path'),str) or not Path(record['path']).is_absolute():continue
            item={**record,'imported_from':str(path),'imported_at':now(),'evidence_freshness':'historical_unverified'}
            state='candidate' if 'root_probability' in record and not record.get('included_at') else 'registered'
            ident=self.register(item,state)
            with self.connection:self.connection.execute('insert into runs(instance_id,created_at,kind,status,document) values (?,?,?,?,?)',(ident,now(),kind,'historical_unverified',encode(item)))
            count+=1
        return count
    def refresh(self,ids=None,config=None):
        from .facets import facets,classification
        from .documentation import check
        from .portfolio import dependencies
        outcomes=[];engine=engine_identity()
        for row in self.list():
            ident=row['id']
            if ids and ident not in ids:continue
            detail=self.show(ident);date=now();scope=None
            if detail['decisions'].get('excluded')=='true':status='excluded'
            elif detail['decisions'].get('approved')=='false':status='candidate'
            elif row['status']=='candidate' and detail['decisions'].get('approved')!='true':status='candidate'
            elif not Path(row['path']).exists():status='unavailable'
            else:
                try:
                    path=Path(row['path'])
                    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('Source symlink rejected')
                    if self.path==path or path in self.path.parents:raise ValueError('Keep catalogue outside source tree')
                    scope=Scope(path,config=config).build();snap=snapshot(scope,engine=engine)
                    cached=self.connection.execute('select document from facts where cache_key=?',(snap['digest'],)).fetchone()
                    facts=json.loads(cached[0]) if cached and snap['complete'] else {'profile':classification(scope),'facets':facets(scope),'documentation':check(path,scope=scope),'dependencies':dependencies(scope)}
                    status='verified' if snap['complete'] else 'partial'
                    old=detail['snapshots'][-1]['digest'] if detail['snapshots'] else None
                    with self.connection:
                        if snap['complete']:self.connection.execute('insert or replace into facts values (?,?)',(snap['digest'],encode(facts)))
                        self.connection.execute('insert into snapshots(instance_id,created_at,digest,document) values (?,?,?,?)',(ident,date,snap['digest'],encode(snap)))
                        self.connection.execute('insert into runs(instance_id,created_at,kind,status,document) values (?,?,?,?,?)',(ident,date,'static_refresh',status,encode({'snapshot':snap['digest'],'facts':facts,'cache_hit':bool(cached),'changed':old is not None and old!=snap['digest']})))
                        for table in ('capability_facts','findings'):
                            self.connection.execute('delete from '+table+' where instance_id=?',(ident,))
                        for fact in facts['facets']['facts']:
                            self.connection.execute('insert or replace into capability_facts values (?,?,?)',(stable(ident+encode(fact)),ident,encode({**fact,'verified_at':date,'snapshot':snap['digest']})))
                        for finding in facts['documentation']['findings']:
                            self.connection.execute('insert or replace into findings values (?,?,?)',(stable(ident+finding['id']),ident,encode(finding)))
                        self.connection.execute('delete from relationships where source_id=?',(ident,))
                        for edge in facts.get('dependencies',[]):
                            self.connection.execute('insert or replace into relationships values (?,?,?,?,?)',(stable(ident+encode(edge)),ident,edge['path'],edge['kind'],encode({**edge,'verified_at':date})))
                        self.connection.execute('update instances set last_seen=?,last_verified=case when ? then ? else last_verified end where id=?',(date,snap['complete'],date,ident))
                except (OSError,ValueError,sqlite3.Error) as exc:
                    status='unreadable'
                    with self.connection:self.connection.execute('insert into runs(instance_id,created_at,kind,status,document) values (?,?,?,?,?)',(ident,date,'static_refresh',status,encode({'error':type(exc).__name__,'reason':str(exc)[:512]})))
                finally:
                    if scope:scope.cache.close()
            with self.connection:self.connection.execute('update instances set status=? where id=?',(status,ident))
            outcomes.append({'id':ident,'status':status})
        return outcomes
    def compare(self,a,b):
        aa=self.show(a);bb=self.show(b)
        sa=aa['snapshots'][-1]['document'] if aa['snapshots'] else None
        sb=bb['snapshots'][-1]['document'] if bb['snapshots'] else None
        def selected(s):return {e['path']:e['sha256'] for e in s['entries'] if e['role']!='docs' and (e['language']!='other' or Path(e['path']).suffix.lower() in {'.json','.toml','.yaml','.yml','.ini','.cfg','.xml','.csproj','.gradle'})}
        equal=selected(sa)==selected(sb) if sa and sb and sa['complete'] and sb['complete'] and selected(sa) and selected(sb) else None
        x=re.sub(r'[^a-z0-9]+',' ',Path(aa['path']).name.lower()).strip();y=re.sub(r'[^a-z0-9]+',' ',Path(bb['path']).name.lower()).strip()
        from .matching import name_features
        names=name_features(Path(aa['path']).name,Path(bb['path']).name)
        return {'name_features':names,'schema_version':1,'a':a,'b':b,'selected_source_equal':equal,
                'normalized_newlines_equal':({e['path']:e.get('normalized_newlines_sha256') for e in sa['entries'] if e['path'] in selected(sa)}=={e['path']:e.get('normalized_newlines_sha256') for e in sb['entries'] if e['path'] in selected(sb)}) if sa and sb else None,
                'compared_files':len(selected(sa)) if sa else 0,'noncode_selected_equal':({e['path']:e['sha256'] for e in sa['entries']}=={e['path']:e['sha256'] for e in sb['entries']}) if sa and sb else None,
                'shared_git_remote':sorted(remote_keys(aa)&remote_keys(bb)),
                'whole_project_equal':None,'name_similarity':round(SequenceMatcher(None,x,y).ratio(),4),
                'state':'candidate','canonical':'user_decision_required','mtime_used_as_quality':False,
                'scope':'Selected authored source/config; assets and excluded content may differ.',
                'freshness':{a:aa['last_verified'],b:bb['last_verified']}}
    def candidates(self,ident,limit=20):
        values=[self.compare(ident,r['id']) for r in self.list() if r['id']!=ident]
        return sorted([v for v in values if (v['selected_source_equal'] and v['compared_files']>0) or (v['name_similarity']>=.55 and not v['name_features']['generic_name'])],key=lambda v:(not bool(v['selected_source_equal']),-v['name_similarity'],v['b']))[:limit]

    def view(self):
        instances=[];engine=engine_identity()
        for row in self.list():
            detail=self.show(row['id'])
            runs=[r for r in detail['runs'] if r['kind']=='static_refresh' and 'facts' in r['document']]
            facts=runs[-1]['document']['facts'] if runs else {}
            metadata=detail['metadata'];profile=facts.get('profile',metadata.get('type',metadata.get('finder_type')))
            instances.append({**{k:v for k,v in row.items() if k!='metadata'},'decisions':detail['decisions'],
                'metadata':{'type':profile,'family':metadata.get('family'),'historical_type':not bool(facts.get('profile'))},
                'canonical_path':facts.get('documentation',{}).get('root'),'engine_matches_current':bool(detail['snapshots'] and detail['snapshots'][-1]['document']['engine']==engine),
                'snapshots':[{'created_at':x['created_at'],'digest':x['digest']} for x in detail['snapshots']],
                'relationships':detail['relationships'],
                'suggestions':[json.loads(x[0]) for x in self.connection.execute('select document from suggestions where instance_id=?',(row['id'],))],
                'runs':[{'created_at':r['created_at'],'status':r['status']} for r in detail['runs'][:-1]]+
                    ([{'created_at':runs[-1]['created_at'],'status':runs[-1]['status'],'document':{'facts':{'facets':facts.get('facets'), 'dependencies':facts.get('dependencies')}}}] if runs else [])})
        return {'schema_version':SCHEMA,'generated_at':now(),'instances':instances}

    def export(self):return {'schema_version':SCHEMA,'generated_at':now(),'instances':[self.show(r['id']) for r in self.list()]}
