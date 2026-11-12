"""Opt-in, bounded JS/TS source observations. No execution or credential decoding.

This deliberately limited lexer/structural reader is not a compiler, taint engine,
or proof of races, authentication failures, validation quality or data loss.
"""
from __future__ import annotations
from collections import namedtuple
import hashlib
from importlib import resources
import json
from pathlib import Path
import re

Token = namedtuple('Token', 'kind value start end line column')
EXTENSIONS = {'.js', '.ts', '.mjs', '.mts', '.cjs', '.cts', '.gs'}
EXCLUDED = {'node_modules','vendor','target','build','dist','coverage','generated',
            'tests','test','__tests__','fixtures','__fixtures__','examples','docs',
            'references','reference','archive','archives','cache'}
MAX_FILE_BYTES = 256000
MAX_TOKENS = 20000
MAX_SCOPES = 128
MAX_FILES = 1000
MAX_TOTAL_BYTES = 20000000
_ATOM = re.compile(r'[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|===|!==|=>|\+\+|--|\+=|-=|&&|\|\||\?\?|==|!=|<=|>=|\?\.')
CHECK_IDS = ('AQR-BROWSER-001','AQR-CRED-001','AQR-STATE-001','AQR-JOB-001','AQR-VALID-001','AQR-LIFE-001')


def catalog():
    return json.loads(resources.files('aqaf').joinpath('data/review_checks.json').read_text(encoding='utf8'))


def excluded(path):
    p=Path(path)
    return (p.name.startswith('.') or any(x in EXCLUDED or x.startswith('.') for x in p.parts[:-1])
            or bool(re.search(r'(?:\.test\.|\.spec\.|\.min\.|^test_|\.d\.ts$)',p.name)))


def lex(text):
    tokens=[];i=0;line=1;last_newline=-1
    while i<len(text):
        start=i;kind=None;value=None;c=text[i]
        if c.isspace():
            i+=1
        elif text.startswith('//',i):
            end=text.find('\n',i);i=len(text) if end<0 else end
        elif text.startswith('/*',i):
            end=text.find('*/',i+2)
            if end<0:raise ValueError('unsupported_syntax')
            i=end+2
        elif c in '\"\'`':
            quote=c;i+=1
            while i<len(text):
                if text[i]=='\\':i+=2;continue
                if text[i]==quote:break
                i+=1
            if i>=len(text):raise ValueError('unsupported_syntax')
            i+=1;kind='opaque' if quote=='`' else 'string';value='' if quote=='`' else text[start+1:i-1]
        elif c=='/' and (not tokens or tokens[-1].value in {'=', '(', '[', '{', ',', ':', 'return', '=>', '!', '?', '&&', '||', ';'}):
            i+=1;in_class=False
            while i<len(text):
                if text[i]=='\\':i+=2;continue
                if text[i]=='[':in_class=True
                elif text[i]==']':in_class=False
                elif text[i]=='/' and not in_class:break
                elif text[i]=='\n':raise ValueError('unsupported_syntax')
                i+=1
            if i>=len(text):raise ValueError('unsupported_syntax')
            i+=1
            while i<len(text) and text[i].isalpha():i+=1
            kind='opaque';value=''
        else:
            match=_ATOM.match(text,i)
            if match:
                value=match.group();i+=len(value);kind='name' if re.match('[A-Za-z_$]',value) else 'symbol'
            else:kind='symbol';value=c;i+=1
        if kind:
            tokens.append(Token(kind,value,start,i,line,start-last_newline))
            if len(tokens)>MAX_TOKENS:raise ValueError('unsupported_limit')
        segment=text[start:i]
        count=segment.count('\n')
        if count:line+=count;last_newline=text.rfind('\n',start,i)
    return tokens


class Structure:
    def __init__(self,tokens):
        self.t=tokens;self.pairs={};stack=[]
        for i,t in enumerate(tokens):
            if t.kind!='symbol':continue
            if t.value in ('(', '[', '{'):stack.append(i)
            elif t.value in (')',']','}'):
                if not stack or {'(':')','[':']','{':'}'}[tokens[stack[-1]].value]!=t.value:raise ValueError('unsupported_syntax')
                other=stack.pop();self.pairs[other]=i;self.pairs[i]=other
        if stack:raise ValueError('unsupported_syntax')
        self.scopes=[{'start':-1,'end':len(tokens),'params':[],'parent':None}]
        for i,t in enumerate(tokens):
            body=None;params=[]
            if t.kind=='name' and t.value=='function':
                j=i+1
                if j<len(tokens) and tokens[j].value=='*':j+=1
                if j<len(tokens) and tokens[j].kind=='name':j+=1
                if j in self.pairs and tokens[j].value=='(':
                    close=self.pairs[j];params=list(range(j+1,close));k=close+1
                    while k<len(tokens) and k<close+32 and tokens[k].value not in {'{',';','=>'}:k+=1
                    if k in self.pairs and tokens[k].value=='{':body=k
            elif t.kind=='symbol' and t.value=='=>' and i+1 in self.pairs and tokens[i+1].value=='{':
                body=i+1
                if i-1 in self.pairs and tokens[i-1].value==')':params=list(range(self.pairs[i-1]+1,i-1))
                elif i:params=[i-1]
            if body is not None:self.scopes.append({'start':body,'end':self.pairs[body],'params':params,'parent':None})
        self.scopes[1:]=sorted(self.scopes[1:],key=lambda s:s['start'])
        if len(self.scopes)>MAX_SCOPES:raise ValueError('unsupported_limit')
        starts={s['start']:i for i,s in enumerate(self.scopes) if i};active=[0];self.owner=[]
        for i in range(len(tokens)):
            while len(active)>1 and i>self.scopes[active[-1]]['end']:active.pop()
            if i in starts:
                n=starts[i];self.scopes[n]['parent']=active[-1];active.append(n)
            self.owner.append(active[-1])
        self.by_owner={}
        for i,owner in enumerate(self.owner):self.by_owner.setdefault(owner,[]).append(i)
        self.defs={}
        for owner,s in enumerate(self.scopes):
            for chunk in self.split_indices(s['params']):
                if chunk and tokens[chunk[0]].kind=='name':self.defs[(owner,tokens[chunk[0]].value)]=(chunk[0],None)
        for i,t in enumerate(tokens[:-2]):
            if t.kind=='name' and t.value in {'const','let','var'} and tokens[i+1].kind=='name' and tokens[i+2].value=='=':
                end=self.expression_end(i+3)
                self.defs[(self.owner[i],tokens[i+1].value)]=(i,list(range(i+3,end)))
        # Straight-line identifier assignments supersede earlier local definitions.
        for i,token in enumerate(tokens[:-2]):
            if token.kind!='name' or tokens[i+1].value!='=' or (i and tokens[i-1].value in {'.','?.','const','let','var'}):continue
            origin,_=self.definition(token.value,self.owner[i],i)
            if origin is not None:self.defs[(origin,token.value)]=(i,list(range(i+2,self.expression_end(i+2))))
        self.calls=[]
        for i,t in enumerate(tokens[:-1]):
            if t.kind!='name' or i+1 not in self.pairs or tokens[i+1].value!='(':continue
            start=i;chain=[t.value]
            while start>=2 and tokens[start-1].value in {'.','?.'} and tokens[start-2].kind=='name':
                start-=2;chain.insert(0,tokens[start].value)
            self.calls.append({'start':start,'end':self.pairs[i+1], 'name':chain,
                'args':self.split_range(i+2,self.pairs[i+1]),'owner':self.owner[start],
                'new':start>0 and tokens[start-1].value=='new'})

    def split_indices(self,indices):
        if not indices:return []
        return self.split_range(indices[0],indices[-1]+1)

    def split_range(self,start,end):
        result=[];chunk=[];i=start
        while i<end:
            if self.t[i].kind=='symbol' and self.t[i].value==',':result.append(chunk);chunk=[];i+=1;continue
            if i in self.pairs and self.pairs[i]>i:
                close=self.pairs[i];chunk.extend(range(i,close+1));i=close+1
            else:chunk.append(i);i+=1
        if chunk:result.append(chunk)
        return result

    def expression_end(self,start):
        i=start
        while i<len(self.t):
            if self.t[i].kind=='symbol' and self.t[i].value in {';', '}'}:return i
            if i>start and self.t[i].line>self.t[i-1].line and self.t[i].value in {'const','let','var','function','return'}:return i
            if i in self.pairs and self.pairs[i]>i:i=self.pairs[i]+1
            else:i+=1
        return i

    def values(self,indices):return [self.t[i].value for i in indices]
    def direct(self,owner):return self.by_owner.get(owner,[])
    def definition(self,name,owner,before):
        while owner is not None:
            result=self.defs.get((owner,name))
            if result and result[0]<before:return owner,result[1]
            owner=self.scopes[owner]['parent']
        return None,None

    def properties(self,indices):
        if not indices or indices[0] not in self.pairs or self.t[indices[0]].value!='{':return None
        if self.pairs[indices[0]]!=indices[-1]:return None
        out={}
        for entry in self.split_range(indices[0]+1,indices[-1]):
            if self.t[entry[0]].kind not in {'name','string'}:return None
            if len(entry)>1 and self.t[entry[1]].value==':':out[self.t[entry[0]].value]=entry[2:]
            elif len(entry)==1:out[self.t[entry[0]].value]=entry
            else:return None
        return out


def _review_source(text,path,apply_exclusions=True):
    """Analyze a bounded source string; output contains no source snippets/literals."""
    result={'status':'assessed','signals':[]}
    if Path(path).is_absolute() or '..' in Path(path).parts or '\\' in str(path) or '\x00' in str(path):result['status']='unsupported_path';return result
    if Path(path).suffix.lower() not in EXTENSIONS:result['status']='unsupported_language';return result
    if apply_exclusions and excluded(path):result['status']='excluded_scope';return result
    if len(text.encode('utf8'))>MAX_FILE_BYTES:result['status']='unsupported_limit';return result
    try:s=Structure(lex(text))
    except (ValueError,RecursionError) as error:
        result['status']='unsupported_limit' if str(error)=='unsupported_limit' else 'unsupported_syntax';return result
    t=s.t;checks={c['id']:c for c in catalog()['checks']};source_digest=hashlib.sha256(text.encode('utf8')).hexdigest()
    seen=set(); budget=[5000]
    def spend():
        budget[0]-=1
        if budget[0]<0:raise ValueError('unsupported_limit')
    def emit(check,variant,index,fact,kind='review_candidate',controls=()):
        key=(check,variant,index)
        if key in seen:return
        if len(result['signals'])>=100:
            result['status']='assessed_limited';return
        seen.add(key);token=t[index];entry=checks[check]
        result['signals'].append({'check_id':check,'variant':variant,'kind':kind,'confirmed':False,'runtime_verified':False,
            'origin':'static_review_heuristic','review_state':'unreviewed','confidence':'medium' if kind=='observed_control' else 'low',
            'locations':[{'path':str(path),'line':token.line,'column':token.column}],
            'observed_fact':fact,'observed_controls':list(controls),
            'unknowns':entry['unknowns'],'next_test':entry['next_test'],'source_ids':entry['source_ids'],
            'source_digest':source_digest,'fingerprint':hashlib.sha256((check+'\0'+variant+'\0'+str(path)+'\0'+str(token.line)+'\0'+source_digest).encode()).hexdigest()})
    # Worker/browser error transport is counterevidence, never a missing-logging claim.
    for call in s.calls:
        if call['name'][-1]=='postMessage' and call['args']:
            props=s.properties(call['args'][0])
            if props and any(t[i].kind=='string' and t[i].value=='error' for i in props.get('type',[])):
                emit('AQR-BROWSER-001','error_message_channel',call['start'],
                     'An explicit error-type message is sent through a browser/worker message channel.', 'observed_control',
                     ['Explicit error transport is visible; absence of console logging is not absence of error reporting.'])
    # Encoded literal ancestry: allowlisted syntax only, no decoding or evaluation.
    def embedded(indices,owner,before,depth=0,visited=None):
        spend()
        if depth>4 or len(indices)>4000:return False
        visited=set() if visited is None else visited
        for i in indices:
            value=t[i].value
            if t[i].kind=='string' and value and value not in {'base64','base64url','utf8','utf-8','hex'} and not re.search(r'(?i)todo|example|placeholder|fake|test.only|changeme',value):return True
            if t[i].kind=='name' and value not in visited:
                origin,expr=s.definition(value,owner,before)
                if expr is not None and (origin,value) not in visited:
                    visited.add((origin,value))
                    if embedded(expr,origin,before,depth+1,visited):return True
        return False
    def decoded(indices,owner,before,depth=0):
        spend()
        if depth>4 or len(indices)>4000:return False
        inside=[c for c in s.calls if c['start'] in indices and (c['name']==['Buffer','from'] or c['name'][-1]=='atob')]
        for call in inside:
            encoded=call['name'][-1]=='atob' or any(t[i].kind=='string' and t[i].value in {'base64','base64url'} for arg in call['args'][1:] for i in arg)
            data=[i for i in indices if not (t[i].kind=='string' and t[i].value in {'base64','base64url','utf8','hex'})]
            if encoded and embedded(data,owner,before):return True
        for i in indices:
            if t[i].kind=='name':
                origin,expr=s.definition(t[i].value,owner,before)
                if expr is not None and decoded(expr,origin,before,depth+1):return True
        return False
    for i,token in enumerate(t):
        if token.value not in {'||','??'}:continue
        end=s.expression_end(i+1);right=list(range(i+1,end));owner=s.owner[i]
        # Only a fallback assignment to a header/auth-like binding; no general dataflow claim.
        start=max(0,i-10);eq=next((j for j in range(i-1,start-1,-1) if t[j].value=='='),None)
        if eq is None:continue
        names=[t[j].value.lower() for j in range(start,eq) if t[j].kind in {'name','string'}]
        if not any(re.search(r'header|authorization|credential|api_?key|token|password',name) for name in names):continue
        if decoded(right,owner,i):emit('AQR-CRED-001','encoded_fallback_binding',i,
            'Supported lexical assignments link an encoded-literal construction to a fallback in a header/authentication-like binding. Branches, authentication use and validity are unverified; values are omitted.')
    # Durable-state sequences: publication and recovery are reviewed independently.
    for call in s.calls:
        if call['name'][-1] in {'writeFile','writeFileSync'} and len(call['args'])>=2:
            serial=any(c['name']==['JSON','stringify'] and c['start'] in call['args'][1] for c in s.calls)
            if not serial:continue
            path_arg=s.values(call['args'][0]);rename=next((c for c in s.calls if c['owner']==call['owner'] and c['start']>call['end'] and c['name'][-1] in {'rename','renameSync'} and len(c['args'])>=2 and s.values(c['args'][0])==path_arg and s.values(c['args'][1])!=path_arg),None)
            if rename:emit('AQR-STATE-001','publication_sequence',call['start'],'A JSON write is followed by rename from the same temporary binding. Filesystem durability and all paths remain unverified.','observed_control')
            else:emit('AQR-STATE-001','direct_json_write',call['start'],'A JSON serialization is written directly with no rename publication observed in the same function; wrapper behavior is unknown.')
    for owner,scope in enumerate(s.scopes):
        body=s.direct(owner);calls=[c for c in s.calls if c['owner']==owner]
        parses=any(c['name']==['JSON','parse'] for c in calls)
        for i in body:
            if t[i].value!='catch' or not parses:continue
            j=i+1
            if j<len(t) and t[j].value=='(':j=s.pairs[j]+1
            if j>=len(t) or t[j].value!='{':continue
            part=list(range(j+1,s.pairs[j]));values=s.values(part)
            empty=any(t[k].value=='return' and k+1<len(t) and t[k+1].value in {'{','['} and s.pairs.get(k+1)==k+2 for k in part)
            if empty and 'throw' not in values and not any(c['start'] in part and c['name'][-1] in {'rename','renameSync','copyFile','copyFileSync'} for c in calls):
                emit('AQR-STATE-001','empty_recovery_default',i,'A JSON-parse function catches failure and returns an empty container; preservation of corrupt state is not visible in this catch block.')
        # Admission counter used before an await but incremented afterward.
        for i in body:
            if t[i].value!='while' or i+1>=len(t) or t[i+1].value!='(':continue
            close=s.pairs[i+1];j=close+1
            if j>=len(t) or t[j].value!='{':continue
            loop=list(range(j+1,s.pairs[j]));condition={t[k].value for k in range(i+2,close) if t[k].kind=='name'}
            claims=[c for c in calls if c['start'] in loop and c['name'][-1] in {'claim','claimJob','takeJob','dequeue','nextJob'} and c['start'] and t[c['start']-1].value=='await']
            for claim in claims:
                increments=[k for k in loop if t[k].value in condition and k+1<len(t) and t[k+1].value in {'++','+='}]
                if increments and min(increments)>claim['end']:emit('AQR-JOB-001','admission_after_await',claim['start'],'A loop-condition counter is incremented after an awaited claim-like call. Overlapping admission and synchronization require characterization.')
        # Unknown/any input asserted into an application type without a visible guard.
        unknown={t[k].value for k in scope['params'] if t[k].kind=='name' and k+2<len(t) and t[k+1].value==':' and t[k+2].value in {'unknown','any'}}
        for i in body:
            if t[i].value!='return' or i+2>=len(t) or t[i+1].value not in unknown or t[i+2].value!='as':continue
            name=t[i+1].value
            guards=[]
            for call in calls:
                if call['start']>=i or not any(name in s.values(arg) for arg in call['args']):continue
                for k in body:
                    if t[k].value!='if' or k+1>=len(t) or t[k+1].value!='(':continue
                    close=s.pairs[k+1];j=close+1
                    if k<call['start']<close and j<len(t) and t[j].value=='{' and s.pairs[j]<i and 'throw' in s.values(list(range(j+1,s.pairs[j]))):guards.append(call)
            if guards:emit('AQR-VALID-001','validation_control',i,'A check of the same unknown input precedes a type assertion; validator semantics and control-flow coverage remain unverified.','observed_control')
            else:emit('AQR-VALID-001','unknown_type_assertion',i,'A function returns an unknown/any input through a TypeScript assertion. Assertions alone do not perform runtime validation.')
    for call in s.calls:
        if call['name'][-1] not in {'update','updateMany'} or not call['args']:continue
        props=s.properties(call['args'][0])
        if not props:continue
        where=s.properties(props.get('where',[]));data=s.properties(props.get('data',[]))
        if where is None or not data or not any(t[i].kind=='string' and t[i].value in {'completed','failed','cancelled','canceled'} for i in data.get('status',[])):continue
        if set(where)=={'id'}:emit('AQR-JOB-001','terminal_id_only',call['start'],'A terminal-state update has only an ID in its inline where clause; ownership, state and transaction fencing may exist elsewhere.')
        elif 'id' in where:emit('AQR-JOB-001','terminal_guard_fields',call['start'],'A terminal update includes additional inline ownership/state filter fields; their semantics and database enforcement remain unverified.','observed_control')
    for call in s.calls:
        if call['name']!=['Worker'] or not call['new'] or call['owner']==0:continue
        owner=call['owner'];start=call['start'];binding=t[start-2].value if start>=2 and t[start-1].value=='new' else ''
        # Declaration is NAME = new Worker(...).
        if start>=3 and t[start-1].value=='new' and t[start-2].value=='=':binding=t[start-3].value
        terminate=False;error=False
        for c in s.calls:
            if c['name'][0]==binding:
                origin,_=s.definition(binding,c['owner'],c['start'])
                if origin==owner and c['name'][-1]=='terminate':terminate=True
                if origin==owner and c['name'][-1]=='addEventListener' and c['args'] and any(t[k].value=='error' for k in c['args'][0]):error=True
        for k in range(start+1,len(t)-3):
            if [t[x].value for x in range(k,k+4)]==[binding,'.','onerror','=']:
                origin,_=s.definition(binding,s.owner[k],k)
                if origin==owner:error=True
        if terminate and error:emit('AQR-LIFE-001','worker_controls',start,'A function-created worker has visible error and termination controls; lifecycle coverage and all exit paths remain unverified.','observed_control')
        else:emit('AQR-LIFE-001','function_worker_ownership',start,'A worker is constructed inside a function; local error/termination coverage is incomplete or delegated.',controls=[label for yes,label in [(terminate,'Termination call observed.'),(error,'Error handler observed.')] if yes])
    for call in s.calls:
        if call['name'][-1]!='save' or not call['start'] or t[call['start']-1].value!='await':continue
        owner=call['owner'];body=s.direct(owner)
        for i in body:
            if i<=call['end'] or t[i].value!='status' or i+2>=len(t) or t[i+1].value!='=' or t[i+2].kind!='string' or t[i+2].value.lower()!='saved':continue
            guarded=False
            for k in body:
                if t[k].value!='if' or k+1>=len(t) or t[k+1].value!='(':continue
                close=s.pairs[k+1];values=s.values(list(range(k+2,close)));j=close+1
                if j<len(t) and t[j].value=='{' and j<i<s.pairs[j] and any(v in {'===','==','!==','!='} for v in values) and any(re.search(r'(?i)revision|version|generation',v) for v in values):guarded=True
            if guarded:emit('AQR-LIFE-001','save_revision_control',i,'A revision/version comparison guards the saved-status assignment; revision ownership and acknowledgement semantics remain unverified.','observed_control')
            else:emit('AQR-LIFE-001','saved_after_await',i,'A saved status is assigned after an awaited save without a visible revision guard on that assignment; concurrent edits require characterization.')
    result['signals'].sort(key=lambda x:(x['locations'][0]['line'],x['locations'][0]['column'],x['check_id'],x['variant']))
    return result


def review_source(text,path):
    from .adapters import analyze_source
    # Direct callers retain the conservative path-role exclusions.
    if Path(path).is_absolute() or '..' in Path(path).parts or '\\' in str(path) or '\x00' in str(path):return {'status':'unsupported_path','signals':[]}
    if excluded(path):return {'status':'excluded_scope','signals':[]}
    return analyze_source(text,path)


def review_files(files,root,scope=None,max_files=MAX_FILES,max_total_bytes=MAX_TOTAL_BYTES,max_file_bytes=MAX_FILE_BYTES,offset=0):
    """Round-robin components/languages; preserve evidence and explicit omissions."""
    from collections import Counter,defaultdict,deque
    import unicodedata
    from .adapters import analyze_source,language,support_matrix,FAMILIES
    metadata=catalog();signals=[];counts=Counter();buckets=defaultdict(list);groups={};outcomes=[];digests=defaultdict(list)
    roles=(scope.config.get('review_roles',['production','source','unknown','tooling']) if scope else ['production','source','unknown','tooling'])
    def group(record,lang):
        key=(record.get('owner','root'),lang)
        if key not in groups:groups[key]={'owner':key[0],'language':lang,'files_collected':0,'eligible':0,'attempted':0,'assessed':0,'outcomes':Counter()}
        return groups[key]
    feasibility=Counter();pool=0
    for path in files:
        relative=path.relative_to(root).as_posix();record=scope.record(path) if scope else {'relative':relative,'role':'unknown','priority':relative}
        lang=language(relative) or (record.get('language') if record.get('language_basis')=='bounded_shebang' else None);g=group(record,lang or record.get('language','other'));g['files_collected']+=1
        if not lang:
            counts['unsupported_language']+=1;g['outcomes']['unsupported_language']+=1
            if record.get('language') not in {'other',None}:feasibility[record['language']]+=1
            continue
        if record.get('role') not in roles or (scope is None and excluded(relative)):
            counts['excluded_scope']+=1;g['outcomes']['excluded_scope']+=1;continue
        pool+=1;g['eligible']+=1;buckets[(g['owner'],lang)].append((path,relative,record,g))
    # Deterministic rotation prevents large PHP/JS trees from starving smaller components.
    queue=deque(deque(sorted(rows,key=lambda r:r[2].get('priority',r[1]))) for _,rows in sorted(buckets.items()))
    ordered=[]
    while queue:
        rows=queue.popleft();ordered.append(rows.popleft())
        if rows:queue.append(rows)
    attempted=0;total=0;assessed=0
    for ordinal,(path,relative,record,g) in enumerate(ordered):
        status=None;result=None;raw=None
        if ordinal<offset:status='before_offset_unassessed'
        elif attempted>=max_files:status='file_budget'
        elif total>=max_total_bytes:status='byte_budget'
        else:
            attempted+=1;g['attempted']+=1
            try:
                if scope:size=record['size']
                else:
                    if path.is_symlink():raise ValueError('excluded_symlink')
                    size=path.stat().st_size
                if size>max_file_bytes:status='unsupported_limit'
                elif total+size>max_total_bytes:status='byte_budget'
                else:
                    raw=scope.raw(path,max_file_bytes+1) if scope else path.read_bytes()[:max_file_bytes+1]
                    total+=len(raw)
                    if len(raw)!=size:status='changed_or_unreadable'
                    elif len(raw)>max_file_bytes:status='unsupported_limit'
                    else:
                        text=raw.decode('utf8');context={'role':record.get('role','unknown'),'owner':record.get('owner','root'),'sql_dialect':scope.config.get('sql_dialect','unknown') if scope else 'unknown'}
                        result=analyze_source(text,relative,context);status=result['status']
                        digest=hashlib.sha256(raw).hexdigest();digests[digest].append(relative)
                        if status.startswith('assessed'):assessed+=1;g['assessed']+=1
                        available=max(0,5000-len(signals));new=result['signals'][:available]
                        for signal in new:
                            # Evidence identity is content-sensitive; concern identity is separate.
                            loc=signal['locations'][0];logical='\0'.join([signal['check_id'],signal['variant'],record.get('owner','root'),relative,str(loc['line']),str(loc['column'])])
                            signal['logical_concern_id']=hashlib.sha256(logical.encode()).hexdigest()
                            signal['display_path']=unicodedata.normalize('NFC',relative);signal['source_digest']=digest
                        signals.extend(new)
                        if len(result['signals'])>available:counts['signal_budget']+=1
            except UnicodeError:status='unsupported_encoding'
            except OSError:status='unreadable'
            except ValueError as error:status=str(error) if str(error)=='excluded_symlink' else 'unsupported_syntax'
        counts[status]+=1;g['outcomes'][status]+=1
        if len(outcomes)<10000:outcomes.append({'path':relative,'owner':g['owner'],'language':g['language'],'status':status,'ordinal':ordinal,**({'diagnostics':result['diagnostics']} if result and result.get('diagnostics') else {})})
    sources=json.loads(resources.files('aqaf').joinpath('data/source_registry.json').read_text(encoding='utf8'))
    ids={sid for check in metadata['checks'] for sid in check['source_ids']}|{sid for signal in signals for sid in signal['source_ids']}
    for g in groups.values():g['outcomes']=dict(sorted(g['outcomes'].items()))
    secondary=[]
    for lang,n in sorted(feasibility.items()):
        examples=[{'path':record['relative'],'owner':record['owner'],'role':record['role']} for record in (scope.records if scope else []) if record.get('language')==lang][:8]
        secondary.append({'language':lang,'collected_candidate_files':n,'examples':examples,'ownership':'filtered_owned_candidates_not_certified_authorship',
            'decision':'deferred','candidate_slice':'Passive publication/error/resource ownership facts, with language-specific sources and positive/control/adversarial fixtures before enabling.',
            'validation_effort':'Separate bounded adapter proposal plus independent applicability review; no automatic parser/compiler installation.',
            'reason':'No calibrated bounded adapter; authored intent and useful characterization require independent review. Presence is not support.'})
    selected_checks=sorted({c for g in groups.values() if g['assessed'] for c in FAMILIES.get(g['language'],[])})
    return {'schema_version':2,'status':'experimental','score_impact':0,'affects_baseline_gates':False,'checks':metadata['checks'],'signals':signals,
      'support_matrix':support_matrix(),'secondary_language_feasibility':secondary,
      'coverage_groups':[{'owner':g['owner'],'language':g['language'],'check_id':check,'files_eligible':g['eligible'],'files_assessed_partial_syntax':g['assessed'],'status':'partial_source_assessed' if g['assessed'] else 'unassessed'} for g in groups.values() for check in FAMILIES.get(g['language'],[])],
      'coverage':[{'check_id':check['id'],'status':'observed' if any(s['check_id']==check['id'] for s in signals) else 'no_observation_in_assessed_subset' if check['id'] in selected_checks else 'unassessed'} for check in metadata['checks']],
      'scope':{'languages':sorted(__import__('aqaf.adapters',fromlist=['LANGUAGE_EXTENSIONS']).LANGUAGE_EXTENSIONS),'review_roles':roles,
        'max_file_bytes':max_file_bytes,'max_files':max_files,'max_total_bytes':max_total_bytes,'files_eligible':pool,'files_attempted':attempted,'files_assessed':assessed,'bytes_read':total,'offset':offset,
        'scheduler':'round_robin_owner_language_then_source_priority','coverage_complete':counts['assessed']==pool and not counts.get('signal_budget'),
        'zero_attempt_reason':None if attempted else 'no_supported_owned_files_in_selected_roles' if not pool else 'offset_beyond_pool',
        'outcomes':dict(sorted(counts.items())),'groups':[groups[k] for k in sorted(groups)],'file_outcomes':outcomes,'file_outcomes_truncated':len(ordered)>len(outcomes),
        'resume':'Offset is an independent partial selection, not a validated merged run. No prior results or human labels are silently reused.'},
      'exact_source_copies':[{'sha256':sha,'paths':paths,'assessment':'Every owned path retains ownership and evidence; copies are not silently deduplicated.'} for sha,paths in sorted(digests.items()) if len(paths)>1][:2000],
      'limitations':['Partial experimental adapters recognize declared bounded syntax, not complete languages or frameworks.',
        'Observations are unscored, unconfirmed and not runtime verification. No observation does not establish correctness.',
        'No target execution, imports, build hooks, macros, credential decoding, provider calls or source excerpts.',
        'Per-language support is partial; dynamic calls, aliases, caller controls, complex markup and unrecognized syntax remain unresolved.',
        'Independent defect precision and human calibration remain pending; fixture conformance is not defect accuracy.'],
      'source_registry':[s for s in sources if s['id'] in ids]}
