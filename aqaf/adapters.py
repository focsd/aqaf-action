"""Bounded passive review adapters. Facts/controls are not runtime defect proofs.

Python uses its AST without compilation/import. Other new adapters recognize a
small declared subset of masked, qualified call syntax; no full language parser,
macro expansion, type/taint resolution or arbitrary control-flow proof is claimed.
"""
from __future__ import annotations
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

LANGUAGE_EXTENSIONS={'.js':'javascript','.mjs':'javascript','.cjs':'javascript','.gs':'javascript','.ts':'typescript','.mts':'typescript','.cts':'typescript',
 '.jsx':'jsx','.tsx':'tsx','.html':'html','.htm':'html','.py':'python','.kt':'kotlin','.kts':'kotlin','.java':'java','.cs':'csharp',
 '.php':'php','.rs':'rust','.ps1':'powershell','.psm1':'powershell','.command':'shell','.sh':'shell','.bash':'shell','.zsh':'shell','.sql':'sql','.swift':'swift'}
SOURCES={'swift':['S37','S38','S39','S40','S42'],'python':['S22','S30','S31'],'kotlin':['S23'],'java':['S32'],'csharp':['S24','S35'], 'php':['S25','S36'],'rust':['S26'],'powershell':['S27','S41'],'shell':['S33'],'sql':['S28'],'jsx':['S29'],'tsx':['S29'],'html':['S34']}
FAMILIES={'swift':['AQR-STATE-001','AQR-VALID-001','AQR-LIFE-001'],'python':['AQR-STATE-001','AQR-CRED-001','AQR-JOB-001','AQR-VALID-001','AQR-LIFE-001','AQR-ERROR-001'],
 'kotlin':['AQR-STATE-001','AQR-CRED-001','AQR-VALID-001','AQR-LIFE-001','AQR-ERROR-001'],
 'java':['AQR-STATE-001','AQR-CRED-001','AQR-VALID-001','AQR-ERROR-001'],
 'csharp':['AQR-STATE-001','AQR-CRED-001','AQR-JOB-001','AQR-VALID-001','AQR-LIFE-001','AQR-ERROR-001'],
 'php':['AQR-STATE-001','AQR-CRED-001','AQR-VALID-001','AQR-ERROR-001'],
 'rust':['AQR-STATE-001','AQR-CRED-001','AQR-LIFE-001','AQR-VALID-001','AQR-ERROR-001'],
 'powershell':['AQR-STATE-001','AQR-CRED-001','AQR-LIFE-001','AQR-ERROR-001'],
 'shell':['AQR-STATE-001','AQR-LIFE-001','AQR-ERROR-001'],'sql':['AQR-SQL-001']}
ALL_JS=['AQR-BROWSER-001','AQR-CRED-001','AQR-STATE-001','AQR-JOB-001','AQR-VALID-001','AQR-LIFE-001']
for _lang in ['javascript','typescript','jsx','tsx','html']:FAMILIES[_lang]=ALL_JS
MAX_SOURCE_BYTES=1500000
MAX_AST_NODES=20000
MAX_LOCAL_CALLS=2000
MAX_SIGNALS=100


def shebang_language(text):
    line=text.split('\n',1)[0][:256]
    if not line.startswith('#!'):return None
    import shlex
    try:parts=shlex.split(line[2:].strip())
    except ValueError:return None
    if not parts:return None
    command=Path(parts[0]).name
    if command=='env':
        parts=parts[1:]
        if parts and parts[0]=='-S':parts=parts[1:]
        if not parts:return None
        command=Path(parts[0]).name
    if re.fullmatch(r'python(?:[23](?:\.\d+)?)?',command):return 'python'
    return {'sh':'shell','bash':'shell','zsh':'shell','node':'javascript','php':'php','pwsh':'powershell'}.get(command)


def language(path,text=None):
    return LANGUAGE_EXTENSIONS.get(Path(path).suffix.lower()) or (shebang_language(text) if text is not None and not Path(path).suffix else None)


def support_matrix():
    return [{'language':name,'extensions':sorted(k for k,v in LANGUAGE_EXTENSIONS.items() if v==name),
             'status':'experimental_partial','checks':checks,'analysis':'passive_python_ast' if name=='python' else 'bounded_source_patterns',
             **({'dialects':['unknown_common_syntax','sqlite_common_syntax','postgresql_common_syntax','mysql_common_syntax','sqlserver_common_syntax']} if name=='sql' else {}),
             'limitations':['No whole-program/type/taint analysis or executed behavior.',
                            'Qualified direct calls/local bindings only; imported wrappers and dynamic syntax remain unresolved.',
                            'JS primitive retains its 256000-byte/20000-token parser limit even when the outer file budget is raised.' if name in {'javascript','typescript','jsx','tsx','html'} else 'Complex interpolation, macros, dialect constructs and unsupported templates can remain unassessed.']}
            for name,checks in sorted(FAMILIES.items())]


class Emitter:
    def __init__(self,text,path,lang,context):
        self.text=text;self.path=path;self.lang=lang;self.context=context or {};self.signals=[];self.seen=set()
        self.digest=hashlib.sha256(text.encode('utf8')).hexdigest()

    def emit(self,check,variant,index,fact,kind='review_candidate',controls=()):
        if len(self.signals)>=MAX_SIGNALS:return
        index=max(0,min(index,len(self.text)));line=self.text.count('\n',0,index)+1;last=self.text.rfind('\n',0,index);column=index-last
        key=(check,variant,line,column)
        if key in self.seen:return
        self.seen.add(key)
        if check=='AQR-STATE-001' and self.context.get('role') in {'tooling','tests','docs','fixture'} and kind=='review_candidate':
            kind='source_observation';fact+=' The selected role is tooling/test/documentation; a persistent-state requirement has not been established.'
        self.signals.append({'check_id':check,'variant':variant,'language':self.lang,'kind':kind,'confirmed':False,'runtime_verified':False,
          'origin':'static_review_heuristic','review_state':'unreviewed','confidence':'medium' if kind=='observed_control' else 'low',
          'locations':[{'path':self.path,'line':line,'column':column}],'observed_fact':fact,'observed_controls':list(controls),
          'unknowns':['Actual call binding, supported local control flow, imported/caller controls and operational intent require review.',
                      'Persistence, validation, authorization, lifetime and transaction behavior are not proven by this observation.'],
          'next_test':'Verify the source/role and relevant controls, then characterize the declared behavior with bounded disposable fixtures before changing application code.',
          'source_ids':SOURCES.get(self.lang,[])+(['S20'] if check=='AQR-CRED-001' else []),
          'source_digest':self.digest,'fingerprint':hashlib.sha256((check+'\0'+variant+'\0'+self.path+'\0'+str(line)+'\0'+self.digest).encode()).hexdigest(),
          'applicability':{'role':self.context.get('role','unknown'),'owner':self.context.get('owner','root'),'intent_verified':False,**({key:self.context[key] for key in ('sql_role','sql_dialect') if key in self.context})}})


def _index(text,node):
    # Python AST columns are UTF-8 byte offsets, reports use Unicode codepoints.
    lines=text.splitlines(keepends=True);line=max(1,getattr(node,'lineno',1));prefix=''.join(lines[:line-1]);raw=lines[line-1].encode('utf8') if line<=len(lines) else b''
    return len(prefix)+len(raw[:getattr(node,'col_offset',0)].decode('utf8','ignore'))


def _name(node):
    if isinstance(node,ast.Name):return node.id
    if isinstance(node,ast.Attribute):
        before=_name(node.value);return before+'.'+node.attr if before else ''
    return ''


def _scope_nodes(node):
    stack=[node]
    while stack:
        current=stack.pop();yield current
        children=list(ast.iter_child_nodes(current))
        for child in reversed(children):
            if child is not node and isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):continue
            stack.append(child)


def python_review(text,path,context):
    emitter=Emitter(text,path,'python',context)
    try:tree=ast.parse(text)
    except (SyntaxError,ValueError,RecursionError):return {'status':'unsupported_syntax','signals':[]}
    all_nodes=list(ast.walk(tree))
    if len(all_nodes)>MAX_AST_NODES:return {'status':'unsupported_limit','signals':[]}
    aliases={};shadow=set()
    for n in tree.body:
        if isinstance(n,ast.Import):
            for alias in n.names:aliases[alias.asname or alias.name.split('.')[0]]=alias.name
        elif isinstance(n,ast.ImportFrom):
            for alias in n.names:
                if n.level:shadow.add(alias.asname or alias.name)
                else:aliases[alias.asname or alias.name]=(n.module or '')+'.'+alias.name
    shadow.update(n.name for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.name in aliases)
    scopes=[tree]+[n for n in all_nodes if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]
    for scope in scopes:
        nodes=list(_scope_nodes(scope));local_shadow=set(shadow);definitions={};handles={}
        if isinstance(scope,(ast.FunctionDef,ast.AsyncFunctionDef)):
            local_shadow.update(a.arg for a in scope.args.args+scope.args.kwonlyargs)
            if scope.args.vararg:local_shadow.add(scope.args.vararg.arg)
            if scope.args.kwarg:local_shadow.add(scope.args.kwarg.arg)
        for n in nodes:
            if isinstance(n,(ast.Assign,ast.AnnAssign)):
                targets=n.targets if isinstance(n,ast.Assign) else [n.target]
                for target in targets:
                    if isinstance(target,ast.Name):definitions.setdefault(target.id,[]).append((n.lineno,n.value));local_shadow.add(target.id)
            if isinstance(n,(ast.With,ast.AsyncWith)):
                for item in n.items:
                    if isinstance(item.optional_vars,ast.Name) and isinstance(item.context_expr,ast.Call) and _name(item.context_expr.func)=='open':
                        args=item.context_expr.args;mode=args[1].value if len(args)>1 and isinstance(args[1],ast.Constant) else None
                        handles[item.optional_vars.id]=(item.context_expr,mode)
        def name(n):
            value=_name(n);root=value.split('.')[0]
            if root in aliases and root not in local_shadow:value=aliases[root]+value[len(root):]
            elif root in local_shadow and root in {'json','base64','typing','asyncio','logging'}:return ''
            return value
        def calls_in(n):return [x for x in ast.walk(n) if isinstance(x,ast.Call)]
        calls=[n for n in nodes if isinstance(n,ast.Call)]
        def empty(n):return isinstance(n,(ast.Dict,ast.List,ast.Set,ast.Tuple)) and not (getattr(n,'keys',None) or getattr(n,'elts',None))
        def json_dump(n):return isinstance(n,ast.Call) and name(n.func) in {'json.dump','json.dumps'}
        def guarded(data_name,before):
            for n in nodes:
                if not isinstance(n,ast.If) or n.lineno>=before:continue
                if not any(isinstance(x,ast.Name) and x.id==data_name for x in ast.walk(n.test)):continue
                # Only an explicit rejection branch is counterevidence, not a call named validate.
                if isinstance(n.test,ast.UnaryOp) and isinstance(n.test.op,ast.Not) and any(isinstance(x,(ast.Raise,ast.Return)) for x in n.body):return True
            return False
        def decoded(n,before,depth=0,seen=None):
            if depth>4:return False
            if isinstance(n,ast.Call) and name(n.func) in {'base64.b64decode','base64.urlsafe_b64decode','bytes.fromhex'}:
                return bool(n.args and isinstance(n.args[0],ast.Constant) and isinstance(n.args[0].value,(str,bytes)))
            if isinstance(n,ast.Name):
                seen=set() if seen is None else seen
                if n.id in seen:return False
                prior=[x for x in definitions.get(n.id,[]) if x[0]<before]
                return bool(prior and decoded(prior[-1][1],prior[-1][0],depth+1,seen|{n.id}))
            return False
        for call in calls:
            cname=name(call.func);index=_index(text,call)
            if cname=='json.dump' and len(call.args)>1:
                handle=call.args[1];known=isinstance(handle,ast.Name) and handle.id in handles and handles[handle.id][1] in {'w','wb','a','ab','x','xb'}
                controls=[c for c in calls if name(c.func) in {'os.replace','os.rename'} and c.lineno>call.lineno]
                # Match the source path bound to the file handle, not an unrelated rename.
                linked=False
                if known:
                    opener=handles[handle.id][0]
                    linked=any(c.args and opener.args and ast.dump(c.args[0])==ast.dump(opener.args[0]) for c in controls)
                emitter.emit('AQR-STATE-001','json_publication_control' if linked else 'json_file_publication',index,
                    'JSON serialization writes to a file-like sink; publication/recovery requirements and caller controls remain unresolved.',
                    'observed_control' if linked else 'review_candidate' if known else 'source_observation', ['A later rename/replace uses the same locally opened path.'] if linked else [])
            if isinstance(call.func,ast.Attribute) and call.func.attr in {'write_text','write_bytes','write'} and call.args and any(json_dump(c) for c in calls_in(call.args[0])):
                receiver=call.func.value;known=False;written_path=None
                if isinstance(receiver,ast.Call) and name(receiver.func) in {'pathlib.Path','open'}:
                    known=True;written_path=receiver.args[0] if receiver.args else None
                if isinstance(receiver,ast.Name):
                    if receiver.id in handles:known=True;opener=handles[receiver.id][0];written_path=opener.args[0] if opener.args else None
                    else:
                        prior=[x for x in definitions.get(receiver.id,[]) if x[0]<call.lineno]
                        if prior and isinstance(prior[-1][1],ast.Call) and name(prior[-1][1].func) in {'pathlib.Path'}:
                            known=True;written_path=prior[-1][1].args[0] if prior[-1][1].args else None
                linked=bool(written_path and any(name(c.func) in {'os.replace','os.rename'} and c.lineno>call.lineno and c.args and ast.dump(c.args[0])==ast.dump(written_path) for c in calls))
                emitter.emit('AQR-STATE-001','json_publication_control' if linked else 'direct_json_write',index,
                    'A recognized write-method call receives JSON serialization; sink identity and publication intent require characterization.',
                    'observed_control' if linked else 'review_candidate' if known else 'source_observation', ['Same-path rename/replace is visible.'] if linked else [])
            if cname in {'typing.cast'} and len(call.args)>1 and isinstance(call.args[1],ast.Name):
                controlled=guarded(call.args[1].id,call.lineno)
                emitter.emit('AQR-VALID-001','validation_control' if controlled else 'python_type_cast',index,'A type-cast syntax uses external/dynamic data; a cast does not establish domain validation.', 'observed_control' if controlled else 'review_candidate')
            if cname.endswith(('.model_validate','.parse_obj','.parse_raw')):
                emitter.emit('AQR-VALID-001','validator_api_observed',index,'A validation-shaped API is called; schema completeness, result use and actual binding remain unverified.','observed_control')
            if cname in {'asyncio.create_task','asyncio.ensure_future'}:
                owner=next((target for target,values in definitions.items() if any(value is call for _,value in values)),None)
                awaited=bool(owner and any(isinstance(n,ast.Await) and isinstance(n.value,ast.Name) and n.value.id==owner for n in nodes))
                cancelled=bool(owner and any(isinstance(c.func,ast.Attribute) and _name(c.func.value)==owner and c.func.attr=='cancel' for c in calls))
                emitter.emit('AQR-LIFE-001','task_owner_control' if awaited or cancelled else 'python_task_ownership',index,'A task is created in the selected scope; cleanup, cancellation and all exit paths require review.', 'observed_control' if awaited or cancelled else 'review_candidate', [x for yes,x in [(awaited,'Await of the same task binding is visible.'),(cancelled,'Cancellation on the same task binding is visible.')] if yes])
            if cname.startswith(('logging.','logger.')) and cname.split('.')[-1] in {'warning','error','exception','critical','warn'}:
                emitter.emit('AQR-ERROR-001','diagnostic_call',index,'A recognized diagnostic/error call is present; adequacy and sensitive-data handling remain unverified.','observed_control')
        for node in nodes:
            if isinstance(node,ast.Try) and any(name(c.func) in {'json.load','json.loads'} for n in node.body for c in calls_in(n)):
                readers=[c for statement in node.body for c in calls_in(statement)]
                file_context=any(name(c.func)=='open' or (isinstance(c.func,ast.Attribute) and c.func.attr in {'read_text','read_bytes'}) or (name(c.func)=='json.load' and c.args and isinstance(c.args[0],ast.Name) and c.args[0].id in handles) for c in readers)
                for handler in node.handlers:
                    for statement in handler.body:
                        if isinstance(statement,ast.Return) and statement.value is not None and empty(statement.value):emitter.emit('AQR-STATE-001','empty_json_recovery',_index(text,statement),'An exception handler around JSON-reading syntax returns an empty container; file-backed state and recovery intent require characterization.', 'review_candidate' if file_context else 'source_observation')
            if isinstance(node,ast.While):
                counters={x.id for x in ast.walk(node.test) if isinstance(x,ast.Name)}
                claims=[x for x in ast.walk(node) if isinstance(x,ast.Await) and isinstance(x.value,ast.Call) and re.fullmatch(r'(?:claim|claim_job|take_job|dequeue)',name(x.value.func).split('.')[-1])]
                for claim in claims:
                    late=[x for x in ast.walk(node) if isinstance(x,ast.AugAssign) and isinstance(x.target,ast.Name) and x.target.id in counters and isinstance(x.op,ast.Add) and x.lineno>claim.lineno]
                    if late:
                        locked=False
                        for control in nodes:
                            if not isinstance(control,ast.AsyncWith):continue
                            if not any(x is claim for x in ast.walk(control)):continue
                            for item in control.items:
                                expr=item.context_expr
                                if isinstance(expr,ast.Name):
                                    prior=[value for line,value in definitions.get(expr.id,[]) if line<control.lineno]
                                    expr=prior[-1] if prior else expr
                                if isinstance(expr,ast.Call) and name(expr.func) in {'asyncio.Lock','asyncio.Semaphore','asyncio.BoundedSemaphore'}:locked=True
                        emitter.emit('AQR-JOB-001','admission_lock_context' if locked else 'admission_after_await',_index(text,claim),
                            'A loop admission counter is incremented after an awaited claim-shaped call; overlap and serialization require characterization.',
                            'source_observation' if locked else 'review_candidate', ['An enclosing async-with uses a locally constructed asyncio lock/semaphore; capacity and complete admission coverage remain unresolved.'] if locked else [])
            if isinstance(node,(ast.Assign,ast.AnnAssign)):
                targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                if isinstance(node.value,ast.BoolOp) and isinstance(node.value.op,ast.Or) and any(re.search(r'(?i)header|auth|api_?key|token|secret',_name(t)) for t in targets) and any(decoded(x,node.lineno) for x in node.value.values):
                    emitter.emit('AQR-CRED-001','encoded_fallback',_index(text,node),'An authentication/header-shaped fallback has bounded lexical ancestry to an encoded literal; request use, credential meaning and validity are unverified.')
    return {'status':'assessed_limited' if len(emitter.signals)>=MAX_SIGNALS else 'assessed','signals':emitter.signals}


def mask_source(text,lang):
    """Position-preserving mask for comments/literals and shell here-documents."""
    chars=list(text);literals=[];i=0;n=len(text)
    def erase(start,end):
        for k in range(start,end):
            if chars[k] not in '\r\n':chars[k]=' '
    while i<n:
        start=i
        if lang=='powershell' and text.startswith(('@\"',"@'"),i):
            quote=text[i+1];end=re.search(r'(?m)^'+re.escape(quote+'@')+r'(?=$|\s|[)\]};|+.,])',text[i+2:])
            if not end:raise ValueError('unsupported_syntax')
            i=i+2+end.end();erase(start,i);continue
        if lang=='shell' and text.startswith('<<',i):
            match=re.match(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?[^\n]*\n",text[i:])
            if match:
                after=i+match.end();end=re.search(r'(?m)^\t*'+re.escape(match.group(1))+r'\s*$',text[after:])
                if not end:raise ValueError('unsupported_syntax')
                i=after+end.end();erase(start,i);continue
        block=None
        if text.startswith('/*',i) and lang not in {'powershell','shell'}:block='*/'
        if lang=='powershell' and text.startswith('<#',i):block='#>'
        if block:
            end=text.find(block,i+2)
            if end<0:raise ValueError('unsupported_syntax')
            if lang=='sql' and '/*' in text[i+2:end]:raise ValueError('unsupported_syntax')
            i=end+2;erase(start,i);continue
        comment=(text.startswith('//',i) and lang not in {'powershell','shell','sql'}) or (text[i]=='#' and (lang in {'powershell','shell'} or (lang=='php' and not text.startswith('#[',i)))) or (text.startswith('--',i) and lang=='sql')
        if comment:
            end=text.find('\n',i);i=n if end<0 else end;erase(start,i);continue
        if lang=='rust' and re.match(r'(?:br|r)#{0,32}"',text[i:]):
            m=re.match(r'(?:br|r)(#{0,32})"',text[i:]);end=text.find('"'+m.group(1),i+len(m.group()))
            if end<0:raise ValueError('unsupported_syntax')
            i=end+1+len(m.group(1));literals.append((start,i));erase(start,i);continue
        if lang=='powershell' and text[i]=='`':erase(i,min(i+2,n));i+=2;continue
        if lang=='csharp' and text.startswith('"""',i) and not (i>0 and text[i-1]=='@'):
            count=len(re.match(r'"{3,}',text[i:]).group());end=text.find('"'*count,i+count)
            if end<0:raise ValueError('unsupported_syntax')
            i=end+count;literals.append((start,i));erase(start,i);continue
        if text[i] in '\"\'`':
            quote=text[i];verbatim=lang=='csharp' and i>0 and text[i-1]=='@'
            if lang=='rust' and quote=="'" and re.match(r"'[A-Za-z_]\w*\b(?!')",text[i:]):i+=1;continue
            i+=1
            while i<n:
                escaped=(text[i]=='\\' and lang!='powershell' and not verbatim and not (lang=='shell' and quote=="'")) or (lang=='powershell' and text[i]=='`' and quote=='"')
                if escaped:i+=2;continue
                if text[i]==quote:
                    if lang in {'sql','powershell','csharp'} and i+1<n and text[i+1]==quote:i+=2;continue
                    break
                i+=1
            if i>=n:raise ValueError('unsupported_syntax')
            i+=1;literals.append((start,i));erase(start,i);continue
        i+=1
    return ''.join(chars),literals


def _pairs(mask):
    pairs={};stack=[]
    for i,c in enumerate(mask):
        if c in '([{':stack.append(i)
        elif c in ')]}':
            if not stack or {'(':')','[':']','{':'}'}[mask[stack[-1]]]!=c:raise ValueError('unsupported_syntax')
            other=stack.pop();pairs[other]=i;pairs[i]=other
    if stack:raise ValueError('unsupported_syntax')
    return pairs


def _calls(mask,pairs):
    calls=[]
    pattern=r'\b([A-Za-z_$][\w$]*(?:(?:::|\?\.|\.|->)[A-Za-z_$][\w$]*)*)\s*(?:<[^;{}\n()]{1,100}>\s*)?\('
    for match in re.finditer(pattern,mask):
        opening=match.end()-1
        if opening not in pairs:continue
        closing=pairs[opening];args=[];start=opening+1;i=start
        while i<closing:
            if mask[i]==',':args.append((start,i));start=i+1;i+=1
            elif i in pairs and pairs[i]>i:i=pairs[i]+1
            else:i+=1
        if start<closing:args.append((start,closing))
        calls.append({'name':match.group(1),'start':match.start(),'end':closing,'args':args})
        if len(calls)>MAX_LOCAL_CALLS:raise ValueError('unsupported_limit')
    return calls


def php_regions(text):
    """Mask HTML outside PHP tags while preserving original coordinates."""
    if not re.search(r'<\?(?:php\b|=)',text,re.I):raise ValueError('unsupported_embedded_content')
    chars=[c if c in '\r\n' else ' ' for c in text];position=0
    while position<len(text):
        match=re.search(r'<\?(?:php\b|=)',text[position:],re.I)
        if not match:break
        start=position+match.end();i=start
        while i<len(text):
            if text.startswith('?>',i):break
            if text.startswith('<<<',i):raise ValueError('unsupported_syntax')
            if text.startswith('/*',i):
                end=text.find('*/',i+2)
                if end<0:raise ValueError('unsupported_syntax')
                i=end+2;continue
            if text.startswith('//',i) or (text[i]=='#' and not text.startswith('#[',i)):
                newline=text.find('\n',i);close=text.find('?>',i)
                if close>=0 and (newline<0 or close<newline):i=close;break
                i=len(text) if newline<0 else newline;continue
            if text[i] in '\"\'`':
                quote=text[i];i+=1
                while i<len(text):
                    if text[i]=='\\':i+=2;continue
                    if text[i]==quote:break
                    i+=1
                if i>=len(text):raise ValueError('unsupported_syntax')
            i+=1
        chars[start:i]=text[start:i];position=i+2
    return ''.join(chars)


def structured_review(text,path,lang,context):
    emitter=Emitter(text,path,lang,context)
    try:
        scoped=php_regions(text) if lang=='php' else text
        mask,literals=mask_source(scoped,lang)
        if len(re.findall(r'\w+|[^\s\w]',mask))>20000:return {'status':'unsupported_limit','signals':[]}
        pairs={} if lang=='shell' else _pairs(mask);calls=[] if lang=='shell' else _calls(mask,pairs)
    except (ValueError,RecursionError) as error:return {'status':str(error) if str(error) in {'unsupported_limit','unsupported_syntax','unsupported_embedded_content'} else 'unsupported_syntax','signals':[]}
    def block(index):
        containers=[(a,b) for a,b in pairs.items() if a<index<b and mask[a]=='{']
        return max(containers,key=lambda x:x[0]) if containers else (0,len(text))
    def expression(span):return text[span[0]:span[1]].strip()
    def same_block(a,b):return block(a)==block(b)
    writes={'csharp':{'File.WriteAllText','File.WriteAllTextAsync','System.IO.File.WriteAllText','System.IO.File.WriteAllTextAsync'},
            'java':{'Files.writeString','Files.write','java.nio.file.Files.writeString'},
            'kotlin':{'Files.writeString','file.writeText'},'php':{'file_put_contents'},'rust':{'std::fs::write','fs::write'}}
    serializers={'csharp':r'\b(?:JsonSerializer\.Serialize|JsonConvert\.SerializeObject)\s*\(',
                 'java':r'\b(?:gson\.toJson|mapper\.writeValueAsString|new\s+Gson)\s*\(',
                 'kotlin':r'\b(?:Json\.encodeToString|json\.encodeToString|gson\.toJson)\s*(?:<[^>]*>)?\(',
                 'php':r'\bjson_encode\s*\(','rust':r'\bserde_json::to_(?:string|vec)(?:_pretty)?\s*\('}
    renames={'File.Move','File.Replace','System.IO.File.Move','System.IO.File.Replace','Files.move','java.nio.file.Files.move','rename','std::fs::rename','fs::rename'}
    for call in calls:
        cname=call['name'];start=call['start'];a,b=block(start);local=mask[a:b]
        is_write=cname in writes.get(lang,set())
        if lang=='rust' and cname=='fs::write' and not re.search(r'\buse\s+std::fs\b',mask):is_write=False
        if lang=='kotlin' and cname=='writeText':
            prefix=mask[max(a,start-300):start]
            is_write=bool(re.search(r'\bFile\s*\([^()]*\)\s*\.\s*$',prefix))
        if is_write and call['args'] and lang in serializers and re.search(serializers[lang],mask[start:call['end']+1]):
            target=expression(call['args'][0]);controls=[]
            for other in calls:
                if other['name'] in renames and other['start']>call['end'] and same_block(start,other['start']) and other['args'] and expression(other['args'][0])==target:
                    if not cname.endswith('Async') or re.search(r'\bawait\s*$',mask[max(a,start-20):start]):controls.append('A later rename/move uses the same written path expression.')
            emitter.emit('AQR-STATE-001','json_publication_control' if controls else 'direct_json_write',start,
                'A qualified write-call spelling receives JSON serialization. Publication intent, sink binding and crash/recovery behavior require characterization.',
                'observed_control' if controls else 'review_candidate',controls)
        if lang in {'csharp','kotlin','java','php','rust'} and re.search(r'(?:Deserialize|decodeFromString|fromJson|readValue|json_decode|serde_json::from_(?:str|slice))$',cname):
            line_start=max(mask.rfind(';',a,start),mask.rfind('\n',a,start),a);prefix=mask[line_start:start]
            installing=bool(re.search(r'\breturn\s*$|\b(?:state|project|document|config)\s*=\s*$',prefix,re.I))
            if installing and call['args']:
                arg=mask[call['args'][0][0]:call['args'][0][1]].strip();prior=mask[a:start]
                guarded=bool(arg and re.search(r'\bif\s*\(\s*!\s*(?:isValid\w*|[Vv]alidate\w*)\s*\(\s*'+re.escape(arg)+r'\s*\)[^{}]*\)\s*\{?\s*(?:throw|return)',prior))
                emitter.emit('AQR-VALID-001','validation_control' if guarded else 'typed_deserialization_boundary',start,
                    'Deserialization-shaped syntax feeds a returned or installed value; domain validation and framework/caller controls remain unresolved.',
                    'observed_control' if guarded else 'source_observation')
        if lang=='rust' and cname in {'std::fs::write','fs::write','serde_json::to_string','serde_json::to_vec','serde_json::from_str','serde_json::from_slice'}:
            tail=mask[call['end']+1:call['end']+100]
            if re.match(r'\s*\?',tail):
                emitter.emit('AQR-ERROR-001','rust_result_propagation',start,
                    'A recognized filesystem/serialization call is followed by the question-mark propagation operator; enclosing Result type, caller handling and complete failure coverage remain unresolved.','observed_control')
        if re.search(r'(?:^|[.:])(?:LogWarning|LogError|warning|error|exception|warn|error_log)$',cname):
            emitter.emit('AQR-ERROR-001','diagnostic_call',start,'A diagnostic/error-call spelling is visible; call binding, privacy and end-to-end failure coverage remain unverified.','observed_control')
        if re.search(r'(?:FromBase64String|base64_decode|decodeBase64|decode)$',cname):
            literal=any(start<x<call['end'] for x,y in literals)
            statement_start=max(mask.rfind(';',a,start),mask.rfind('\n',a,start),a);statement=mask[statement_start:call['end']+1]
            if literal and re.search(r'(?i)\b(?:header|auth\w*|api_?key|token|secret)\b',statement) and re.search(r'\?\?|\?:|\|\||\s-or\s',statement):
                emitter.emit('AQR-CRED-001','encoded_fallback',start,'An auth/header-shaped fallback directly contains encoded-literal decoding syntax; no value is decoded, reconstructed or tested.')
        if re.search(r'(?:^|[.:])(?:claim|claimJob|ClaimJob|takeJob|dequeue|Dequeue)(?:Async)?$',cname) and re.search(r'\bawait\s*$',mask[max(a,start-30):start]):
            # Only a visible enclosing loop and counter name link warrant a candidate.
            for m in re.finditer(r'\bwhile\s*\(([^{};]*)\)\s*\{',mask[:start]):
                opening=m.end()-1
                if pairs.get(opening,0)<start:continue
                names=set(re.findall(r'\b[A-Za-z_]\w*\b',m.group(1)));tail=mask[call['end']+1:pairs[opening]]
                increments=[name for name in names if re.search(r'\b'+re.escape(name)+r'\s*(?:\+\+|\+=)',tail)]
                if increments:
                    emitter.emit('AQR-JOB-001','admission_after_await',start,'A loop counter is incremented after an awaited claim-shaped call; locks, serialization and overlap require characterization.')
                    break
    # Startup syntax is recorded as a fact where framework ownership cannot be resolved.
    startup={'kotlin':r'\b(?:GlobalScope|viewModelScope|lifecycleScope|scope)\.(?:launch|async)\s*(?:\(|\{)',
             'csharp':r'\b(?:Task\.Run|Task\.Factory\.StartNew)\s*\(',
             'rust':r'\b(?:tokio::spawn|std::thread::spawn|thread::spawn)\s*\('}
    if lang in startup:
        for match in re.finditer(startup[lang],mask):
            emitter.emit('AQR-LIFE-001','async_startup_context',match.start(),
                'A recognized task/coroutine/thread startup spelling is visible. Framework scopes, returned owners, cancellation and cleanup remain unresolved.','source_observation')
    if lang=='php':
        for match in re.finditer(r'\b(?:check_ajax_referer|check_admin_referer|wp_verify_nonce|current_user_can|sanitize_text_field|sanitize_email)\s*\(',mask):
            emitter.emit('AQR-VALID-001','wordpress_boundary_api',match.start(),
                'A WordPress nonce, authorization or sanitization API spelling is present; these have different roles and do not establish complete domain validation.','source_observation')
    if lang=='rust':
        for match in re.finditer(r'\.\s*(?:unwrap|expect)\s*\(',mask):
            emitter.emit('AQR-ERROR-001','rust_error_boundary_context',match.start(),
                'An unwrap/expect call spelling is visible; invariant/test intent, concrete result type and reachable panic behavior require review.','source_observation')
    # Bind recovery to the adjacent try body, not arbitrary preceding methods.
    for match in re.finditer(r'\bcatch\b[^{}]*\{',mask):
        opening=match.end()-1;closing=pairs.get(opening)
        previous=match.start()-1
        while previous>=0 and mask[previous].isspace():previous-=1
        try_start=pairs.get(previous)
        if closing is None or try_start is None or not re.search(r'\btry\s*$',mask[max(0,try_start-24):try_start]):continue
        body=mask[opening+1:closing];before=mask[try_start+1:previous]
        if re.search(r'\b(?:Deserialize|decodeFromString|json_decode|fromJson|readValue|JSON\.parse|serde_json::from_str)\b',before) and re.search(r'\breturn\s*(?:\{\s*\}|\[\s*\]|new\s+\w+(?:<[^>]*>)?\s*\(\s*\))',body):
            file_context=bool(re.search(r'\b(?:File\.ReadAll(?:Text|Bytes)|Files\.read\w*|file_get_contents|std::fs::read\w*|fs::read\w*)\s*\(',before))
            emitter.emit('AQR-STATE-001','empty_json_recovery',match.start(),
                'An empty/default return is visible in the catch attached to JSON-reading syntax; storage binding and recovery intent require review.',
                'review_candidate' if file_context else 'source_observation')
    # Bounded local save-revision acknowledgement, without claiming a race.
    if lang in {'csharp','kotlin','java'}:
        for match in re.finditer(r'\bawait\s+[\w.]*[Ss]ave\w*\s*\(',mask):
            a,b=block(match.start());tail=mask[match.end():b]
            saved=next(((x,y) for x,y in literals if match.end()<x<b and re.search(r'(?i)saved',text[x:y]) and re.search(r'(?i)(?:status|state|acknowledg\w*)\s*=\s*$',mask[max(a,x-80):x])),None)
            if saved:
                controlled=bool(re.search(r'\bif\s*\([^)]*(?:revision|version|generation)[^)]*(?:==|!=)[^)]*\)',tail,re.I))
                emitter.emit('AQR-LIFE-001','save_revision_control' if controlled else 'saved_after_await',saved[0],
                    'A saved-status literal follows awaited save syntax; revision ownership, acknowledgement and concurrent edits require characterization.',
                    'observed_control' if controlled else 'review_candidate')
    if lang=='powershell':
        for match in re.finditer(r'\bConvertTo-Json\b[^\n;]*\|\s*(?:Set-Content|Out-File)\b',mask,re.I):
            statement=mask[match.start():mask.find('\n',match.start()) if '\n' in mask[match.start():] else len(mask)]
            emitter.emit('AQR-STATE-001','powershell_json_publication',match.start(),'A JSON conversion pipeline reaches a file-output cmdlet spelling; path binding, encoding and publication/recovery intent require review.', 'source_observation' if any(part in {'deploy','samples'} for part in Path(path).parts[:-1]) else 'review_candidate')
        for match in re.finditer(r'\b(Start-Job|Start-ThreadJob|Start-Process)\b',mask,re.I):
            line_end=mask.find('\n',match.end());line_end=len(mask) if line_end<0 else line_end
            statement=mask[match.start():line_end];prefix=mask[max(0,mask.rfind('\n',0,match.start())):match.start()]
            process=match.group(1).lower()=='start-process';controls=[]
            binding=re.search(r'(\$(?:(?:script|global|local):)?[A-Za-z_]\w*)\s*=\s*$',prefix,re.I)
            if process and re.search(r'(?:^|\s)-Wait(?:\s|$)',statement,re.I):controls.append('The same Start-Process command includes -Wait.')
            if process and binding:
                a,b=block(match.start());tail=mask[match.end():b];name=re.escape(binding.group(1))
                rebound=re.search(name+r'\s*=',tail,re.I)
                if rebound:tail=tail[:rebound.start()]
                linked=re.search(name+r'\s*\.\s*(?:WaitForExit|Kill|CloseMainWindow)\s*\(',tail,re.I)
                if linked:controls.append('A wait/termination-shaped method is visible on the same local process binding; exit coverage remains unresolved.')
            other=bool(re.search(r'\b(?:Wait-Job|Stop-Job|Remove-Job)\b',mask[match.end():],re.I)) if not process else False
            emitter.emit('AQR-LIFE-001','powershell_process_controls' if controls else 'powershell_process_context' if process else 'powershell_job_controls' if other else 'powershell_job_ownership',match.start(),
                'Process/job startup syntax is present; independent launch intent, retained handles and complete lifetime coverage require review.',
                'observed_control' if controls else 'source_observation' if process or other else 'review_candidate',controls)
        for match in re.finditer(r'\b(?:Write-Error|Write-Warning|throw)\b',mask,re.I):emitter.emit('AQR-ERROR-001','powershell_error_path',match.start(),'An explicit diagnostic/error propagation spelling is visible; error-mode configuration and actual handling remain unverified.','observed_control')
    if lang=='shell':
        for match in re.finditer(r'(?m)^\s*trap\b',mask):emitter.emit('AQR-LIFE-001','shell_cleanup_trap',match.start(),'A shell trap declaration is present; its body, signals, resource binding and exit coverage remain unresolved.','source_observation')
        for match in re.finditer(r'(?m)^\s*(?:jq|python[23]?)\b[^\n]*>[^\n]*',mask):
            emitter.emit('AQR-STATE-001','shell_generated_file_output',match.start(),'A supported tool-call spelling redirects output; whether this is JSON or persistent state remains unresolved.','source_observation')
        if re.search(r'(?m)^\s*set\s+-[A-Za-z]*e',mask):emitter.emit('AQR-ERROR-001','shell_error_mode',re.search(r'(?m)^\s*set\s+-[A-Za-z]*e',mask).start(),'An errexit-shaped option is declared; shell exception contexts and actual command outcomes are not proven.','source_observation')
    interpolation=lang=='csharp' and bool(re.search(r'\$(?:@)?"|@\$"',text))
    limited=lang=='shell' or interpolation or len(emitter.signals)>=MAX_SIGNALS
    return {'status':'assessed_limited' if limited else 'assessed','signals':emitter.signals,**({'diagnostics':['shell_case_substitution_and_full_grammar_unassessed']} if lang=='shell' else {'diagnostics':['csharp_interpolation_code_unassessed']} if interpolation else {})}


def sql_review(text,path,context):
    context=dict(context or {});name=path.lower()
    sql_role=next((role for pattern,role in [(r'dump|backup','dump_or_backup'),(r'reset|teach|practice|example|fixture|test','teaching_or_reset'),(r'seed','seed'),(r'migrat','migration'),(r'schema','schema'),(r'quer','application_query')] if re.search(pattern,name)),'unknown')
    context['sql_role']=sql_role;context.setdefault('sql_dialect','unknown')
    emitter=Emitter(text,path,'sql',context)
    try:mask,_=mask_source(text,'sql')
    except ValueError:return {'status':'unsupported_syntax','signals':[]}
    dialect=(context or {}).get('sql_dialect','unknown');role=(context or {}).get('role','unknown')
    for m in re.finditer(r'(?im)(?:^|;)\s*(BEGIN(?:\s+TRANSACTION)?|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b',mask):
        emitter.emit('AQR-SQL-001','transaction_syntax',m.start(1),'Transaction-control syntax is present; dialect, implicit transactions, binding and runtime atomicity remain unverified.','observed_control')
    for m in re.finditer(r'(?im)(?:^|;)\s*(DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE(?:\s+TABLE)?)\b',mask):
        reset=bool(re.search(r'(?i)(?:reset|seed|demo|fixture|example|test)',path)) or role in {'tests','fixture','tooling'}
        emitter.emit('AQR-SQL-001','destructive_statement_context',m.start(1),
            'Explicit schema/reset syntax is present. Teaching, disposable/reset and production-migration intent must be distinguished; no unsafe execution or data loss is established.',
            'review_candidate' if not reset and dialect!='unknown' and sql_role=='migration' and role in {'production','source'} else 'source_observation')
    return {'status':'assessed_limited' if dialect=='unknown' or len(emitter.signals)>=MAX_SIGNALS else 'assessed','signals':emitter.signals,
            'diagnostics':['unknown_sql_dialect_common_syntax_only'] if dialect=='unknown' else []}


def markup_review(text,path,lang,context):
    """Analyze bounded script regions with original Unicode positions/digests."""
    from .review import _review_source
    emitter=Emitter(text,path,lang,context);segments=[];diagnostics=[]
    if lang=='html':
        from html.parser import HTMLParser
        class Scripts(HTMLParser):
            def __init__(self):super().__init__(convert_charrefs=False);self.active=None
            def source_offset(self):
                line,col=self.getpos();return sum(len(x) for x in text.splitlines(keepends=True)[:line-1])+col
            def handle_starttag(self,tag,attrs):
                if tag!='script':return
                attrs=dict(attrs);kind=attrs.get('type','').lower()
                if 'src' in attrs:diagnostics.append('external_script_not_followed');return
                if kind not in {'','module','text/javascript','application/javascript','text/typescript'}:diagnostics.append('non_javascript_script_excluded');return
                self.active=self.source_offset()+len(self.get_starttag_text())
            def handle_endtag(self,tag):
                if tag=='script' and self.active is not None:segments.append((self.active,self.source_offset()));self.active=None
        parser=Scripts()
        try:parser.feed(text);parser.close()
        except (ValueError,RecursionError):return {'status':'unsupported_syntax','signals':[]}
        if parser.active is not None:return {'status':'unsupported_syntax','signals':[]}
        if len(segments)>64:return {'status':'unsupported_limit','signals':[]}
        if not segments:return {'status':'unsupported_embedded_content','signals':[],'diagnostics':diagnostics+['no_supported_inline_scripts']}
        diagnostics.append('html_handlers_templates_and_external_scripts_unassessed')
    else:
        from .markup import prepare_jsx
        try:prepared,jsx_diagnostics=prepare_jsx(text)
        except ValueError as error:return {'status':str(error),'signals':[]}
        segments=[(0,len(text))];diagnostics.extend(jsx_diagnostics)
    statuses=[]
    for start,end in segments:
        # Whitespace prefix preserves original line/column coordinates.
        prefix=''.join(c if c in '\r\n' else ' ' for c in text[:start])
        fragment=(prepared if lang!='html' else prefix+text[start:end])
        result=_review_source(fragment,'embedded.ts',apply_exclusions=False);statuses.append(result['status'])
        for signal in result['signals']:
            loc=signal['locations'][0];lines=text.splitlines(keepends=True)
            index=sum(len(x) for x in lines[:loc['line']-1])+loc['column']-1
            count_before=len(emitter.signals)
            emitter.emit(signal['check_id'],signal['variant'],index,signal['observed_fact'],signal['kind'],signal['observed_controls'])
            if len(emitter.signals)==count_before:continue
            emitter.signals[-1]['source_ids']=sorted(set(signal['source_ids']+SOURCES[lang]))
            emitter.signals[-1]['segment_digest']=hashlib.sha256(text[start:end].encode()).hexdigest()
    status='assessed_limited' if len(emitter.signals)>=MAX_SIGNALS or any(s!='assessed' for s in statuses) or lang=='html' or 'template_interpolation_unassessed' in diagnostics else 'assessed'
    if not any(s.startswith('assessed') for s in statuses):status=statuses[0]
    return {'status':status,'signals':emitter.signals,'diagnostics':diagnostics}


def analyze_source(text,path,context=None):
    if Path(path).is_absolute() or '..' in Path(path).parts or '\\' in str(path) or '\x00' in str(path):return {'status':'unsupported_path','signals':[]}
    lang=language(path,text)
    if not lang:return {'status':'unsupported_language','signals':[]}
    if len(text.encode('utf8'))>MAX_SOURCE_BYTES:return {'status':'unsupported_limit','signals':[]}
    try:
        if lang in {'javascript','typescript'}:
            from .review import _review_source
            result=_review_source(text,path,apply_exclusions=False)
            for signal in result['signals']:
                signal['language']=lang;signal['applicability']={'role':(context or {}).get('role','unknown'),'owner':(context or {}).get('owner','root'),'intent_verified':False}
                if signal['check_id']=='AQR-STATE-001' and signal['kind']=='review_candidate' and (context or {}).get('role') in {'tooling','tests','docs','fixture'}:signal['kind']='source_observation'
            return result
        if lang in {'jsx','tsx','html'}:return markup_review(text,path,lang,context)
        if lang=='python':return python_review(text,path,context)
        if lang=='sql':return sql_review(text,path,context)
        if lang=='swift':
            from .swift_review import swift_review
            return swift_review(text,path,context)
        return structured_review(text,path,lang,context)
    except (IndexError,KeyError,SyntaxError):return {'status':'unsupported_syntax','signals':[]}
    except (ValueError,RecursionError,OverflowError):return {'status':'unsupported_limit','signals':[]}
