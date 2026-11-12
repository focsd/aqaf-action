"""Separate unscored documentation observations; no target execution or certification."""
from __future__ import annotations
import ast
import hashlib
import re
import unicodedata
from pathlib import Path,PurePosixPath
from urllib.parse import unquote,urlsplit
from .scope import Scope


def markdown_body(text):
    """Remove fenced/indented samples, comments and inline code before link parsing."""
    lines=[];fence=None
    for line in text.splitlines():
        m=re.match(r'^ {0,3}(`{3,}|~{3,})',line)
        if m:
            token=m.group(1)
            if fence is None:fence=token
            elif token[0]==fence[0] and len(token)>=len(fence):fence=None
            lines.append('');continue
        lines.append('' if fence or line.startswith(('    ','\t')) else line)
    return re.sub(r'<!--[\s\S]*?-->|(`+).*?\1','', '\n'.join(lines))


def links(text):
    body=markdown_body(text);refs={}
    for m in re.finditer(r'(?m)^ {0,3}\[([^]\n]+)\]:\s*<?([^\s>]+)>?',body):refs[m.group(1).casefold()]=m.group(2)
    body=re.sub(r'(?m)^ {0,3}\[[^]\n]+\]:[^\n]*','',body)
    found=[]
    # Bounded balanced parentheses allow ordinary paths containing parentheses.
    for m in re.finditer(r'!?\[([^]\n]*)\]\(\s*(<[^>\n]+>|(?:[^\s()\\]|\\.|\([^()\n]*\)){1,2048})(?:\s+["\'][^\n]*?["\'])?\s*\)',body):
        found.append((m.group(2).strip('<>'),body.count('\n',0,m.start())+1))
    for m in re.finditer(r'!?\[([^]\n]+)\](?:\[([^]\n]*)\])?(?![(:])',body):
        key=(m.group(2) or m.group(1)).casefold()
        if key in refs:found.append((refs[key],body.count('\n',0,m.start())+1))
    return sorted(set(found),key=lambda x:(x[1],x[0]))


def anchors(text):
    result=set();counts={}
    for line in markdown_body(text).splitlines():
        m=re.match(r'^ {0,3}#{1,6}\s+(.+?)\s*#*$',line)
        if not m:continue
        label=re.sub(r'[^\w\- ]','',m.group(1).lower()).replace(' ','-')
        n=counts.get(label,0);counts[label]=n+1;result.add(label+('-'+str(n) if n else ''))
    result.update(re.findall(r'\bid=["\']([^"\']+)',text))
    return result


def documented_default(node,flag):
    """Only JSON scalars; never return credential-shaped literal metadata."""
    import math
    if not isinstance(node,ast.Constant):return None,'unknown'
    value=node.value
    if type(value) not in {str,int,float,bool,type(None)} or (type(value) is float and not math.isfinite(value)):
        return None,'unknown'
    sensitive_name=re.search(r'password|passphrase|secret|token|key|credential|auth',flag,re.I)
    sensitive_value=isinstance(value,str) and re.search(r'://[^/\s]+@|(?:api[_-]?key|token|password|secret)=[^&\s]+|^Bearer\s+\S+|^(?:sk-|gh[pousr]_|xox[baprs]-|AKIA)',value,re.I)
    if value is not None and (sensitive_name or sensitive_value):return '[redacted]','redacted'
    return value,'observed'


def interfaces(scope):
    facts=[];unknown=[];read_bytes=0;attempted=0
    for r in scope.selected({'production','source','unknown','tooling'}):
        if r['language']=='other' and r['path'].suffix not in {'.json','.service','.plist'}:continue
        if attempted>=1000 or read_bytes>=16000000:
            unknown.append({'reason':'interface_budget','remaining_coverage':'unknown'});break
        attempted+=1
        raw=scope.raw(r['path'],min(131072,16000000-read_bytes));read_bytes+=len(raw);text=raw.decode('utf8','replace');sha=hashlib.sha256(raw).hexdigest()
        base={'path':r['relative'],'sha256':sha,'runtime_verified':False}
        if r['language']=='python':
            try:tree=ast.parse(text)
            except (SyntaxError,ValueError,RecursionError):unknown.append({**base,'reason':'python_syntax_or_truncated'});continue
            for node in ast.walk(tree):
                if not isinstance(node,ast.Call):continue
                name=node.func.attr if isinstance(node.func,ast.Attribute) else ''
                if name=='add_argument':
                    flags=[a.value for a in node.args if isinstance(a,ast.Constant) and isinstance(a.value,str) and a.value.startswith('--')]
                    default_node=next((k.value for k in node.keywords if k.arg=='default'),None)
                    for flag in flags:
                        default,default_state=documented_default(default_node,flag)
                        facts.append({**base,'kind':'cli_flag','name':flag,'default':default,'default_state':default_state,'line':node.lineno,'state':'observed'})
                    if not flags:unknown.append({**base,'reason':'dynamic_cli_registration','line':node.lineno})
                if name in {'get','post','put','patch','delete','route'} and node.args and isinstance(node.args[0],ast.Constant) and isinstance(node.args[0].value,str) and node.args[0].value.startswith('/'):
                    facts.append({**base,'kind':'route_candidate','name':node.args[0].value,'method':name.upper(),'line':node.lineno,'state':'inferred'})
        elif r['language'] in {'javascript','typescript','shell','powershell','cmd'}:
            from .adapters import mask_source
            try:view=mask_source(text,r['language'])[0] if r['language']!='cmd' else text
            except (ValueError,RecursionError):
                unknown.append({**base,'reason':'unsupported_or_truncated_syntax'});continue
            if r['language'] in {'shell','powershell'}:
                for i,line in enumerate(text.splitlines(),1):
                    visible=view.splitlines()[i-1] if i<=len(view.splitlines()) else ''
                    if not re.match(r'^\s*(?:exec\s+)?(?:python[23]?|node|pwsh)\s+',visible):continue
                    m=re.match(r'^\s*(?:exec\s+)?(python[23]?|node|pwsh)\s+([\w./\\-]+)',line)
                    if m:facts.append({**base,'kind':'launcher','name':m.group(1),'target':m.group(2),'line':i,'state':'observed','syntax_scope':'literal_launcher_only'})
            if r['language']=='cmd':
                for i,line in enumerate(text.splitlines(),1):
                    if re.match(r'(?i)^\s*@?(?:rem\b|::)',line):continue
                    m=re.match(r'(?i)^\s*@?(?:call\s+)?(python(?:3|\.exe)?|node(?:\.exe)?|powershell(?:\.exe)?|pwsh|java(?:\.exe)?)\s+([\w./\\-]+)',line)
                    if m:facts.append({**base,'kind':'launcher','name':m.group(1),'target':m.group(2),'line':i,'state':'observed','syntax_scope':'literal_cmd_launcher_only'})
            # String-bearing registration requires a call spelling outside strings/comments.
            for m in re.finditer(r'\.(option|command|get|post|put|delete)\s*\(',view):
                tail=text[m.end():m.end()+512];literal=re.match(r'\s*["\']([^"\'\n]{1,256})["\']',tail)
                if literal:
                    value=literal.group(1);kind='cli_flag' if m.group(1)=='option' else 'route_candidate'
                    if kind=='cli_flag' and not value.startswith('-'):continue
                    facts.append({**base,'kind':kind,'name':value.split()[0],'default':None,'state':'inferred','line':text.count('\n',0,m.start())+1})
                else:unknown.append({**base,'reason':'dynamic_registration'})
        if r['path'].suffix in {'.service','.plist'}:facts.append({**base,'kind':'service_definition','name':r['path'].name,'state':'observed'})
        if re.search(r'\b(?:getenv|environ|process\.env)\b',text):unknown.append({**base,'reason':'environment_precedence_requires_review'})
    return facts,unknown

EXPECTATIONS={
 'desktop_ui':('end_user','install|installation','state|storage','reset|troubleshoot'),
 'desktop_widget':('end_user','install|installation','state|storage|reset'),
 'windows_service':('administrator','privilege|administrator|account','pair|trust|permission'),
 'browser_python':('learner','worker|stop|cancel','offline|asset|download'),
 'proxy':('operator','auth|token|access','stream','retention|logging'),
 'backup':('operator','restore|recovery','dry.run|preview|verify'),
 'ocr':('reviewer','evidence|confidence|manual.review','provenance|original|source'),
 'pdf_mapping':('content_author','page|mapping','provenance|source|chapter'),
 'apps_script':('administrator','permission|scope|oauth','deploy|installation'),
 'ide_extension':('developer','install|plugin','model|endpoint|privacy')}


def check(root,scope=None,generated_routes=(),audience=None):
    owned=scope is None;scope=scope or Scope(root).build();root=scope.root
    try:
        all_docs=[r for r in scope.records if r['path'].suffix.lower() in {'.md','.markdown'}]
        docs=all_docs[:2048];budget=16000000;doc_partial=len(docs)<len(all_docs)
        texts={};hashes={};seen={};duplicates=0;evidence=[];findings=[];finding_keys={}
        for r in docs:
            if budget<=0:doc_partial=True;break
            raw=scope.raw(r['path'],min(262144,budget));budget-=len(raw)
            if len(raw)!=r['size']:doc_partial=True
            sha=hashlib.sha256(raw).hexdigest();texts[r['relative']]=raw.decode('utf8','replace')
            hashes[r['relative']]={'sha256':sha,'bytes':len(raw),'complete_file':len(raw)==r['size']}
            evidence.append({'path':r['relative'],**hashes[r['relative']],'kind':'documentation','audience':audience or 'unknown'})
            if sha in seen:duplicates+=1
            seen[sha]=r['relative']
        def issue(rule,state,r,message,action,**extra):
            h=hashes.get(r['relative'])
            if h is None:
                raw=scope.raw(r['path'],131072);h={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'complete_file':len(raw)==r['size']}
            key=(rule,state,h['sha256'],extra.get('target',extra.get('name',action)))
            if key in finding_keys:
                finding_keys[key].setdefault('copied_occurrences',[]).append(r['relative']);return
            item={'rule_id':rule,'state':state,'path':r['relative'],**h,
                'audience':audience or 'maintainer','consequence':message,'action':action,'priority':'medium' if state=='observed' else 'low',
                'confirmed':False,'runtime_verified':False,**extra}
            findings.append(item);finding_keys[key]=item
        selected={x['relative'] for x in scope.records}
        for r in docs:
            if r['relative'] not in texts:continue
            text=texts[r['relative']]
            for target,line in links(text):
                if re.match(r'^[a-z][a-z0-9+.-]*:',target,re.I) or target.startswith('//'):continue
                parsed=urlsplit(target);link=unquote(parsed.path);fragment=unquote(parsed.fragment)
                if link.startswith('/'):
                    if link not in generated_routes:issue('AQD-LINK-003','unknown',r,'Root-relative route has no configured resolution.','Configure the generated route or verify it separately.',target=target,line=line)
                    continue
                candidate=r['path'].parent/link if link else r['path']
                candidate=candidate.resolve()
                try:rel=candidate.relative_to(root).as_posix()
                except ValueError:
                    issue('AQD-LINK-003','unknown',r,'Link leaves the selected root.','Verify the external local dependency separately.',target=target,line=line);continue
                if rel not in selected and not candidate.is_dir():
                    portable=[n for n in selected if unicodedata.normalize('NFC',n).casefold()==unicodedata.normalize('NFC',rel).casefold()]
                    if portable:issue('AQD-LINK-002','observed',r,'Link differs in case or Unicode normalization.','Use the exact portable path spelling.',target=target,line=line)
                    else:issue('AQD-LINK-001','observed' if not candidate.exists() else 'unknown',r,'Local link target is missing or outside selected scope.','Repair the link or declare its generated/excluded target.',target=target,line=line)
                elif fragment and candidate in scope.by_path:
                    if rel not in texts:
                        issue('AQD-LINK-003','unknown',r,'Anchor target is outside the documentation read budget or supported Markdown scope.','Verify this fragment separately.',target=target,line=line)
                    elif fragment not in anchors(texts[rel]):issue('AQD-LINK-004','inferred',r,'Heading anchor does not match the supported Markdown convention.','Verify renderer anchor rules and correct the fragment.',target=target,line=line)
        interface,unknown=interfaces(scope)
        canonical='\n'.join(t for p,t in texts.items() if not re.search(r'(?i)changelog|release.notes|history',p))
        documented=set(re.findall(r'--[a-zA-Z][a-zA-Z0-9_-]*',canonical));known={x['name'] for x in interface if x['kind']=='cli_flag'}
        for fact in interface:
            if fact['kind']=='route_candidate' and fact['name'] not in canonical:
                issue('AQD-API-001','inferred',scope.record(root/fact['path']),'A static route-shaped registration has no selected documentation mention.','Check whether this is an exposed route and document its method/authentication contract.',name=fact['name'])
            if fact['kind']=='cli_flag' and fact['name'] not in documented:
                r=scope.record(root/fact['path']);issue('AQD-CLI-001','inferred',r,'A static CLI flag is absent from selected current documentation.','Document this flag if it is public.',name=fact['name'])
            if fact['kind']=='cli_flag' and fact.get('default') is not None and fact['default']!='[redacted]':
                for line in canonical.splitlines():
                    if fact['name'] in line:
                        m=re.search(r'default\s*[:=]\s*[`"\']?([\w./-]+)',line,re.I)
                        if m and m.group(1)!=str(fact['default']):
                            issue('AQD-CLI-002','inferred',scope.record(root/fact['path']),'Documented default differs from a static literal.','Check precedence and update the public default.',name=fact['name']);break
        for flag in sorted(documented-known):
            if docs:issue('AQD-CLI-003','unknown',docs[0],'Documented flag was not found in supported static registrations.','Check rename, external command or dynamic registration.',name=flag)
        from .facets import facets
        capabilities=facets(scope)
        present={x['facet'] for x in capabilities['facts']}
        for facet,(reader,*patterns) in EXPECTATIONS.items():
            if facet not in present:continue
            for pattern in patterns:
                if audience and audience!=reader:continue
                if not re.search(pattern,canonical,re.I) and scope.records:
                    issue('AQD-PRODUCT-001','inferred',scope.records[0],'Product evidence suggests an undocumented reader need: '+facet+'.','Review and document '+pattern+' for '+reader+'.',product_facet=facet,reader=reader)
        for index,item in enumerate(findings):item['id']='doc-'+hashlib.sha256((item['rule_id']+item['path']+str(item.get('target',item.get('name',item['action'])))).encode()).hexdigest()[:20]
        return {'schema_version':1,'kind':'aqaf_documentation_review','root':str(root),'status':'partial' if doc_partial or not scope.selection_complete() or any(x.get('reason') in {'interface_budget','unsupported_or_truncated_syntax','python_syntax_or_truncated'} for x in unknown) else 'complete_within_static_scope',
            'score_effect':'none','certification':False,'coverage':{'documents_selected':len(all_docs),'documents_read':len(texts),'max_documents':2048,'max_document_bytes':16000000,'max_document_file_bytes':262144},'documents':evidence,'duplicate_documents':duplicates,'interfaces':interface,'interface_unknowns':unknown,
            'capabilities':capabilities,'findings':findings,'backlog':[{'id':f['id'],'action':f['action'],'evidence':{'path':f['path'],'sha256':f['sha256']},'state':f['state'],'priority':f['priority']} for f in findings],
            'applicability':[{'facet':facet,'reader':reader,'state':'not_applicable' if audience and audience!=reader else 'inferred' if facet in present else 'unknown'} for facet,(reader,*_) in EXPECTATIONS.items()],
            'scope':scope.report(),'limitations':['Static bounded registrations only; dynamic interfaces and runtime claims require verification.','Document presence and term matches do not establish correctness or readability.','Renderer-specific anchors and complex Markdown remain reviewable unknowns.']}
    finally:
        if owned:scope.cache.close()
