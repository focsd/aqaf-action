"""Passive Swift lexical/source facts. No compiler, imports or macro expansion."""
import re
from .adapters import Emitter,_pairs,MAX_SIGNALS


def mask_swift(text):
    chars=list(text);n=len(text);i=0;diagnostics=set()
    def erase(a,b):
        for k in range(a,b):
            if chars[k] not in '\r\n':chars[k]=' '
    def comment(pos):
        level=1;pos+=2
        while pos<n and level:
            if text.startswith('/*',pos):level+=1;pos+=2
            elif text.startswith('*/',pos):level-=1;pos+=2
            else:pos+=1
            if level>64:raise ValueError('unsupported_limit')
        if level:raise ValueError('unsupported_syntax')
        return pos
    def interpolation(pos,depth):
        level=1
        while pos<n:
            if text.startswith('/*',pos):pos=comment(pos);continue
            if text.startswith('//',pos):
                end=text.find('\n',pos);pos=n if end<0 else end;continue
            m=re.match(r'(#{0,16})("""|")',text[pos:])
            if m:pos=string(pos,m,depth+1);continue
            if text[pos]=='(':level+=1
            elif text[pos]==')':
                level-=1
                if not level:return pos+1
            pos+=1
        raise ValueError('unsupported_syntax')
    def string(pos,match,depth):
        if depth>64:raise ValueError('unsupported_limit')
        hashes,quote=match.groups();end_delimiter=quote+hashes;escape='\\'+hashes;pos+=len(match.group())
        while pos<n:
            if text.startswith(escape+'(',pos):
                diagnostics.add('swift_string_interpolation_unassessed');pos=interpolation(pos+len(escape)+1,depth);continue
            if text.startswith(escape,pos):pos+=len(escape)+1;continue
            if text.startswith(end_delimiter,pos):return pos+len(end_delimiter)
            if len(quote)==1 and text[pos] in '\r\n':raise ValueError('unsupported_syntax')
            pos+=1
        raise ValueError('unsupported_syntax')
    while i<n:
        start=i
        if text.startswith('//',i):
            end=text.find('\n',i);i=n if end<0 else end;erase(start,i);continue
        if text.startswith('/*',i):i=comment(i);erase(start,i);continue
        match=re.match(r'(#{0,16})("""|")',text[i:]) if text[i] in '#"' else None
        if match:i=string(i,match,0);erase(start,i);continue
        if text.startswith('#/',i):raise ValueError('unsupported_syntax')
        if text[i]=='/' and re.search(r'(?:^|[=(:,]|\breturn)\s*$',text[:i]):raise ValueError('unsupported_syntax')
        i+=1
    return ''.join(chars),sorted(diagnostics)


def swift_review(text,path,context):
    emitter=Emitter(text,path,'swift',context)
    try:
        mask,diagnostics=mask_swift(text);pairs=_pairs(mask)
        if len(re.findall(r'\w+|[^\s\w]',mask))>20000:return {'status':'unsupported_limit','signals':[]}
    except ValueError as error:return {'status':str(error),'signals':[]}
    def block(index):
        candidates=[(a,b) for a,b in pairs.items() if a<index<b and mask[a]=='{']
        return max(candidates,key=lambda p:p[0]) if candidates else (0,len(text))
    def shadowed(name):return bool(re.search(r'\b(?:class|struct|enum|typealias|func)\s+'+name+r'\b',mask))
    imported=bool(re.search(r'\bimport\s+(?:Foundation|Cocoa|AppKit|SwiftUI)\b',mask))
    if imported:
        for match in re.finditer(r'\b(?:Foundation\.)?Process\s*\(\s*\)',mask):
            if not match.group().startswith('Foundation.') and shadowed('Process'):continue
            a,b=block(match.start());prefix=mask[a:match.start()]
            binding=re.search(r'\b(?:let|var)\s+([A-Za-z_]\w*)\s*(?::\s*(?:Foundation\.)?Process\??\s*)?=\s*$',prefix)
            controls=[]
            if binding:
                name=re.escape(binding.group(1))
                for control in re.finditer(r'\b'+name+r'\s*(?:\?\.|\.)\s*(terminationHandler\s*=|waitUntilExit\s*\(|terminate\s*\()',mask[match.end():b]):
                    index=match.end()+control.start()
                    if block(index)==(a,b):controls.append('A '+control.group(1).split('(')[0].strip(' =')+' spelling is visible on the same local binding.')
            emitter.emit('AQR-LIFE-001','swift_process_controls' if controls else 'swift_process_context',match.start(),
                'Foundation Process construction syntax is present; launch intent, transferred ownership, execution and complete cleanup remain unresolved.',
                'observed_control' if controls else 'source_observation',controls)
        for match in re.finditer(r'\bJSONDecoder(?:\s*\(\s*\)|\.[A-Za-z_]\w*)\s*\.\s*decode\s*\(',mask):
            if shadowed('JSONDecoder'):continue
            emitter.emit('AQR-VALID-001','swift_decoding_context',match.start(),
                'JSONDecoder-shaped decoding syntax is present; Decodable typing does not establish complete domain validation or an unsafe input boundary.','source_observation')
        for match in re.finditer(r'\b([A-Za-z_]\w*)\s*\.\s*write\s*\(\s*to\s*:',mask):
            opening=mask.find('(',match.start());closing=pairs.get(opening)
            if closing is None:continue
            arguments=mask[opening:closing+1];atomic=bool(re.search(r'\boptions\s*:[^)]*\.atomic\b',arguments))
            emitter.emit('AQR-STATE-001','swift_atomic_option' if atomic else 'swift_write_context',match.start(),
                'A write(to:) spelling is present; receiver type, persistent-state intent and caller/framework publication controls require review.',
                'observed_control' if atomic else 'source_observation',
                ['An .atomic option spelling is visible; filesystem semantics and full durability are not established.'] if atomic else [])
    if not shadowed('Task'):
        for match in re.finditer(r'\bTask(?:\s*\.\s*detached)?\s*(?:\([^{}\n]*\))?\s*\{',mask):
            emitter.emit('AQR-LIFE-001','swift_task_context',match.start(),
                'Task startup syntax is present; actor inheritance, captured state, retained handles, cooperative cancellation and all exit paths remain unresolved.','source_observation')
    return {'status':'assessed_limited','signals':emitter.signals,'diagnostics':diagnostics+['swift_bounded_source_facts_not_compiler_type_or_actor_analysis']}
