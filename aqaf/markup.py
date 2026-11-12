"""Position-preserving bounded JSX extraction, never a JSX/TypeScript compiler."""
import re


def prepare_jsx(text):
    chars=list(text);length=len(text);diagnostics=set();budget=[length*5+100]
    def step():
        budget[0]-=1
        if budget[0]<0:raise ValueError('unsupported_limit')
    def erase(a,b):
        for k in range(a,b):
            if chars[k] not in '\r\n':chars[k]=' '
    def quoted(i):
        quote=text[i];start=i;i+=1
        while i<length:
            step()
            if text[i]=='\\':i+=2;continue
            if text[i]==quote:
                if quote=='`' and '${' in text[start:i]:diagnostics.add('template_interpolation_unassessed')
                return i+1
            i+=1
        raise ValueError('unsupported_syntax')
    def tag(i,depth):
        start=i;closing=text.startswith('</',i);i+=2 if closing else 1
        match=re.match(r'[A-Za-z][\w.:-]*',text[i:]);name=match.group() if match else ''
        if not name and (i>=length or text[i]!='>'):raise ValueError('unsupported_syntax')
        end_name=i+len(name);erase(start,end_name);i=end_name
        while i<length:
            step()
            if text.startswith('/>',i):erase(i,i+2);return i+2,name,True,closing
            if text[i]=='>':erase(i,i+1);return i+1,name,False,closing
            if text[i]=='<':raise ValueError('unsupported_syntax')  # Generic component type arguments remain unresolved.
            if text[i] in '\"\'':
                end=quoted(i);erase(i,end);i=end;continue
            if text[i]=='{' and not closing:
                i=code(i+1,True,depth+1);continue
            if closing and not text[i].isspace():raise ValueError('unsupported_syntax')
            erase(i,i+1);i+=1
        raise ValueError('unsupported_syntax')
    def element(i,depth):
        if depth>64:raise ValueError('unsupported_limit')
        i,name,self_closing,closing=tag(i,depth)
        if closing:raise ValueError('unsupported_syntax')
        if self_closing:return i
        while i<length:
            step()
            if text.startswith('</',i):
                i,other,_,closing=tag(i,depth)
                if not closing or other!=name:raise ValueError('unsupported_syntax')
                return i
            if text[i]=='<':i=element(i,depth+1)
            elif text[i]=='{':i=code(i+1,True,depth+1)
            else:erase(i,i+1);i+=1
        raise ValueError('unsupported_syntax')
    def code(i,expression,depth):
        if depth>64:raise ValueError('unsupported_limit')
        braces=0
        while i<length:
            step();c=text[i]
            if text.startswith('//',i):
                end=text.find('\n',i);i=length if end<0 else end;continue
            if text.startswith('/*',i):
                end=text.find('*/',i+2)
                if end<0:raise ValueError('unsupported_syntax')
                i=end+2;continue
            if c in '\"\'`':i=quoted(i);continue
            if c=='<':
                previous=text[:i].rstrip();last=previous[-1:] or '='
                word=re.search(r'(\w+)\s*$',previous)
                allowed=(last in '=([{,:;?!' or previous.endswith('=>') or (word and word.group(1) in {'return','yield'}))
                if allowed and (text.startswith('<>',i) or re.match(r'<[A-Za-z]',text[i:])):
                    i=element(i,depth+1);continue
            if c=='/' and not text.startswith(('/=','//','/*'),i):
                previous=text[:i].rstrip();word=re.search(r'(\w+)\s*$',previous)
                if not previous or previous[-1:] in '=([{,:;!?' or previous.endswith('=>') or (word and word.group(1)=='return'):
                    j=i+1;inside=False
                    while j<length:
                        step()
                        if text[j]=='\\':j+=2;continue
                        if text[j]=='[':inside=True
                        elif text[j]==']':inside=False
                        elif text[j]=='/' and not inside:break
                        elif text[j]=='\n':raise ValueError('unsupported_syntax')
                        j+=1
                    if j>=length:raise ValueError('unsupported_syntax')
                    i=j+1;continue
            if c=='{':braces+=1
            elif c=='}':
                if expression and braces==0:return i+1
                braces-=1
                if braces<0:raise ValueError('unsupported_syntax')
            i+=1
        if expression or braces:raise ValueError('unsupported_syntax')
        return i
    code(0,False,0)
    return ''.join(chars),sorted(diagnostics|{'jsx_text_and_tags_masked_expression_code_preserved'})
