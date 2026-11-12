"""Bounded .gitignore matching without Git, shell execution, or index access.

Patterns apply to scanned files regardless of tracked status. Only ignore files
inside the authorized root are loaded; global Git config is never consulted.
"""
from __future__ import annotations
from dataclasses import dataclass
import fnmatch
import hashlib
from pathlib import PurePosixPath

MAX_IGNORE_BYTES = 131072
MAX_RULES = 4096
MAX_PATTERN = 512


def _unescape(pattern):
    out=[];i=0
    while i<len(pattern):
        if pattern[i]=='\\' and i+1<len(pattern):
            i+=1;c=pattern[i];out.append({'*':'[*]','?':'[?]','[':'[[]'}.get(c,c))
        elif pattern.startswith('[^',i):
            # Git accepts both ! and ^ to negate a character class.
            out.append('[!');i+=2;continue
        else:out.append(pattern[i])
        i+=1
    return ''.join(out)


def _components_match(pattern, parts):
    # DP rather than a recursive/backtracking ** regex over an entire path.
    states={0}
    for index,component in enumerate(pattern):
        next_states=set()
        for pos in states:
            if component=='**':
                # A trailing '/**' matches descendants, never the parent itself.
                minimum=1 if index==len(pattern)-1 and len(pattern)>1 else 0
                next_states.update(range(pos+minimum,len(parts)+1))
            elif pos<len(parts) and fnmatch.fnmatchcase(parts[pos],component):next_states.add(pos+1)
        states=next_states
        if not states:return False
    return len(parts) in states


@dataclass(frozen=True)
class IgnoreRule:
    base: tuple
    pattern: tuple
    basename: bool
    directory_only: bool
    negate: bool
    source: str
    line: int

    def matches(self, relative, is_dir):
        parts=PurePosixPath(relative).parts
        if parts[:len(self.base)]!=self.base:return False
        parts=parts[len(self.base):]
        if not parts:return False
        if self.basename:
            return any(fnmatch.fnmatchcase(part,self.pattern[0]) and (not self.directory_only or i<len(parts)-1 or is_dir) for i,part in enumerate(parts))
        # A matched directory also excludes descendants. The walker prunes
        # excluded parents, so a later child negation cannot rescue them.
        for end in range(1,len(parts)+1):
            if self.directory_only and end==len(parts) and not is_dir:continue
            if _components_match(self.pattern,parts[:end]):return True
        return False


def parse_ignore(raw, source='.gitignore'):
    """Return rules plus an explicit diagnostic for unsupported/oversized input."""
    if len(raw)>MAX_IGNORE_BYTES:return [],'oversized_gitignore'
    try:text=raw.decode('utf-8-sig')
    except UnicodeError:return [],'invalid_gitignore_encoding'
    base=PurePosixPath(source).parent.parts
    rules=[];diagnostic=None
    for line_no,line in enumerate(text.splitlines(),1):
        while line.endswith(' '):
            preceding=len(line[:-1])-len(line[:-1].rstrip('\\'))
            if preceding%2:break
            line=line[:-1]
        if not line or line.startswith('#'):continue
        negate=line.startswith('!')
        if negate:line=line[1:]
        if not line:continue
        directory=line.endswith('/')
        if directory:line=line[:-1]
        anchored=line.startswith('/')
        if anchored:line=line[1:]
        if not line:continue
        if len(line)>MAX_PATTERN or len(line.split('/'))>64 or line.count('*')+line.count('?')>32 or '\x00' in line or '[[:' in line:
            diagnostic='unsupported_gitignore_pattern';continue
        basename='/' not in line and not anchored
        pattern=tuple(_unescape(x) for x in line.split('/'))
        rules.append(IgnoreRule(base,pattern,basename,directory,negate,source,line_no))
        if len(rules)>=MAX_RULES:diagnostic='gitignore_rule_limit';break
    return rules,diagnostic


def ignore_decision(relative,is_dir,rules):
    ignored=False;last=None
    for rule in rules:
        if rule.matches(relative,is_dir):ignored=not rule.negate;last=rule
    return ignored,({'path':last.source,'line':last.line} if ignored and last else None)


def ignore_evidence(raw, relative):
    return {'path':relative,'sha256':hashlib.sha256(raw).hexdigest()}
