"""Strictly data-only architecture profiles and packs. Does not import or execute extension code."""
from __future__ import annotations
import json
import re
from pathlib import Path
from importlib import resources

IDENT = re.compile(r'^[a-z][a-z0-9_]{1,63}$')
SIGNALS = {'file','extension','path','text','json_key'}

class ProfileError(ValueError):
    pass


def validate(doc, category):
    if not isinstance(doc, dict) or doc.get('schema_version') != 1 or not IDENT.fullmatch(str(doc.get('id',''))):
        raise ProfileError('Expected schema_version=1 and lowercase snake_case id')
    if category == 'profile':
        for key in ('name','product_type','target_architecture','status'):
            if not isinstance(doc.get(key),str) or not doc[key].strip():
                raise ProfileError(f'Profile {doc["id"]}: missing {key}')
        if not isinstance(doc.get('packs'),list) or not all(IDENT.fullmatch(str(x)) for x in doc['packs']):
            raise ProfileError(f'Profile {doc["id"]}: invalid packs')
        if not isinstance(doc.get('detection'),list): raise ProfileError('detection must be a list')
        for item in doc['detection']:
            if not isinstance(item,dict) or item.get('kind') not in SIGNALS or not isinstance(item.get('value'),str) or not 0 <= item.get('weight',-1) <= 150:
                raise ProfileError(f'Invalid declarative detection in {doc["id"]}')
            if len(item['value']) > 200 or '..' in item['value']:
                raise ProfileError('Unsafe/oversized detection value')
    elif category == 'pack':
        if not isinstance(doc.get('name'),str) or not isinstance(doc.get('profiles'),list):
            raise ProfileError(f'Pack {doc["id"]}: invalid fields')
        if not all(IDENT.fullmatch(str(p)) for p in doc['profiles']):
            raise ProfileError('Invalid profile ID in pack')
    return doc


def read_doc(path: Path, category):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ProfileError(f'Invalid or oversized manifest: {path}')
    try: return validate(json.loads(path.read_text(encoding='utf-8')), category)
    except (OSError, ValueError) as e: raise ProfileError(f'{path}: {e}') from e


class Registry:
    def __init__(self, extra_dirs=(), extra_pack_dirs=()):
        self.profiles = {}
        self.packs = {}
        pkg = resources.files('aqaf').joinpath('data')
        for category, name, store in [('profile','profiles',self.profiles),('pack','packs',self.packs)]:
            for item in sorted(pkg.joinpath(name).iterdir(), key=lambda p:p.name):
                if item.name.endswith('.json'):
                    value = validate(json.loads(item.read_text(encoding='utf-8')),category)
                    if value['id'] in store: raise ProfileError('Duplicate built-in ID')
                    store[value['id']] = value
        for folder in extra_dirs:
            path=Path(folder)
            if not path.is_dir(): raise ProfileError(f'Profile directory not found: {path}')
            for item in sorted(path.glob('*.json')):
                value=read_doc(item,'profile')
                if value['id'] in self.profiles:
                    raise ProfileError(f'External profile may not override built-in ID {value["id"]}')
                self.profiles[value['id']] = value
        for folder in extra_pack_dirs:
            path=Path(folder)
            if not path.is_dir(): raise ProfileError(f'Pack directory not found: {path}')
            for item in sorted(path.glob('*.json')):
                value=read_doc(item,'pack')
                if value['id'] in self.packs:
                    raise ProfileError(f'External pack may not override built-in ID {value["id"]}')
                self.packs[value['id']] = value
        for pack in self.packs.values():
            for p in pack['profiles']:
                if p not in self.profiles: raise ProfileError(f'Pack {pack["id"]}: unknown profile {p}')

    def get_profile(self, id):
        if id not in self.profiles: raise ProfileError(f'Unknown product profile {id}; run aqaf profiles list')
        return self.profiles[id]

    def get_pack(self,id):
        if id not in self.packs: raise ProfileError(f'Unknown pack {id}; run aqaf packs list')
        return self.packs[id]

    def detect(self, files, root, code, pack='auto', reader=None):
        read=reader or _read_small
        if pack!='auto': allowed=set(self.get_pack(pack)['profiles']) | {pid for pid,p in self.profiles.items() if pack in p['packs']}
        else: allowed=set(self.profiles)
        filenames={p.name.lower() for p in files}
        extensions={p.suffix.lower() for p in code}
        paths='\n'.join(str(p.relative_to(root)).replace('\\','/').lower() for p in files)
        # Text signal sampling is bounded; this detector never executes target files.
        snippets='\n'.join(read(p,65536)[:1500].lower() for p in code[:350])
        candidates=[]
        for id,profile in self.profiles.items():
            if id not in allowed or id=='unknown_or_general_app': continue
            evidence=[]; total=0
            for s in profile['detection']:
                kind=s['kind']; val=s['value']; weight=s['weight']; matched=False
                if kind=='file': matched=val.lower() in filenames
                elif kind=='extension': matched=val.lower() in extensions
                elif kind=='path': matched=val.lower() in paths
                elif kind=='text': matched=val.lower() in snippets
                elif kind=='json_key':
                    file_name,key=val.split(':',1) if ':' in val else ('','')
                    for p in files:
                        if p.name.lower()==file_name.lower():
                            try:
                                d=json.loads(read(p,65536)); matched= key in d if isinstance(d,dict) else False
                            except (ValueError,UnicodeError): pass
                            if matched: break
                if matched: total+=weight; evidence.append(kind+':'+val)
            if evidence: candidates.append((total,id,evidence))
        if not candidates: return 'unknown_or_general_app',[], 'low', []
        candidates.sort(key=lambda x:(-x[0],x[1]))
        best=candidates[0]
        # Don't treat weak, generic evidence as an authoritative classification.
        confidence='medium' if best[0]>=60 and (len(candidates)==1 or best[0]-candidates[1][0]>=20) else 'low'
        summary=[{'profile':id,'signal_score':score,'signals':evidence} for score,id,evidence in candidates[:5]]
        return best[1], best[2],confidence,summary


def _read_small(p,limit=65536):
    try:
        with p.open('rb') as handle: return handle.read(limit).decode('utf-8','replace')
    except OSError: return ''
