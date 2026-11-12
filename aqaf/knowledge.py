"""Optional, data-only book-informed review questions. Never scored detectors."""
from __future__ import annotations
import hashlib
from importlib import resources
import json
import re
from urllib.parse import urlsplit
from pathlib import Path


def load_knowledge():
    data=json.loads(resources.files('aqaf').joinpath('data/book_review_knowledge.json').read_text(encoding='utf8'))
    return validate_knowledge(data)


def validate_knowledge(data):
    if data.get('schema_version')!=1:raise ValueError('Unsupported review knowledge version')
    books={b['id']:b for b in data['books']}
    if len(books)!=len(data['books']):raise ValueError('Duplicate knowledge book')
    routes=set()
    for b in books.values():
        if not b.get('edition') or not b.get('review_summary') or not b.get('review_contribution') or not b.get('reading_references'):
            raise ValueError('Missing book reading metadata')
        expected='/books/'+b['id']+'/'
        if b.get('website_path')!=expected or not re.fullmatch(r'/books/[a-z0-9-]+/',expected):raise ValueError('Invalid book page')
        for ref in b['reading_references']:
            if ref.get('kind') not in {'chapter','topic','pattern'} or not ref.get('title') or ref.get('edition')!=b['edition']:
                raise ValueError('Invalid reading reference')
            if ref.get('number') is not None and not re.fullmatch(r'[1-9][0-9]*',str(ref['number'])):raise ValueError('Invalid reference number')
            url=ref.get('source_url','');parsed=urlsplit(url)
            if parsed.scheme!='https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or any(c.isspace() or c=='\\' for c in url):raise ValueError('Invalid reference URL')
            if ref.get('verification_status')!='verified_primary' or not re.fullmatch(r'\d{4}-\d{2}-\d{2}',ref.get('verified_on','')) or not ref.get('verification_basis'):
                raise ValueError('Unverified reading reference')
    ids=set()
    for card in data['principles']:
        if card['id'] in ids or not card['book_ids'] or not set(card['book_ids'])<=set(books):raise ValueError('Invalid knowledge references')
        route=card.get('website_path','')
        if not re.fullmatch(r'/learn/[a-z0-9-]+/',route) or route in routes:raise ValueError('Invalid guide page')
        routes.add(route)
        if not all(card.get(k) for k in ('explanation','example','counterexample','editorial_basis','example_basis')):raise ValueError('Incomplete guide')
        ids.add(card['id'])
        if set(card['applies_when'])!={'profiles','facets','languages'}:raise ValueError('Invalid knowledge applicability')
    return data


def review_agenda(scope,profile,paths=None):
    """Ask context-sensitive questions, without interpreting absence as failure."""
    from .facets import facets
    allowed=set(Path(p) for p in paths) if paths is not None else set(scope.files)
    records=[r for r in scope.records if r['path'] in allowed]
    owners={r['owner'] for r in records}
    context=facets(scope,owner=next(iter(owners)) if len(owners)==1 else None) if records else {'facts':[],'partial':False}
    relative={r['relative'] for r in records}
    facts=[f for f in context['facts'] if f['path'] in relative]
    present={f['facet'] for f in facts};languages={r['language'] for r in records if r['language']!='other'}
    # Evidence is deliberately bounded, contains no source bodies or default values.
    samples=[]
    for role in ({'production','source','unknown','tooling'},{'docs'},{'tests'}):
        candidates=[r for r in records if r['role'] in role]
        for r in candidates[:2]:
            raw=scope.raw(r['path'],8192)
            samples.append({'path':r['relative'],'role':r['role'],'sha256':hashlib.sha256(raw).hexdigest(),
                            'bytes':len(raw),'complete_file':len(raw)==r['size'],'state':'observed_inventory_only'})
    data=load_knowledge();books={b['id']:b for b in data['books']};questions=[]
    for card in data['principles']:
        when=card['applies_when'];basis=[]
        if not any(when.values()):basis.append({'kind':'general_review','claim':'Applicability and adequacy require a reviewer; not a missing-feature finding.'})
        if profile in when['profiles']:basis.append({'kind':'profile_hint','profile':profile,'confirmed':False})
        for lang in sorted(languages & set(when['languages'])):basis.append({'kind':'language_presence','language':lang})
        for f in facts:
            if f['facet'] in when['facets']:basis.append({'kind':'inferred_static_facet',**f})
        if not basis:continue
        questions.append({k:card[k] for k in ('id','title','question','required_evidence','verification','limitations','explanation')} | {
            'kind':'manual_verification','state':'unknown','confirmed':False,'runtime_verified':False,'mandatory':False,
            'guide_url':'https://aqaf.focsd.com'+card['website_path'],
            'applicability_basis':basis,'sources':[{'source_id':books[b]['source_id'],'book_id':b,'title':books[b]['title'],
                'url':books[b]['primary_url'],'book_url':'https://aqaf.focsd.com'+books[b]['website_path'],
                'edition':books[b]['edition'],'contribution':books[b]['review_contribution'],
                'reading_references':books[b]['reading_references'],'basis':'secondary_application_notes','notes_path':books[b]['notes_path'],
                'notes_sha256':books[b]['notes_sha256'],'full_book_reviewed':False} for b in card['book_ids']],
            'completion_record':{'reviewer':None,'date':None,'evidence':[],'result':'unknown','not_applicable_reason':None}})
    return {'schema_version':1,'knowledge_version':data['knowledge_version'],'kind':'book_informed_review_agenda','score_effect':'none',
            'profile_hint':profile,'languages':sorted(languages),'questions':questions,'inventory_evidence':samples,
            'context_sampling_partial':context.get('partial',False),'target_code_executed':False,
            'limitations':data['limitations']+['Profile/facet hints select questions; they do not establish a product contract or a defect.',
                'No repository commands, Git history, tests, network checks or hardware actions are executed.',
                'Receiver validation, authentication, runtime behavior and architecture conformance need independent evidence.']}


def markdown_agenda(agenda):
    """Render current and earlier additive agenda records without online lookups."""
    lines=['## Book-informed review agenda','','Optional human verification questions; unknown until reviewed. No score effect. Application guidance uses secondary notes; selected reading-reference facts were independently checked. These references do not validate detectors.','']
    for q in agenda['questions']:
        lines.extend(['### '+q['id']+' — '+q['title'],q['question']])
        if q.get('explanation'):lines.extend(['',q['explanation']])
        if q.get('guide_url'):lines.extend(['','[Why this matters and how to review it]('+q['guide_url']+')'])
        lines.extend(['','- Evidence to request: '+q['required_evidence'],
            '- Suggested verification (not executed): '+q['verification'],'- Limit: '+q['limitations'],
            '- State: unknown; assign a reviewer and date or explain why not applicable.','', 'Further reading:'])
        for source in q['sources']:
            edition=' — '+source['edition'] if source.get('edition') else ''
            contribution='. '+source['contribution'] if source.get('contribution') else ''
            lines.extend(['- ['+source['title']+']('+source.get('book_url',source['url'])+')'+edition+contribution,
                          '  Primary resource: ['+source['title']+']('+source['url']+').'])
            for ref in source.get('reading_references',[]):
                label=ref['kind'].capitalize()+(' '+ref['number'] if ref['number'] is not None else '')+': '+ref['title']
                lines.append('  - ['+label+']('+ref['source_url']+') — '+ref['edition']+'; verified '+ref['verified_on']+' (title/number/edition only).')
            lines.append('  Source ID: '+source['source_id']+'. Full book not reviewed.')
        lines.append('')
    return lines
