"""Roll up what AQAF could not establish, from the structures that already carry it. Unknown never means clean."""
from collections import Counter, OrderedDict

LIMIT_ITEMS = 25
LIMIT_LOCATIONS = 5
LIMIT_GROUPS = 50
NOTE = 'Unknown means not established by static analysis. It is not evidence that the code or documentation is sound.'


def scan_unknowns(report):
    """Group review-signal unknowns, unassessed checks, partial-syntax groups and manifest unknowns of a scan report."""
    review = report.get('review') or {}
    grouped = OrderedDict()
    for signal in review.get('signals', []):
        for text in signal.get('unknowns', []):
            entry = grouped.setdefault(text, {'text': text, 'count': 0, 'check_ids': set(), 'locations': []})
            entry['count'] += 1
            entry['check_ids'].add(signal.get('check_id'))
            for location in signal.get('locations', [])[:1]:
                place = '%s:%s' % (location.get('path'), location.get('line'))
                if len(entry['locations']) < LIMIT_LOCATIONS and place not in entry['locations']:
                    entry['locations'].append(place)
    items = [{**entry, 'check_ids': sorted(c for c in entry['check_ids'] if c)} for entry in
             sorted(grouped.values(), key=lambda e: (-e['count'], e['text']))]
    unassessed = sorted({c['check_id'] for c in review.get('coverage', []) if c.get('status') == 'unassessed'})
    partial = [{k: g.get(k) for k in ('owner', 'language', 'check_id', 'status', 'files_eligible')}
               for g in review.get('coverage_groups', []) if 'partial' in str(g.get('status'))]
    nodes = (report.get('projects') or {}).get('nodes', [])
    manifest = [{'root': n.get('root'), **u} for n in nodes for u in n.get('unknowns', [])]
    ambiguous = (report.get('projects') or {}).get('ambiguous_roots', [])
    return {
        'schema_version': 1, 'note': NOTE,
        'counts': {'review_signal_unknowns': sum(e['count'] for e in items), 'distinct_review_signal_unknowns': len(items),
                   'unassessed_checks': len(unassessed), 'partial_language_groups': len(partial),
                   'manifest_unknowns': len(manifest), 'ambiguous_roots': len(ambiguous)},
        'review_signal_unknowns': items[:LIMIT_ITEMS], 'unassessed_checks': unassessed,
        'partial_language_groups': partial[:LIMIT_GROUPS], 'manifest_unknowns': manifest[:LIMIT_ITEMS],
        'ambiguous_roots': [{'root': a.get('root'), 'reason': a.get('reason')} for a in ambiguous[:LIMIT_ITEMS]],
        'truncated': len(items) > LIMIT_ITEMS or len(partial) > LIMIT_GROUPS or len(manifest) > LIMIT_ITEMS or len(ambiguous) > LIMIT_ITEMS}


def docs_unknowns(doc):
    """Summarise the documentation review's unknowns: interface unknowns by reason and reader needs with unknown state."""
    reasons = Counter(u.get('reason') for u in doc.get('interface_unknowns', []))
    unknown_facets = [a for a in doc.get('applicability', []) if a.get('state') == 'unknown']
    return {'note': NOTE, 'interface_unknowns_by_reason': dict(sorted(reasons.items(), key=lambda kv: (-kv[1], str(kv[0])))),
            'interface_unknowns': sum(reasons.values()),
            'reader_needs_with_unknown_applicability': [{'facet': a['facet'], 'reader': a['reader']} for a in unknown_facets]}


def markdown(unknowns):
    c = unknowns['counts']
    lines = ['## What AQAF could not establish', '', unknowns['note'], '',
             '- Review-signal unknowns: %d (%d distinct)' % (c['review_signal_unknowns'], c['distinct_review_signal_unknowns']),
             '- Review checks unassessed: %d%s' % (c['unassessed_checks'], ' (' + ', '.join(unassessed_ids(unknowns)) + ')' if c['unassessed_checks'] else ''),
             '- Language groups with partial syntax coverage: %d' % c['partial_language_groups'],
             '- Manifest unknowns: %d; candidate roots not selected: %d' % (c['manifest_unknowns'], c['ambiguous_roots'])]
    for item in unknowns['review_signal_unknowns'][:10]:
        lines.append('  - %dx %s%s' % (item['count'], item['text'], ' (e.g. ' + item['locations'][0] + ')' if item['locations'] else ''))
    lines.append('')
    return lines


def unassessed_ids(unknowns):
    return unknowns['unassessed_checks']
