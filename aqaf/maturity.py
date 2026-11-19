"""Rule maturity and measured precision shown with every finding (AQAF-059).

No maturity above experimental is claimed without recorded evidence. Threshold numbers come from the owner
(aqaf/data/maturity.json); while they are unset nothing can be promoted.
"""
from importlib import resources
import json
import math


def levels():
    return json.loads(resources.files('aqaf').joinpath('data/maturity.json').read_text(encoding='utf8'))


def wilson(successes, n, z=1.96):
    """95% Wilson score interval for a proportion; None when there is no sample."""
    if not n:
        return None
    p = successes / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)]


def supported_level(rule, config=None):
    """Highest level the rule's recorded evidence supports under the configured thresholds."""
    config = config or levels()
    base = config['validation_status_to_level'].get(rule.get('validation_status'), 'experimental')
    if base == 'manual':
        return 'manual'
    measured = rule.get('measured')
    if not measured:
        return 'experimental'
    interval = wilson(measured.get('true_positives', 0), measured.get('labelled_sample', 0))
    best = 'experimental'
    for lv in sorted((l for l in config['levels'] if l['rank'] > 0), key=lambda l: l['rank']):
        need_n, need_p = lv['min_labelled_sample'], lv['min_precision_lower_bound']
        if need_n is None or need_p is None or interval is None:
            break  # thresholds not set by the owner: no promotion
        if measured['labelled_sample'] >= need_n and interval[0] >= need_p:
            best = lv['id']
        else:
            break
    return best


def finding_fields(rule, config=None):
    """The maturity block shown on a finding; additions only."""
    measured = rule.get('measured') or {}
    n = measured.get('labelled_sample')
    tp = measured.get('true_positives')
    return {'level': rule.get('maturity', 'experimental'), 'validation_status': rule.get('validation_status'),
            'false_positive_risk': rule.get('false_positive_risk'), 'labelled_sample': n,
            'precision': round(tp / n, 3) if n else None, 'precision_interval_95': wilson(tp, n) if n else None,
            'basis': 'recorded measurement' if measured else 'no recorded measurement'}


def summarise(findings):
    counts = {}
    for f in findings:
        level = (f.get('maturity') or {}).get('level', 'unknown')
        counts[level] = counts.get(level, 0) + 1
    return counts
