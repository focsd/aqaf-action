"""Coverage of the heuristic index and a coverage-adjusted score. Additive: `score` itself is never changed.

The index only subtracts for what AQAF observed. When AQAF could assess little (checks unassessed, languages only partly
parsed, no code selected) a high score mostly means "nothing found", so this module reports how much was assessed and
shrinks the score toward the uninformative midpoint in proportion to what was not.

    coverage = check_coverage * (0.5 + 0.5 * source_coverage) * (0.5 if content_only else 1)
    score_coverage_adjusted = round(50 + coverage * (score - 50))

Provisional and uncalibrated, like the index itself; not a quality measure.
"""
MIDPOINT = 50
NOTE = ('Coverage is the share of review checks and eligible source AQAF could assess. The adjusted score moves the index toward 50 '
        'as coverage falls; it is a provisional reading aid, not a validated score.')


def _band(value):
    return 'high' if value >= 0.8 else 'medium' if value >= 0.5 else 'low'


def coverage_adjusted(report):
    """Return {'coverage': {...}, 'score_coverage_adjusted': int|None} from a finished scan report."""
    review = report.get('review')
    score = report.get('score')
    content_only = bool(report.get('content_only'))
    if not isinstance(review, dict) or not isinstance(score, (int, float)):
        return {'coverage': {'value': None, 'band': 'unknown', 'note': NOTE,
                             'reason': 'review signals were not collected; run with --review-signals to measure coverage',
                             'content_only': content_only}, 'score_coverage_adjusted': None}
    checks = review.get('coverage') or []
    unassessed = sum(1 for c in checks if c.get('status') == 'unassessed')
    check_cov = 1 - unassessed / len(checks) if checks else 1.0
    eligible = full = 0.0
    for g in review.get('coverage_groups') or []:
        n = g.get('files_eligible') or 0
        eligible += n
        status = str(g.get('status'))
        full += n * (0.0 if 'unassessed' in status else 0.5 if 'partial' in status else 1.0)
    source_cov = full / eligible if eligible else 1.0
    value = check_cov * (0.5 + 0.5 * source_cov) * (0.5 if content_only else 1.0)
    value = round(max(0.0, min(1.0, value)), 3)
    return {'coverage': {'value': value, 'band': _band(value), 'check_coverage': round(check_cov, 3),
                         'source_coverage': round(source_cov, 3), 'unassessed_checks': unassessed,
                         'content_only': content_only, 'note': NOTE},
            'score_coverage_adjusted': int(round(MIDPOINT + value * (score - MIDPOINT)))}
