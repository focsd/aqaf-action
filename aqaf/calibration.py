"""Data-only calibration. Conformance and independently reviewed defects differ."""
from collections import Counter
import re


def evaluate(report,worksheet):
    if not isinstance(worksheet,dict) or worksheet.get('schema_version')!=1:raise ValueError('Unsupported calibration worksheet')
    labels=worksheet.get('labels',[])
    if not isinstance(labels,list) or len(labels)>10000:raise ValueError('Calibration labels must be a bounded list')
    signals={s['fingerprint']:s for s in report.get('review',{}).get('signals',[])};counts=Counter();stale=[];seen=set()
    for row in labels:
        if not isinstance(row,dict):raise ValueError('Invalid calibration row')
        fingerprint=row.get('fingerprint');label=row.get('label','unreviewed')
        if not isinstance(fingerprint,str) or not re.fullmatch('[0-9a-f]{64}',fingerprint) or fingerprint in seen:raise ValueError('Invalid or duplicate calibration fingerprint')
        seen.add(fingerprint)
        if label not in {'true_positive','false_positive','false_negative','ambiguous','unreviewed'}:raise ValueError('Invalid calibration label')
        signal=signals.get(fingerprint)
        if signal is None or row.get('source_digest')!=signal.get('source_digest'):stale.append(fingerprint);continue
        if label=='unreviewed':counts[label]+=1;continue
        reviewer=row.get('reviewer');author=worksheet.get('detector_author')
        if not isinstance(reviewer,str) or not reviewer.strip() or not author or reviewer==author or row.get('independent_review') is not True:raise ValueError('Labeled evidence requires an explicit independent reviewer distinct from detector author')
        if not row.get('rationale') or not row.get('characterization_evidence'):raise ValueError('Labeled evidence requires rationale and characterization evidence')
        counts[label]+=1
    counts['unreviewed']+=len(signals.keys()-seen)
    tp=counts['true_positive'];fp=counts['false_positive']
    return {'schema_version':1,'conformance':'separate_fixture_result','status':'independent_labels_present' if tp+fp+counts['ambiguous'] else 'independent_review_pending',
            'counts':dict(counts),'stale_labels':stale,'precision_on_reviewed_signals':tp/(tp+fp) if tp+fp else None,
            'recall':None,'recall_reason':'Requires an independently established exhaustive expected-concern corpus; observation worksheets cannot establish recall.',
            'promotion_authorized':False}
