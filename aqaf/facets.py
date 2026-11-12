"""Unscored product facets from bounded static evidence, separate from profiles."""
import re
import hashlib

# Spelling evidence is an inferred capability, never proof of complete behavior.
PATTERNS={
 'browser_python':r'\b(?:loadPyodide|runPythonAsync|pyodide)\b',
 'pseudocode':r'\b(?:parsePseudocode|PseudocodeParser|executePseudocode)\b',
 'ocr':r'\b(?:pytesseract|Tesseract|recognizeText|VNRecognizeTextRequest|OCRResult|OcrResult|ocr|ocr_[A-Za-z0-9_]+)\b',
 'grading':r'\b(?:grade_submission|evaluate_submission|EvaluationResult|criterion_scores)\b',
 'desktop_ui':r'\b(?:QApplication|NSApplication|Tk|WindowGroup|ApplicationWindow|QMainWindow)\b',
 'desktop_widget':r'\b(?:WidgetKit|WidgetConfiguration|AppWidgetProvider)\b',
 'windows_service':r'\b(?:ServiceBase|AddWindowsService|UseWindowsService|ServiceFramework)\b',
 'proxy':r'\b(?:StreamingResponse|ReverseProxy|ProxyPass|proxy_pass|http_proxy)\b',
 'authentication':r'\b(?:OAuth2PasswordBearer|AuthenticationMiddleware|AddAuthentication|login_required|verify_oauth2_token|verify_id_token|OAuth2AuthorizationCodeBearer)\b',
 'backup':r'\b(?:CreateBackup|create_backup|backup_source|BackupFlow|PortBackupSource)\b',
 'pdf_mapping':r'\b(?:page_map|page_mapping|chapter_manifest|build_book_packs)\b',
 'browser_worker':r'\b(?:Worker|postMessage|terminate)\b',
 'apps_script':r'\b(?:SpreadsheetApp|ScriptApp|DocumentApp)\b',
 'ide_extension':r'\b(?:ToolWindowFactory|AnAction|IntelliJPlatform|ProjectActivity)\b',
 'infrastructure':r'\b(?:subprocess|ProcessBuilder|StartProcess|Popen)\b',
}

def facets(scope,max_files=128,max_bytes=2000000,owner=None):
    from .discovery import code_view,load_engine
    engine=load_engine();facts=[];diagnostics=[];used=0;attempted=0
    records=[r for r in scope.selected({'production','source','unknown','tooling'}) if owner is None or r['owner']==owner]
    for record in records:
        if record['language']=='other':continue
        if attempted>=max_files or used>=max_bytes:break
        raw=scope.raw(record['path'],min(32768,max_bytes-used));used+=len(raw);attempted+=1
        text=raw.decode('utf8','replace')
        try:view=code_view(text,record['language'],engine)
        except (ValueError,RecursionError,SyntaxError):
            diagnostics.append({'path':record['relative'],'reason':'unsupported_or_truncated_syntax'});continue
        for facet,pattern in PATTERNS.items():
            match=re.search(pattern,view)
            if match:facts.append({'facet':facet,'state':'inferred','path':record['relative'],
                'sha256':hashlib.sha256(raw).hexdigest(),'line':view.count('\n',0,match.start())+1,
                'read_bytes':len(raw),'complete_file':len(raw)==record['size'],
                'confirmed':False,'runtime_verified':False})
    present={f['facet'] for f in facts}
    delivery=sorted({kind for facet,kind in [('desktop_ui','desktop'),('browser_python','browser'),('browser_worker','browser'),('desktop_widget','desktop'),('windows_service','service'),('ide_extension','ide_plugin'),('apps_script','cloud_script')] if facet in present})
    return {'delivery':delivery,'runtimes':sorted({r['language'] for r in records if r['language']!='other'}),'source_evidence_state':'bounded_source_sample' if attempted else 'metadata_only_or_unread','platform_constraints':['windows'] if 'windows_service' in present else ['apple'] if 'desktop_widget' in present and any(r['language']=='swift' for r in records) else ['unknown'],
            'diagnostics':diagnostics[:200],'schema_version':1,'facts':facts,'attempted':attempted,'bytes':used,
            'partial':bool(diagnostics) or attempted<sum(r['language']!='other' for r in records) or any(not f['complete_file'] for f in facts),
            'interpretation':'Static capability spellings; absence from bounded evidence means unknown.'}


def classification(scope):
    """Existing profile IDs, shared selected roots, masked source-only text cues."""
    from .discovery import code_view,load_engine
    from .registry import Registry
    engine=load_engine();records=[r for r in scope.records if r['owner']=='root']
    code=[r['path'] for r in records if r['language']!='other']
    def reader(path,limit=65536):
        text=scope.text(path,limit);lang=scope.record(path).get('language')
        if lang and lang!='other':
            try:return code_view(text,lang,engine)
            except (ValueError,RecursionError):return ''
        return text
    ident,evidence,confidence,alternatives=Registry().detect([r['path'] for r in records],scope.root,code,reader=reader)
    return {'profile':ident,'evidence':evidence,'confidence':confidence,'alternatives':alternatives,'kind':'static_heuristic','confirmed':False}
