"""Publish complete format bundles atomically, never replace historical results."""
from pathlib import Path
import json,os,tempfile


def write_bundle(report,destination):
    from .cli import md_report,sarif_report
    destination=Path(destination)
    if destination.is_symlink():raise ValueError('Bundle destination cannot be a symlink')
    if destination.exists() and any(destination.iterdir()):raise ValueError('Bundle destination is not empty; choose a new attempt directory')
    destination.mkdir(parents=True,exist_ok=True)
    values={'report.json':json.dumps(report,indent=2),'report.md':md_report(report),'report.sarif':json.dumps(sarif_report(report),indent=2)}
    # Each file is complete before rename; the manifest is the commit marker.
    import hashlib
    for name,text in values.items():
        target=destination/name
        if target.is_symlink():raise ValueError('Bundle artifact cannot be a symlink')
        fd,temporary=tempfile.mkstemp(prefix='.aqaf-',dir=destination)
        try:
            with os.fdopen(fd,'w',encoding='utf8',newline='\n') as stream:stream.write(text+'\n')
            os.replace(temporary,target)
        finally:Path(temporary).unlink(missing_ok=True)
    manifest={'schema_version':1,'status':'complete','files':{k:hashlib.sha256((v+'\n').encode()).hexdigest() for k,v in values.items()}}
    fd,temporary=tempfile.mkstemp(prefix='.aqaf-',dir=destination)
    try:
        with os.fdopen(fd,'w',encoding='utf8',newline='\n') as stream:json.dump(manifest,stream,indent=2)
        os.replace(temporary,destination/'bundle.json')
    finally:Path(temporary).unlink(missing_ok=True)
