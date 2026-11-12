"""Bounded data-only continuation identity. Never merge different assessments."""
import hashlib,json,os,tempfile
from pathlib import Path
from . import __version__

MAX_STATE_BYTES=16384
MAX_IDENTITY_BYTES=256000000
MAX_IDENTITY_FILE=1500000


def runtime_identity():
    root=Path(__file__).parent;digest=hashlib.sha256()
    for path in sorted(root.rglob('*')):
        if path.is_file() and path.suffix in {'.py','.json'} and '__pycache__' not in path.parts:
            digest.update(path.relative_to(root).as_posix().encode()+b'\0'+path.read_bytes())
    return digest.hexdigest()


def identity(scope,options):
    """Full selected-body hashes under explicit bounds; oversized identity fails closed."""
    digest=hashlib.sha256();total=0
    metadata={'root':str(scope.root),'runtime':runtime_identity(),'version':__version__,'policy':scope.policy,
              'gitignore':scope.respect_gitignore,'ignore_sources':scope.ignore_sources,'config':scope.config,
              'options':{k:v for k,v in options.items() if k!='offset'}}
    digest.update(json.dumps(metadata,sort_keys=True).encode())
    for record in sorted(scope.records,key=lambda r:r['relative']):
        size=record['size'];total+=size
        if size>MAX_IDENTITY_FILE or total>MAX_IDENTITY_BYTES:raise ValueError('Continuation identity exceeds safe full-content bounds; use a smaller component/scope or a fresh independent scan')
        raw=scope.raw(record['path'],MAX_IDENTITY_FILE+1)
        if len(raw)!=size:raise ValueError('Continuation identity input changed or is unreadable')
        digest.update(record['relative'].encode()+b'\0'+hashlib.sha256(raw).digest())
    return digest.hexdigest()


def load(path,expected):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_STATE_BYTES:raise ValueError('Invalid bounded continuation state')
    try:data=json.loads(path.read_text())
    except (ValueError,OSError,RecursionError) as error:raise ValueError('Invalid continuation JSON') from error
    if not isinstance(data,dict) or data.get('schema_version')!=1 or data.get('identity')!=expected:raise ValueError('Stale continuation: source, root, runtime, scope or budgets changed; start a new scan')
    offset=data.get('next_offset')
    if type(offset) is not int or not 0<=offset<=500000:raise ValueError('Invalid continuation offset')
    return offset


def write(path,scope,identity_value,next_offset):
    path=Path(path).absolute()
    resolved=path.resolve()
    if resolved==scope.root or scope.root in resolved.parents:raise ValueError('Continuation state must be outside the assessed source')
    if path.exists() or path.is_symlink():raise ValueError('Continuation state already exists; choose a new output file')
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,temporary=tempfile.mkstemp(prefix='.aqaf-cursor-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:json.dump({'schema_version':1,'identity':identity_value,'next_offset':next_offset,'scope':'Independent partial page; previous evidence is not merged or marked complete.'},f,indent=2)
        os.link(temporary,path)  # Atomic create without replacing historical state.
    finally:Path(temporary).unlink(missing_ok=True)
