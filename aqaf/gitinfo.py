"""Read-only git inventory for discovered projects: repositories, remotes, latest commit, submodules, nested repositories.

Opt-in (`aqaf projects discover --git`). The only thing executed is the `git` binary, with the repository's own
configuration neutralised (no hooks, fsmonitor, pager, global or system config, prompts or external protocols) and only
`config --local`, `rev-parse` and `log -1`; no project code runs and nothing is modified. When `git` is not installed the
remotes are still read from `.git/config`, and commit information is reported as unavailable. Remote URLs and commit
subjects are untrusted text from the project: credentials are removed from URLs and nothing here is a verified fact.
"""
import os
import re
import subprocess
from pathlib import Path

PRUNE = {'node_modules', '.venv', 'venv', 'env', '__pycache__', 'target', 'build', 'dist', 'Pods', '.gradle', '.idea', '.tox',
         '.mypy_cache', 'site-packages', '.next', '.cache', '$RECYCLE.BIN', 'System Volume Information'}
GIT_ENV = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS='0',
               GIT_TERMINAL_PROMPT='0', GIT_PAGER='cat', LC_ALL='C')
GIT = ['git', '-c', 'safe.directory=*', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=' + os.devnull,
       '-c', 'core.pager=cat', '-c', 'protocol.ext.allow=never']
MAX_REPOS = 200


def git(directory, *args, timeout=20):
    try:
        done = subprocess.run(GIT + ['-C', str(directory)] + list(args), capture_output=True, text=True, timeout=timeout, env=GIT_ENV)
    except FileNotFoundError:
        return None
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def available():
    try:
        subprocess.run(['git', '--version'], capture_output=True, timeout=10, env=GIT_ENV)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def redact(url):
    """Remove user:password / token credentials from a URL; scp-style git@host:path keeps its user."""
    return re.sub(r'^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@]*@', r'\1', url.strip())


def normalize(url):
    """host/owner/repo, lowercase, without scheme, credentials, port or .git, so ssh and https forms compare equal."""
    url = redact(url)
    scp = re.match(r'^(?:[^@/]+@)?([^:/]+):(?!//)(.+)$', url)
    if scp:
        host, path = scp.group(1), scp.group(2)
    else:
        match = re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^@/]*@)?([^/:]+)(?::\d+)?/(.*)$', url)
        if not match:
            return url.lower().rstrip('/')
        host, path = match.group(1), match.group(2)
    return '%s/%s' % (host.lower(), re.sub(r'\.git$', '', path.strip('/')).lower())


def web_link(url):
    """An https link for ordinary hosted remotes (http, https, ssh, git or scp-style URLs with a dotted host), else None."""
    url = redact(url)
    hosted = url.startswith(('http://', 'https://', 'ssh://', 'git://')) or re.match(r'^(?:[^@/]+@)?[^:/]+:(?!//)', url)
    key = normalize(url)
    return 'https://' + key if hosted and '.' in key.split('/', 1)[0] and '/' in key else None


def config_remotes(directory):
    """Fallback without the git binary: remote URLs from .git/config (a regular .git directory only)."""
    path = Path(directory) / '.git' / 'config'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
        return []
    remotes, name = [], None
    for line in path.read_text(encoding='utf8', errors='replace').splitlines():
        header = re.match(r'\s*\[remote "([^"]+)"\]', line)
        if header:
            name = header.group(1)
        elif line.strip().startswith('['):
            name = None
        elif name and re.match(r'\s*url\s*=', line):
            remotes.append((name, line.split('=', 1)[1].strip()))
    return remotes


def repo_info(directory, rel, binary):
    remotes = []
    if binary:
        out = git(directory, 'config', '--local', '--get-regexp', r'^remote\..*\.url$') or ''
        pairs = [(l.split(None, 1)[0][len('remote.'):-len('.url')], l.split(None, 1)[1]) for l in out.splitlines() if len(l.split(None, 1)) == 2]
    else:
        pairs = config_remotes(directory)
    for name, url in pairs:
        remotes.append({'name': name, 'url': redact(url), 'key': normalize(url), 'link': web_link(url)})
    branch = git(directory, 'rev-parse', '--abbrev-ref', 'HEAD') if binary else None
    commit = None
    out = git(directory, 'log', '-1', '--format=%H%x1f%cI%x1f%s') if binary else None
    if out:
        sha, when, subject = (out.split('\x1f') + ['', ''])[:3]
        commit = {'sha': sha, 'date': when, 'subject': subject}
    return {'path': rel, 'remotes': remotes, 'branch': branch, 'commit': commit}


def declared_submodules(directory):
    """Submodules declared in .gitmodules: [{'path','url','key'}], whether or not they are checked out."""
    if not (Path(directory) / '.gitmodules').is_file():
        return []
    out = git(directory, 'config', '-f', '.gitmodules', '--get-regexp', r'^submodule\..*\.(path|url)$') or ''
    found = {}
    for line in out.splitlines():
        key, _, value = line.partition(' ')
        name, _, field = key[len('submodule.'):].rpartition('.')
        found.setdefault(name, {})[field] = value
    return [{'path': v.get('path', ''), 'url': redact(v.get('url', '')), 'key': normalize(v['url']) if v.get('url') else None}
            for v in found.values()]


def inspect(root, max_depth=8):
    """Every repository in a project folder (without entering dependency/build folders): kind, parent, remotes, commit."""
    root, binary = Path(root), available()
    repos, depth_limited = [], False
    base = len(root.parts)
    for current, dirs, files in os.walk(root, followlinks=False):
        here = Path(current)
        if '.git' in dirs or '.git' in files:
            if len(repos) >= MAX_REPOS:
                depth_limited = True
                break
            rel = here.relative_to(root).as_posix()  # '.' for the root; always '/' separated, also on Windows
            info = repo_info(here, rel, binary)
            info['linked_gitdir'] = '.git' in files
            info['declared_submodules'] = declared_submodules(here) if binary else []
            repos.append(info)
        dirs[:] = [d for d in dirs if d != '.git' and d not in PRUNE and not (here / d).is_symlink()]
        if len(here.parts) - base >= max_depth:
            depth_limited = depth_limited or bool(dirs)
            dirs[:] = []
    by_path = {r['path']: r for r in repos}
    for repo in repos:
        parent, probe = None, Path(repo['path']).parent if repo['path'] != '.' else None
        while probe is not None:
            key = probe.as_posix()
            if key in by_path:
                parent = key
                break
            probe = probe.parent if probe.as_posix() != '.' else None
        repo['parent'] = parent
        if repo['path'] == '.':
            repo['kind'] = 'root'
        elif parent is not None and any(Path(s['path']) == Path(repo['path']).relative_to(parent) for s in by_path[parent]['declared_submodules'] if s['path']):
            repo['kind'] = 'submodule'
        elif repo['linked_gitdir']:
            repo['kind'] = 'linked'
        else:
            repo['kind'] = 'nested' if parent is not None else 'inner'
    declared_only = []
    for repo in repos:
        for sub in repo['declared_submodules']:
            full = (Path(repo['path']) / sub['path']).as_posix() if repo['path'] != '.' else Path(sub['path']).as_posix()
            if full not in by_path:
                declared_only.append({'parent': repo['path'], 'path': full, 'url': sub['url']})
    return {'git_binary': binary, 'repositories': repos, 'declared_submodules_not_checked_out': declared_only,
            'root_is_repository': '.' in by_path, 'search_truncated': depth_limited}


def links(entries):
    """Group repositories that share a normalised remote across projects. entries: {project_path: inspect() result}."""
    groups = {}
    for project, data in entries.items():
        for repo in data['repositories']:
            for remote in repo['remotes']:
                groups.setdefault(remote['key'], []).append({
                    'project': project, 'path': repo['path'], 'kind': repo.get('kind'), 'remote_name': remote['name'],
                    'url': remote['url'], 'link': remote['link'], 'branch': repo['branch'],
                    'sha': (repo['commit'] or {}).get('sha'), 'date': (repo['commit'] or {}).get('date')})
    return [{'remote': key, 'members': members, 'same_commit': len({m['sha'] for m in members}) == 1}
            for key, members in sorted(groups.items()) if len({(m['project'], m['path']) for m in members}) > 1]
