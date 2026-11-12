#!/usr/bin/env python3
"""Find project roots and estimate their types without running target code."""
from __future__ import annotations

import argparse
from collections import Counter
import fnmatch
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tokenize

ROOT = Path(__file__).resolve().parents[1]
TOOL_VERSION = '1.0.0'
OS_SKIP = {'.Trash', '.Trashes', '.Spotlight-V100', '.fseventsd',
           '$RECYCLE.BIN', 'System Volume Information', '.ssh', '.gnupg', '.credentials'}
ARCHIVE_REASONS = {'archive_or_metadata', 'submitted_project_corpus', 'generated_project_copy'}
EXTRA_MARKERS = {'requirements.txt': 'python', 'Pipfile': 'python',
                 'Gemfile': 'ruby', '*.xcodeproj': 'swift', '*.xcworkspace': 'swift'}


def load_engine(source=None):
    """Use the installed trusted runtime; never import a searched project."""
    from . import __version__
    modules = {name: importlib.import_module('aqaf.' + name)
               for name in ('projects','scope','ignore','registry','adapters','review')}
    modules.update(source=ROOT, version=__version__)
    return modules


def known_projects(registry, history):
    """Previous detections are context, never independently verified type labels."""
    known = {}
    if registry and registry.is_dir():
        for p in sorted(registry.iterdir()):
            if p.is_symlink():
                continue
            if p.is_dir() and not p.name.startswith('.'):
                known[str(p.resolve())] = {'registered_id': p.name}
            elif p.is_file() and p.name.endswith('.aqaf-source.json') and p.stat().st_size <= 16384:
                try:
                    d = json.loads(p.read_text())
                    if (d.get('schema_version') == 1 and d.get('kind') == 'aqaf-source-reference'
                            and isinstance(d.get('path'), str) and Path(d['path']).is_absolute()):
                        known[str(Path(d['path']))] = {'registered_id': d.get('id')}
                except (OSError, ValueError, TypeError):
                    continue
    if history:
        try:
            d = json.loads((history / 'summary.json').read_text())
            if d.get('status') == 'passed':
                for ident, value in d.get('projects', {}).items():
                    path = d.get('source_paths', {}).get(ident)
                    if path and value.get('status') == 'passed':
                        known.setdefault(path, {}).update(previous_profile=value.get('profile'),
                            previous_version=d.get('version'), previous_run=str(history),
                            previous_type_independently_verified=False)
        except (OSError, ValueError, TypeError):
            pass
    return known


def code_view(text, language, engine):
    """Keep source tokens, never classify from a copied string/comment example."""
    if language == 'python':
        chars = ['\n' if c == '\n' else ' ' for c in text]
        lines = text.splitlines(keepends=True)
        starts, offset = [], 0
        for line in lines:
            starts.append(offset)
            offset += len(line)
        try:
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                if token.type not in {tokenize.NAME, tokenize.OP, tokenize.NUMBER}:
                    continue
                a = starts[token.start[0] - 1] + token.start[1]
                b = starts[token.end[0] - 1] + token.end[1]
                chars[a:b] = text[a:b]
        except (tokenize.TokenError, IndentationError, IndexError, SyntaxError):
            pass  # Keep only safely tokenized code before a truncated prefix.
        return ''.join(chars)
    if language in {'jsx', 'tsx'}:
        markup = importlib.import_module('aqaf.markup')
        return code_view(markup.prepare_jsx(text)[0], 'typescript', engine)
    if language in {'javascript', 'typescript'}:
        tokens = engine['review'].lex(text)
        chars = ['\n' if c == '\n' else ' ' for c in text]
        for token in tokens:
            if token.kind not in {'string', 'opaque'}:
                chars[token.start:token.end] = text[token.start:token.end]
        return ''.join(chars)
    if language == 'swift':
        module = importlib.import_module('aqaf.swift_review')
        return module.mask_swift(text)[0]
    if language == 'rust':
        module = importlib.import_module('aqaf.evidence')
        return module.code_tokens(text, rust=True)
    if language not in {'python', 'kotlin', 'java', 'csharp', 'php', 'powershell',
                        'shell', 'c', 'cpp', 'c_header', 'objective_c', 'objective_cpp', 'go', 'groovy'}:
        return ''  # Other dialects retain filename/manifest evidence, never raw-text guesses.
    return engine['adapters'].mask_source(text, language)[0]


class Finder:
    def __init__(self, engine, *, respect_gitignore=True, max_depth=24,
                 max_directories=100000, max_entries=1000000, max_projects=2000,
                 max_files_per_project=500, max_bytes=16000000, exclude=(), known=None,
                 include_archives=False, include_installed_plugins=False, scope_config=None):
        self.engine = engine
        self.scope_config=scope_config or {}
        self.registry = engine['registry'].Registry()
        self.ignore = engine['ignore']
        self.scope = engine['scope']
        self.projects = engine['projects']
        self.respect_gitignore = respect_gitignore
        self.limits = dict(max_depth=max_depth, max_directories=max_directories,
                          max_entries=max_entries, max_projects=max_projects,
                          max_files_per_project=max_files_per_project, max_bytes=max_bytes)
        self.exclude = tuple(exclude)+tuple(self.scope_config.get('exclude',[]))
        self.known = known or {}
        self.include_archives = include_archives
        self.include_installed_plugins = include_installed_plugins
        self.stats = Counter()
        self.exclusions = Counter()
        self.issues = []
        self.rows = []
        self.seen = set()
        self.budget_exhausted = False

    def issue(self, reason, path):
        self.stats['issues'] += 1
        if len(self.issues) < 100:
            self.issues.append({'reason': reason, 'path': str(path)})

    def read_raw(self, cache, path, limit):
        remaining = self.limits['max_bytes'] - self.stats['bytes_requested']
        if remaining <= 0:
            if not self.budget_exhausted:
                self.issue('content_byte_budget', cache.root)
            self.budget_exhausted = True
            return b''
        allowed = min(limit, remaining)
        raw = cache.read(path, allowed)
        self.stats['bytes_requested'] += len(raw)
        if allowed < limit:
            self.issue('content_read_truncated', path)
        return raw

    def read(self, cache, path, limit):
        return self.read_raw(cache, path, limit).decode('utf8', 'replace')

    def listing(self, directory, root):
        if self.stats['directories_visited'] >= self.limits['max_directories']:
            self.issue('directory_budget', directory)
            return None
        self.stats['directories_visited'] += 1
        entries = []
        fd = None
        try:
            if (os.open in os.supports_dir_fd and os.scandir in os.supports_fd
                    and hasattr(os, 'O_NOFOLLOW')):
                fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                for part in directory.relative_to(root).parts:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                scan = fd
            else:
                if any(p.is_symlink() for p in (directory, *directory.parents)):
                    raise OSError('Symlink directory rejected')
                scan = directory
            with os.scandir(scan) as stream:
                for entry in stream:
                    if self.stats['entries_seen'] >= self.limits['max_entries']:
                        self.issue('entry_budget', directory)
                        return None
                    self.stats['entries_seen'] += 1
                    if len(entries) == 20000:
                        self.issue('directory_entry_limit', directory)
                        break
                    try:
                        kind = ('symlink' if entry.is_symlink() else 'directory' if entry.is_dir(follow_symlinks=False)
                                else 'file' if entry.is_file(follow_symlinks=False) else 'special')
                        entries.append((entry.name, kind))
                    except OSError:
                        self.issue('unreadable_entry', directory / entry.name)
        except OSError:
            self.issue('unreadable_directory', directory)
            return None
        finally:
            if fd is not None:
                os.close(fd)
        return sorted(entries)

    def markers(self, names):
        found = {name: self.projects.marker_family(name) for name in names
                 if self.projects.marker_family(name)}
        for pattern, family in EXTRA_MARKERS.items():
            found.update({name: family for name in names if fnmatch.fnmatchcase(name, pattern)})
        return found

    def walk(self, root):
        root = Path(root).expanduser().absolute()
        if any(p.is_symlink() for p in (root, *root.parents)):
            self.issue('search_root_symlink_rejected', root)
            return
        if not root.is_dir():
            self.issue('search_root_missing_or_not_directory', root)
            return
        root = root.resolve()
        cache = self.scope.ReadCache(root)
        stack = [(root, 0, (), None, (), None)]
        def authored(relative):
            patterns=self.scope_config.get('include',[])
            return any(fnmatch.fnmatchcase(relative,p) or relative==p.removesuffix('/**') for p in patterns)
        def authored_descendant(relative):
            return authored(relative) or any(p.startswith(relative.rstrip('/')+'/') for p in self.scope_config.get('include',[]))
        try:
            while stack:
                directory, depth, rules, parent, inherited, excluded_context = stack.pop()
                if directory in self.seen:
                    continue
                self.seen.add(directory)
                relative = directory.relative_to(root).as_posix()
                if (not self.include_installed_plugins and directory != root
                        and directory.name == 'plugins' and directory.parent.name == 'wp-content'
                        and not authored_descendant(relative)):
                    self.exclusions['installed_wordpress_plugin_collection'] += 1
                    continue
                entries = self.listing(directory, root)
                if entries is None:
                    if self.stats['entries_seen'] >= self.limits['max_entries'] or self.stats['directories_visited'] >= self.limits['max_directories']:
                        break
                    continue
                files, dirs = [], []
                for name, kind in entries:
                    if kind == 'symlink': self.exclusions['symlink'] += 1
                    elif kind == 'directory': dirs.append(name)
                    elif kind == 'file': files.append(name)
                    else: self.exclusions['special_file'] += 1
                names = set(files + dirs)
                markers = self.markers(files + [n for n in dirs if n.endswith(('.xcodeproj', '.xcworkspace'))])
                families = set(inherited) | set(markers.values())
                if {'wp-content', 'wp-includes'} & names and 'wp-config.php' in names:
                    markers['wp-config.php'] = 'wordpress'
                    families.add('wordpress')
                reason = excluded_context or self.scope.folder_reason(relative, directory.name, families, names)
                if authored(relative) and reason!='vcs_metadata':reason=None
                if reason=='wordpress_deployed_package' and self.include_installed_plugins and directory.name=='plugins':reason=None
                if reason in ARCHIVE_REASONS and self.include_archives:
                    reason = None
                if (reason and not (reason!='vcs_metadata' and authored_descendant(relative))) or directory.name in OS_SKIP or directory == ROOT / 'output':
                    self.exclusions[reason or 'private_os_or_tool_output'] += 1
                    continue
                if self.respect_gitignore and '.gitignore' in files:
                    raw = self.read_raw(cache, directory / '.gitignore', self.ignore.MAX_IGNORE_BYTES + 1)
                    local, diagnostic = self.ignore.parse_ignore(raw, (directory / '.gitignore').relative_to(root).as_posix())
                    if diagnostic:
                        self.issue(diagnostic, directory / '.gitignore')
                        continue  # Invalid controls cannot silently broaden search.
                    rules = (*rules, *local)
                    if len(rules) > self.ignore.MAX_RULES:
                        rules = rules[:self.ignore.MAX_RULES]
                        self.issue('inherited_ignore_rule_limit', directory)
                def included(name, is_dir):
                    rel = (directory / name).relative_to(root).as_posix()
                    if any(fnmatch.fnmatchcase(rel, p) or fnmatch.fnmatchcase(name, p) for p in self.exclude):
                        self.exclusions['operator_pattern'] += 1
                        return False
                    if self.respect_gitignore and self.ignore.ignore_decision(rel, is_dir, rules)[0]:
                        self.exclusions['gitignore'] += 1
                        return False
                    return True
                files = [name for name in files if included(name, False) and (not reason or authored((directory/name).relative_to(root).as_posix()))]
                dirs = [name for name in dirs if included(name, True) and (not reason or authored_descendant((directory/name).relative_to(root).as_posix()))]
                markers = {n: f for n, f in markers.items() if n in files or n in dirs}
                if 'manifest.json' in files:
                    try:
                        manifest = json.loads(self.read(cache, directory / 'manifest.json', 65536))
                        if isinstance(manifest, dict) and 'manifest_version' in manifest:
                            markers['manifest.json'] = 'browser_extension'
                    except (ValueError, RecursionError):
                        pass
                code = [n for n in files if Path(n).suffix.lower() in self.scope.LANGUAGES]
                has_git = '.git' in names
                conventional = sorted(set(dirs) & (self.projects.SOURCES | {'Sources'}))
                # Source-only candidates remain deliberately weak; don't split every src folder.
                nearby_source = False
                if parent is None and not code and depth < self.limits['max_depth']:
                    for name in conventional:
                        child_entries = self.listing(directory / name, root)
                        if child_entries is None:
                            continue
                        child_files = [n for n, kind in child_entries if kind == 'file']
                        if self.markers(child_files) or '.gitignore' in child_files:
                            continue
                        nearby_source = any(Path(n).suffix.lower() in self.scope.LANGUAGES
                            and not (self.respect_gitignore and self.ignore.ignore_decision(
                                (directory / name / n).relative_to(root).as_posix(), False, rules)[0])
                            for n in child_files)
                        if nearby_source:
                            break
                fallback = parent is None and (bool(code) or nearby_source)
                plugin = (directory.parent.name == 'plugins' and directory.parent.parent.name == 'wp-content'
                          and any('Plugin Name:' in self.read(cache, directory / n, 8192) for n in files if n.endswith('.php')))
                if markers or has_git or fallback or plugin:
                    if len(self.rows) >= self.limits['max_projects']:
                        self.issue('project_budget', directory)
                        break
                    row = {'path': str(directory), 'search_root': str(root), 'relative_path': relative,
                           'parent_project': parent['path'] if parent else None,
                           'relationship': 'embedded_project' if parent else 'top_level_project',
                           'markers': sorted(markers), 'ecosystems': sorted({'jvm_gradle' if f == 'android' else f for f in markers.values()}),
                           'source_roots': conventional, 'files': [], 'file_count_observed': 0,
                           'root_probability': .97 if markers and code else .90 if markers else .80 if has_git else .55,
                           'root_basis': 'manifest' if markers else 'wordpress_plugin_header' if plugin else 'git_root' if has_git else 'source_layout_only',
                           'workspace_patterns': [], 'plugin_header': plugin, 'known_context': self.known.get(str(directory)),
                           'archive_or_copy_context': self.projects.archived(directory.as_posix()),
                           'ownership': 'unverified',
                           'installed_wordpress_plugin_context': plugin,
                           'sampling_limited': False}
                    if plugin:
                        row['root_probability'] = .90
                    self.rows.append(row)
                    parent = row
                if parent:
                    parent['file_count_observed'] += len(files)
                    candidates = [directory / n for n in files]
                    candidates.sort(key=lambda p: (not bool(self.projects.marker_family(p.name)),
                        self.scope.file_role(p.relative_to(Path(parent['path'])).as_posix()) in {'tests', 'fixture', 'docs'}, p.name))
                    remaining = self.limits['max_files_per_project'] - len(parent['files'])
                    parent['files'].extend(candidates[:remaining])
                    if len(candidates) > remaining:
                        parent['sampling_limited'] = True
                if depth >= self.limits['max_depth']:
                    if dirs:
                        self.issue('depth_limit', directory)
                    continue
                # Root markers first; nested components keep their own evidence, not their parent's.
                for name in reversed(sorted(dirs, key=lambda n: (n not in conventional, n))):
                    child_relative=(directory/name).relative_to(root).as_posix()
                    child_reason = reason or self.scope.folder_reason(child_relative, name, families)
                    if authored(child_relative) and child_reason!='vcs_metadata':child_reason=None
                    if child_reason=='wordpress_deployed_package' and self.include_installed_plugins and name=='plugins':child_reason=None
                    if child_reason in ARCHIVE_REASONS and self.include_archives:
                        child_reason = None
                    if name in OS_SKIP or (child_reason and not (child_reason!='vcs_metadata' and authored_descendant(child_relative))):
                        self.exclusions['dependency_generated_or_system'] += 1
                        continue
                    stack.append((directory / name, depth + 1, rules, parent, tuple(families),child_reason))
            if cache.failures:
                self.issue('unreadable_source_files', root)
        finally:
            cache.close()

    def classify(self, row):
        root = Path(row['path'])
        cache = self.scope.ReadCache(root)
        collected = row.pop('files')
        local_config=self.scope.ScopeConfig(self.scope_config)
        local_config.control=getattr(self.scope_config,'control',None)
        prefix=row['relative_path'].rstrip('/')+'/' if row['relative_path']!='.' else ''
        for key in ('include','exclude','source_roots'):
            local_config[key]=[p[len(prefix):] if prefix and p.startswith(prefix) else p for p in local_config.get(key,[])]
        local_config['roles']={p[len(prefix):] if prefix and p.startswith(prefix) else p:v for p,v in local_config.get('roles',{}).items()}
        local_config['projects']=[{**p,'root':p['root'][len(prefix):] or '.'} for p in local_config.get('projects',[]) if not prefix or p['root'].startswith(prefix)]
        selection = self.scope.Scope(root, respect_gitignore=self.respect_gitignore,config=local_config,
            max_directories=self.limits['max_directories'],max_entries=self.limits['max_entries'],max_depth=self.limits['max_depth'],
            max_read_bytes=max(0,self.limits['max_bytes']-self.stats['bytes_requested'])).build()
        allowed = set(selection.files)
        collected = sorted([p for p in collected if p in allowed],key=lambda p:selection.record(p)['priority'])
        row['scope'] = selection.report()
        from .facets import facets
        row['facets'] = facets(selection,owner='root',max_files=32,max_bytes=max(0,min(262144,self.limits['max_bytes']-self.stats['bytes_requested'])))
        self.stats['bytes_requested']+=selection.cache.bytes_read
        if selection.cache.failures.get('read_budget'):self.issue('content_read_truncated',root)
        if not selection.selection_complete():self.issue('classification_scope_partial',root)
        selection.cache.close()
        example_parts = {'examples', 'example', 'samples', 'sample', 'fixtures', '__fixtures__', 'templates', 'demo_projects'}
        files = [p for p in collected if self.scope.file_role(p.relative_to(root).as_posix())
                 not in {'tests', 'fixture', 'docs'} and not (set(p.relative_to(root).parts[:-1]) & example_parts)]
        row['classification_excluded_paths'] = len(collected) - len(files)
        # Conventional app source before tooling/tests. Read at most 32 x 8 KB per project.
        ordered = sorted(files, key=lambda p: (self.scope.file_role(p.relative_to(root).as_posix())
            not in {'production', 'source', 'unknown'}, len(p.relative_to(root).parts), p.as_posix()))
        names = {p.name.lower(): p for p in files}
        paths = '\n'.join(p.relative_to(root).as_posix().lower() for p in files)
        suffixes = Counter(self.scope.LANGUAGES[p.suffix.lower()] for p in files if p.suffix.lower() in self.scope.LANGUAGES)
        row['languages_sampled'] = dict(suffixes.most_common())
        try:
            root_names = [p.name for p in files if p.parent == root]
            if any(n in {'package.json', 'pyproject.toml', 'Cargo.toml', 'pnpm-workspace.yaml',
                         'settings.gradle', 'settings.gradle.kts'} or n.endswith('.sln') for n in root_names):
                node = self.projects.node_for(root, '.', root_names,
                    lambda p, limit: self.read(cache, p, limit), root=True)
                row['workspace_patterns'] = node['workspace_patterns']
                row['metadata_issues'] = node['unknowns']
            samples = [p for p in ordered if p.suffix.lower() in self.scope.LANGUAGES
                       and self.scope.file_role(p.relative_to(root).as_posix()) not in {'tests', 'fixture', 'docs'}][:32]
            row['source_files_sampled'] = len(samples)
            views = []
            for p in samples:
                try:
                    views.append(code_view(self.read(cache, p, 8192),
                        self.engine['adapters'].language(p.name) or self.scope.LANGUAGES[p.suffix.lower()], self.engine).lower())
                except (ValueError, RecursionError):
                    row['sampling_limited'] = True
            snippets = '\n'.join(views)
            candidates = []
            for ident, profile in self.registry.profiles.items():
                score, evidence = 0, []
                for rule in profile['detection']:
                    kind, value = rule['kind'], rule['value'].lower()
                    matched = False
                    if kind == 'file': matched = value in names
                    elif kind == 'extension': matched = any(p.suffix.lower() == value for p in files)
                    elif kind == 'path': matched = value in paths
                    elif kind == 'text': matched = value in snippets
                    elif kind == 'json_key':
                        name, _, key = rule['value'].partition(':')
                        if name.lower() in names:
                            try:
                                doc = json.loads(self.read(cache, names[name.lower()], 65536))
                                matched = isinstance(doc, dict) and key in doc
                            except (ValueError, RecursionError): pass
                    if matched:
                        score += rule['weight']
                        evidence.append({'kind': kind, 'signal': rule['value'], 'weight': rule['weight']})
                if score:
                    candidates.append({'profile': ident, 'name': profile['name'], 'score': score, 'evidence': evidence})
            # Structured dependencies improve on keyword-only inference (and don't run npm scripts).
            if 'package.json' in names:
                try:
                    package = json.loads(self.read(cache, names['package.json'], 131072))
                    if not isinstance(package, dict): package = {}
                    deps = set()
                    for key in ('dependencies', 'devDependencies', 'peerDependencies'):
                        if isinstance(package.get(key), dict): deps.update(package[key])
                    for profile, selected, weight in [('tauri_electron', {'electron', '@tauri-apps/api', '@tauri-apps/cli'}, 100),
                            ('saas_or_web_app', {'next', 'react', 'vue', 'svelte', 'nuxt', '@angular/core'}, 65),
                            ('api_backend', {'express', 'fastify', '@nestjs/core'}, 80),
                            ('ai_pipeline', {'openai', 'langchain', '@langchain/core', 'ollama'}, 50),
                            ('mcp_agent_server', {'@modelcontextprotocol/sdk'}, 80)]:
                        if deps & selected:
                            target = next((c for c in candidates if c['profile'] == profile), None)
                            if target is None:
                                target = {'profile': profile, 'name': self.registry.profiles[profile]['name'], 'score': 0, 'evidence': []}
                                candidates.append(target)
                            target['score'] += weight
                            target['evidence'].append({'kind': 'dependency_names', 'signal': sorted(deps & selected), 'weight': weight})
                except (ValueError, RecursionError):
                    self.issue('unparseable_package_manifest', root)
            if row.pop('plugin_header'):
                candidates.append({'profile': 'wordpress_plugin', 'name': 'WordPress Plugin', 'score': 130,
                                   'evidence': [{'kind': 'header', 'signal': 'Plugin Name header in plugin directory', 'weight': 130}]})
            if 'wordpress' in row['ecosystems']:
                candidates.append({'profile': 'wordpress_site', 'name': 'WordPress Installation', 'score': 200,
                    'evidence': [{'kind': 'root_layout', 'signal': 'wp-config.php and WordPress directories', 'weight': 200}]})
            for p in files:
                if p.suffix.lower() not in {'.csproj', '.fsproj', '.vbproj'}:
                    continue
                manifest = self.read(cache, p, 131072)
                if re.search(r'<(?:UseWPF|UseWindowsForms)>\s*true\s*</', manifest, re.I):
                    candidates.append({'profile': 'desktop_utility', 'name': self.registry.profiles['desktop_utility']['name'],
                        'score': 110, 'evidence': [{'kind': 'build_metadata', 'signal': 'WPF/Windows Forms enabled', 'weight': 110}]})
                if re.search(r'\bSdk\s*=\s*["\']Microsoft\.NET\.Sdk\.Web["\']', manifest):
                    candidates.append({'profile': 'api_backend', 'name': self.registry.profiles['api_backend']['name'],
                        'score': 90, 'evidence': [{'kind': 'build_metadata', 'signal': 'ASP.NET Web SDK', 'weight': 90}]})
            merged = {}
            for candidate in candidates:
                previous = merged.get(candidate['profile'])
                if previous:
                    previous['score'] += candidate['score']
                    previous['evidence'].extend(candidate['evidence'])
                else:
                    merged[candidate['profile']] = candidate
            candidates = sorted(merged.values(), key=lambda c: (-c['score'], c['profile']))
            for c in candidates:
                c['probability'] = round(min(.95, c['score'] / (c['score'] + 25)), 4)
            generic_only = bool(candidates) and all(e['kind'] == 'file' and e['signal'] == 'package.json'
                                                     for c in candidates for e in c['evidence'])
            best = candidates[0]['probability'] if candidates else 0
            ratio = candidates[1]['score'] / candidates[0]['score'] if len(candidates) > 1 else 0
            unknown = round(min(.95, max(1 - best, .35 * ratio ** 2, .75 if generic_only else .05)), 4)
            unknown_candidate = {'profile': 'unknown_or_general_app', 'name': 'Unclassified / General',
                                 'probability': unknown, 'score': 0, 'evidence': []}
            row['type'] = unknown_candidate if unknown >= best else candidates[0]
            row['alternatives'] = [c for c in candidates if c is not row['type']][:4]
            row['unknown_probability'] = unknown
            row['confidence'] = ('low' if row['type']['profile'] == 'unknown_or_general_app' else
                'high' if row['type']['probability'] >= .85 and not row['sampling_limited'] else
                'medium' if row['type']['probability'] >= .65 else 'low')
            if any(c['profile'] == 'android' for c in candidates):
                row['ecosystems'] = sorted(set(row['ecosystems']) | {'android'})
            row['classification_read_failures'] = sum(cache.failures.values())
            if cache.failures:
                self.issue('unreadable_classification_files', root)
        finally:
            cache.close()

    def run(self, roots):
        for root in roots:
            self.walk(root)
        for row in self.rows:
            try:self.classify(row)
            except (OSError,ValueError):
                self.issue('classification_scope_error',row['path'])
                row.pop('files',None);row.pop('plugin_header',None)
                row.update(type={'profile':'unknown_or_general_app','name':'Unclassified / General','probability':1.0,'score':0,'evidence':[]},alternatives=[],unknown_probability=1.0,confidence='low',sampling_limited=True,languages_sampled={})
        by_path = {r['path']: r for r in self.rows}
        for row in self.rows:
            parent = by_path.get(row['parent_project'])
            if parent:
                relative = Path(row['path']).relative_to(parent['path']).as_posix()
                if any(fnmatch.fnmatchcase(relative, p) for p in parent['workspace_patterns']):
                    row['relationship'] = 'workspace_member'
        for row in self.rows:
            children = [r for r in self.rows if r['parent_project'] == row['path']]
            row['component_types'] = [{'path': r['path'], 'profile': r['type']['profile'],
                                      'relationship': r['relationship']} for r in children]
            # Literal Gradle inclusion + an Android app member is stronger than a generic Gradle marker.
            members = [r for r in children if r['relationship'] == 'workspace_member' and r['type']['profile'] == 'android']
            if row['type']['profile'] == 'unknown_or_general_app' and 'jvm_gradle' in row['ecosystems'] and members:
                probability = min(.7368, max(r['type']['probability'] for r in members))
                row['type'] = {'profile': 'android', 'name': self.registry.profiles['android']['name'],
                    'score': 70, 'probability': probability,
                    'evidence': [{'kind': 'declared_workspace_member', 'signal': r['path'], 'weight': 70} for r in members]}
                row['unknown_probability'] = round(1 - probability, 4)
                row['confidence'] = 'medium'
                row['ecosystems'] = sorted(set(row['ecosystems']) | {'android'})
        files = [p for p in (self.engine['source'] / 'aqaf').rglob('*')
                 if p.is_file() and p.suffix in {'.py', '.json'} and '__pycache__' not in p.parts]
        digest = hashlib.sha256()
        for p in sorted(files):
            digest.update(p.relative_to(self.engine['source']).as_posix().encode() + b'\0' + p.read_bytes())
        return {'schema_version': 1, 'tool_version': TOOL_VERSION,
            'status': 'partial' if self.stats['issues'] else 'complete_within_policy',
            'probability_kind': 'uncalibrated_heuristic_estimate',
            'probability_method': 'Independent profile scores/(scores+25), capped at 0.95; generic package.json alone stays unclassified. Alternatives can overlap and do not sum to one.',
            'root_probability_method': 'Manifest plus direct source: 0.97; manifest or plugin header: 0.90; Git marker: 0.80; source layout only: 0.55. These are estimates, not measured frequencies.',
            'knowledge': {'aqaf_source': str(self.engine['source']), 'aqaf_version': self.engine['version'],
                          'runtime_sha256': digest.hexdigest(), 'profile_count': len(self.registry.profiles),
                          'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                          'prior_predictions_used_as_training_labels': False},
            'policy': {'respect_gitignore': self.respect_gitignore, 'follow_symlinks': False,
                       'execute_target_code': False, 'register_projects': False,
                       'include_archives': self.include_archives,
                       'include_installed_plugins': self.include_installed_plugins, 'exclude': list(self.exclude)},
            'limits': self.limits, 'statistics': dict(self.stats), 'excluded': dict(self.exclusions),
            'issues': self.issues, 'project_count': len(self.rows),
            'projects': sorted(self.rows, key=lambda r: r['path']),
            'limitations': ['Probabilities are heuristic estimates, not measured accuracy or certification.',
                'Nested roots own their evidence; a parent is not classified from dependency/child source.',
                'Source sampling is bounded. Unvisited/ignored/generated/dependency trees are not certified empty.',
                'Lexical masks reduce comment/literal matches; aliases and type binding remain unresolved. Dependencies do not prove runtime use.',
                'Prior scan classifications are context only, not independently verified labels.']}


def render_table(doc):
    lines = [f"Found {doc['project_count']} project folders ({doc['status']}).",
             'Percentages are heuristic estimates, not calibrated probabilities.', '',
             'Root %  Type %  Project type                         Ecosystem / language     Folder']
    for r in doc['projects']:
        stack = ','.join(r['ecosystems'] or list(r['languages_sampled'])[:2]) or 'unknown'
        path = json.dumps(r['path'], ensure_ascii=False)[1:-1]
        lines.append(f"{r['root_probability']:6.0%}  {r['type']['probability']:6.0%}  {r['type']['name'][:35]:35}  {stack[:23]:23}  {path}")
    if doc['issues']:
        lines += ['', f"Partial coverage: {doc['statistics']['issues']} issues/limits; use --format json for details."]
    return '\n'.join(lines) + '\n'



def discover(roots, **options):
    """Passive bounded discovery; probabilities are explicitly uncalibrated."""
    return Finder(load_engine(), **options).run(roots)
