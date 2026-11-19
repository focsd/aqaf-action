"""Read the set of tracked paths from .git/index without running Git (AQAF-050 follow-up).

A file that Git tracks is part of the public repository even when a later .gitignore pattern matches it
(ignore rules only affect untracked files). Bounded, read-only, no subprocess. Anything unexpected returns
(None, reason) and the scan falls back to applying ignore patterns to every path.
"""
import hashlib
import os
import stat
import struct

MAX_INDEX_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 2000000
GITLINK = 0o160000


def _varint(buf, pos):
    c = buf[pos]
    pos += 1
    value = c & 0x7f
    while c & 0x80:
        c = buf[pos]
        pos += 1
        value = ((value + 1) << 7) | (c & 0x7f)
    return value, pos


def parse(data):
    """Return (tracked_files, tracked_directories) or raise ValueError."""
    if data[:4] != b'DIRC':
        raise ValueError('not_a_git_index')
    version, count = struct.unpack('>II', data[4:12])
    if version not in (2, 3, 4):
        raise ValueError('unsupported_index_version_%d' % version)
    if count > MAX_ENTRIES:
        raise ValueError('index_entry_limit')
    for size, algo in ((20, hashlib.sha1), (32, hashlib.sha256)):
        if len(data) > size and algo(data[:-size]).digest() == data[-size:]:
            hash_size = size
            break
    else:
        raise ValueError('index_checksum_mismatch')
    body_end = len(data) - hash_size
    pos = 12
    files, dirs = set(), set()
    previous = b''
    for _ in range(count):
        start = pos
        pos += 24  # ctime, mtime, dev, ino
        mode = struct.unpack('>I', data[pos:pos + 4])[0]
        pos += 4 + 4 + 4 + 4  # mode, uid, gid, size
        pos += hash_size
        flags = struct.unpack('>H', data[pos:pos + 2])[0]
        pos += 2
        if version >= 3 and flags & 0x4000:
            pos += 2
        if version == 4:
            strip, pos = _varint(data, pos)
            end = data.index(b'\0', pos)
            path = previous[:len(previous) - strip] + data[pos:end]
            pos = end + 1
        else:
            end = data.index(b'\0', pos)
            path = data[pos:end]
            pos = start + (((end + 1 - start) + 7) & ~7)  # NUL-terminated name, padded to 8 bytes
        previous = path
        if pos > body_end:
            raise ValueError('truncated_index')
        if (mode >> 12) == 0o16 or mode == GITLINK:
            continue  # submodule pointer, not a file of this repository
        text = path.decode('utf8', 'surrogateescape')
        files.add(text)
        parts = text.split('/')
        for i in range(1, len(parts)):
            dirs.add('/'.join(parts[:i]))
    # Extensions follow the entries; a split or sparse index holds only part of the list.
    ext = data[pos:body_end]
    while len(ext) >= 8:
        sig, size = ext[:4], struct.unpack('>I', ext[4:8])[0]
        if sig in (b'link', b'sdir'):
            raise ValueError('split_or_sparse_index')
        ext = ext[8 + size:]
    return files, dirs


def read_tracked(root):
    """(files, dirs, status). files and dirs are None when the index is not usable; status says why."""
    git = os.path.join(root, '.git')
    try:
        info = os.lstat(git)
    except OSError:
        return None, None, 'no_git_directory'
    if not stat.S_ISDIR(info.st_mode):
        return None, None, 'git_directory_is_not_a_regular_directory'
    path = os.path.join(git, 'index')
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            return None, None, 'index_is_not_a_regular_file'
        if info.st_size > MAX_INDEX_BYTES:
            return None, None, 'index_too_large'
        with open(path, 'rb') as stream:
            data = stream.read(MAX_INDEX_BYTES + 1)
    except OSError:
        return None, None, 'index_unreadable'
    try:
        files, dirs = parse(data)
    except (ValueError, IndexError, struct.error) as exc:
        return None, None, str(exc)
    return files, dirs, 'index_consulted'
