"""Append-only artifacts, input hash verification, and local stage manifests."""
import csv
import datetime
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read(path):
    path=Path(path)
    if not path.exists() and (path.parent/'labels/storage_manifest.json').exists():
        from scripts.session_storage import SessionStore
        return SessionStore(path.parent).json(path.name)
    return json.loads(Path(path).read_text(encoding='utf-8'))


def rows(path):
    path=Path(path)
    if not path.exists() and (path.parent/'labels/storage_manifest.json').exists():
        from scripts.session_storage import SessionStore
        return SessionStore(path.parent).rows(path.name)
    with Path(path).open(encoding='utf-8') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def sha(path):
    path=Path(path)
    if not path.exists() and (path.parent/'labels/storage_manifest.json').exists():
        from scripts.session_storage import SessionStore
        return hashlib.sha256(SessionStore(path.parent).read_bytes(path.name)).hexdigest()
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)


def save_rows(path, values):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open('x', encoding='utf-8') as stream:
        for value in values:
            stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + '\n')


def save_csv(path, values):
    if not values:
        raise ValueError('Empty CSV has no schema')
    with Path(path).open('x', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(values[0]))
        writer.writeheader()
        writer.writerows(values)


def seal(directory):
    directory = Path(directory)
    paths = sorted(p for p in directory.rglob('*') if p.is_file() and p.name != 'manifest.json')
    save(directory / 'manifest.json', {'created_utc': now(), 'files': {p.relative_to(directory).as_posix(): sha(p) for p in paths}})


def verify(directory):
    directory = Path(directory)
    manifest = read(directory / 'manifest.json')
    for name, expected in manifest['files'].items():
        path = (directory / name).resolve()
        if directory.resolve() not in path.parents or sha(path) != expected:
            raise ValueError('Artifact hash mismatch: ' + name)
    return manifest


def verify_subset(directory, names):
    directory = Path(directory)
    manifest = read(directory / 'manifest.json')['files']
    for name in names:
        if name not in manifest or sha(directory / name) != manifest[name]:
            raise ValueError('Artifact subset hash mismatch: ' + name)
