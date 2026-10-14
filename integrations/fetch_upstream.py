"""Fetch exact native adapter development sources without touching servers."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    'mihomo': ('MetaCubeX/mihomo', '88dcbf7f1614a67c3b36b848ee3592dfa92ada36'),
    'sing-box': ('SagerNet/sing-box', 'af6e64c3b69e6132ebaee0e1a3d24e93903f6709'),
}


def fetch(project):
    repository, commit = PINS[project]
    output = ROOT / '.staging/native-upstream' / (project + '-' + commit)
    evidence = ROOT / 'integrations' / project / 'upstream-source'
    evidence.mkdir(parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    archive = evidence / 'source.tar.gz'
    url = 'https://codeload.github.com/' + repository + '/tar.gz/' + commit
    report = {'project': project, 'repository': repository, 'commit': commit,
              'url': url, 'checkout': str(output), 'pass': False,
              'build': 'not_run', 'remote_hosts': 'not_contacted'}
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'BFP-native-development'})
        with urllib.request.urlopen(request, timeout=30) as response, archive.open('xb') as target:
            total = 0
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 24 * 1024 * 1024:
                    raise RuntimeError('upstream archive exceeds bounded download')
                target.write(chunk)
        report['archive_bytes'] = archive.stat().st_size
        report['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
        files = []
        extracted_bytes = 0
        with tarfile.open(archive, 'r:gz') as source:
            members = source.getmembers()
            if len(members) > 20000:
                raise RuntimeError('upstream archive exceeds bounded member count')
            for member in members:
                parts = PurePosixPath(member.name).parts
                if len(parts) < 1 or parts[0] != project + '-' + commit or '..' in parts or member.issym() or member.islnk():
                    raise RuntimeError('invalid upstream archive member')
                if member.isdir():
                    continue
                if not member.isfile() or member.size > 8 * 1024 * 1024:
                    raise RuntimeError('unsupported or oversized upstream file')
                relative = Path(*parts[1:])
                destination = output / relative
                if not destination.resolve().is_relative_to(output.resolve()):
                    raise RuntimeError('archive target outside development checkout')
                extracted_bytes += member.size
                if extracted_bytes > 128 * 1024 * 1024:
                    raise RuntimeError('upstream extraction exceeds bounded total')
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as reader, destination.open('xb') as writer:
                    shutil.copyfileobj(reader, writer)
                files.append({'path': relative.as_posix(), 'bytes': member.size,
                              'sha256': hashlib.sha256(destination.read_bytes()).hexdigest()})
        report['file_count'] = len(files)
        report['extracted_bytes'] = extracted_bytes
        (evidence / 'source-manifest.json').write_text(json.dumps(files, indent=2) + '\n', encoding='utf-8')
        cached = ROOT / 'integrations/native-source-evidence' / project / commit
        checks = [{'path': p.relative_to(cached).as_posix(),
                   'match': (output / p.relative_to(cached)).read_bytes() == p.read_bytes()}
                  for p in sorted(cached.rglob('*.go'))]
        if not checks or not all(row['match'] for row in checks):
            raise RuntimeError('checkout disagrees with pinned upstream API evidence')
        report['pinned_api_comparison'] = checks
        report['pass'] = True
    except Exception as error:
        report['error_type'] = type(error).__name__
        report['error'] = str(error)
    finally:
        (evidence / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report), flush=True)
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', choices=PINS)
    raise SystemExit(fetch(parser.parse_args().project))
