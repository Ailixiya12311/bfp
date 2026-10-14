"""Read bounded upstream source files at the documented native adapter pins."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import json
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'integrations/native-source-evidence'
SOURCES = {
    'mihomo': ('MetaCubeX/mihomo', '88dcbf7f1614a67c3b36b848ee3592dfa92ada36',
               ('constant/adapters.go', 'constant/metadata.go', 'adapter/parser.go',
                'adapter/outbound/base.go', 'adapter/outbound/socks5.go')),
    'sing-box': ('SagerNet/sing-box', 'af6e64c3b69e6132ebaee0e1a3d24e93903f6709',
                 ('adapter/outbound.go', 'adapter/outbound/registry.go', 'include/registry.go',
                  'protocol/socks/outbound.go', 'option/outbound.go', 'option/socks.go',
                  'adapter/inbound.go')),
}


def fetch(job):
    name, repository, revision, path = job
    url = f'https://raw.githubusercontent.com/{repository}/{revision}/{path}'
    record = {'project': name, 'revision': revision, 'path': path, 'url': url}
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'BFP-native-interface-review'})
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read(131073)
            if len(data) > 131072:
                raise ValueError('source exceeds 128 KiB limit')
            data.decode('utf-8')
        target = OUT / name / revision / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as output:
            output.write(data)
        record.update(status='saved', bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    except Exception as error:
        record.update(status='unavailable', error_type=type(error).__name__)
    return record


def main():
    OUT.mkdir(exist_ok=False)
    jobs = [(name, repository, revision, path)
            for name, (repository, revision, paths) in SOURCES.items() for path in paths]
    with ThreadPoolExecutor(max_workers=3) as pool:
        records = list(pool.map(fetch, jobs))
    report = {'scope': 'read-only bounded upstream API inspection; no clone, patch, build or deployment',
              'max_file_bytes': 131072, 'concurrency': 3, 'files': records,
              'native_outbound_implemented': False, 'native_build_verified': False}
    with (OUT / 'source-manifest.json').open('x', encoding='utf-8') as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write('\n')
    print(json.dumps({'path': str(OUT), 'saved': sum(r['status'] == 'saved' for r in records),
                      'unavailable': [{k: r[k] for k in ('project', 'path', 'error_type')}
                                      for r in records if r['status'] != 'saved']}))


if __name__ == '__main__':
    main()
