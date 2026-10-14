"""Append explicit related-hash correction without overwriting race evidence."""
import argparse
import hashlib
import json

from remote import WORKSPACE, owned_dir, write_public

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--binary',required=True)
    args=parser.parse_args()
    owned_dir(args.run_id)
    output=WORKSPACE/'lab'/'runs'/args.run_id
    report=json.loads((output/'race-result.json').read_text(encoding='utf-8'))
    actual=hashlib.sha256(__import__('pathlib').Path(args.binary).read_bytes()).hexdigest()
    mismatches=[]
    for item in report['source_manifest']:
        path=WORKSPACE/item['path']
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:mismatches.append(item['path'])
    original=report['related_binary_sha256']
    correction={'run_id':args.run_id,'original_related_binary_sha256':original,'original_length':len(original),'actual_binary_sha256':actual,'actual_length':len(actual),'source_files_checked':len(report['source_manifest']),'all_frozen_source_matches_current':not mismatches,'source_mismatches':mismatches,'race_pass_as_recorded':report['pass'],'interpretation':'Race validates the separately frozen source manifest. The malformed originally supplied related binary hash is metadata and is not binary identity evidence. Original race report is retained unchanged.'}
    destination=output/'lineage-correction.json'
    if destination.exists():raise RuntimeError('correction already exists; do not overwrite evidence')
    write_public(destination,correction)
    print(json.dumps({'path':str(destination),**correction},ensure_ascii=False))

if __name__=='__main__':main()
