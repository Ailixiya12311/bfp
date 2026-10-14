"""Recover cleanup of only one exact owned run after an SSH interruption."""
import argparse
import json

from remote import Remote, RemoteRun, WORKSPACE, SANITIZER, load_hosts, compare_snapshots, write_public

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('--role',choices=['receiver','sender'],required=True)
    args=parser.parse_args()
    output=WORKSPACE/'lab'/'runs'/args.run_id
    previous=json.loads((output/'wan-result.json').read_text(encoding='utf-8'))
    before=previous['snapshots'][args.role]['before']
    with Remote(load_hosts()[args.role]) as remote:
        run=RemoteRun(remote,args.run_id)
        cleanup=run.cleanup()
        after=remote.snapshot()
    report={'run_id':args.run_id,'role':args.role,'cleanup':cleanup,'snapshot_comparison':compare_snapshots(before,after),'previous_attempt_pass':previous['pass']}
    write_public(output/'cleanup-recovery.json',report)
    print(json.dumps(report,ensure_ascii=False))

if __name__=='__main__':main()
