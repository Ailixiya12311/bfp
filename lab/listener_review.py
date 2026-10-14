"""Read-only service/ephemeral socket review; retain original strict baseline."""
import argparse
import json
import re

from remote import Remote, WORKSPACE, load_hosts, write_public

def endpoint(row):
    parts=row.split()
    if len(parts)<6:return None
    return parts[4]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    args=parser.parse_args()
    folder=WORKSPACE/'lab'/'runs'/args.run_id
    original=json.loads((folder/'race-result.json').read_text(encoding='utf-8'))
    change=original['snapshot_comparison']['changes'].get('listeners',{})
    before,after=set(change.get('before',[])),set(change.get('after',[]))
    removed=sorted(before-after)
    added=sorted(after-before)
    changed_endpoints={endpoint(row) for row in removed+added}
    with Remote(load_hosts()['receiver']) as remote:
        snapshot=remote.snapshot()
    observations=[]
    for row in snapshot['snapshot']['listeners']:
        if row.startswith('udp ') and ('192.0.2.10:' in row or '192.0.2.10%eth0:' in row):
            observations.append({'endpoint':endpoint(row),'process_names':re.findall(r'\("([^"\n]+)"',row),'changed_endpoint_present':endpoint(row) in changed_endpoints})
    result={'run_id':args.run_id,'original_race_pass':original['pass'],'original_test_exit_code':original['execution']['exit_code'],'original_strict_baseline_unchanged':original['snapshot_comparison']['unchanged'],'removed_sockets':removed,'added_sockets':added,'current_udp_owner_observations':observations,'tcp_listener_change':any(row.startswith('tcp ') for row in removed+added),'configuration_change_keys':sorted(original['snapshot_comparison']['changes']),'container_network':'none','limitation':'The race report did not retain full pre/post ss owner records; current process attribution does not independently establish ownership of already vanished pre-test UDP endpoints. Raw strict baseline FAIL is retained unchanged.'}
    write_public(folder/'listener-review.json',result)
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
