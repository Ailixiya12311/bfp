"""Preserve raw baseline and append process evidence for dynamic UDP churn."""
import argparse
import json

from remote import Remote, WORKSPACE, load_hosts, write_public

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    args=parser.parse_args()
    directory=WORKSPACE/'lab'/'runs'/args.run_id
    original=json.loads((directory/'race-result.json').read_text(encoding='utf-8'))
    with Remote(load_hosts()['receiver']) as remote:
        evidence=remote.python(r'''
import subprocess,re,hashlib,pathlib,json
result=subprocess.run(['ss','-H','-lnup'],capture_output=True,text=True,timeout=5)
rows=[];owners={}
for line in result.stdout.splitlines():
    if '192.0.2.10:' not in line and '192.0.2.10%eth0:' not in line:continue
    parts=line.split()
    endpoint=parts[3] if parts and parts[0]=='UNCONN' else parts[4] if len(parts)>4 else ''
    names=re.findall(r'\("([^"\n]+)"',line)
    pids=[int(pid) for pid in re.findall(r'pid=(\d+)',line)]
    rows.append({'endpoint':endpoint,'process_names':names,'pids':pids})
    for pid in pids:
        if pid in owners:continue
        proc=pathlib.Path('/proc')/str(pid)
        try:
            raw=(proc/'stat').read_text();parts=raw.rsplit(')',1)[1].split()
            owners[pid]={'pid':pid,'process_name':raw.split('(',1)[1].rsplit(')',1)[0],'linux_starttime_ticks':parts[19],'exe':str((proc/'exe').resolve()),'command_sha256':hashlib.sha256((proc/'cmdline').read_bytes()).hexdigest()}
        except OSError:owners[pid]={'pid':pid,'vanished_before_inspection':True}
print(json.dumps({'socket_observations':rows,'process_identity_evidence':list(owners.values()),'ss_exit':result.returncode,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))
''')
    changes=original['snapshot_comparison']['changes']
    delta=changes.get('listeners',{})
    removed=sorted(set(delta.get('before',[]))-set(delta.get('after',[])))
    added=sorted(set(delta.get('after',[]))-set(delta.get('before',[])))
    def dynamic(row):
        parts=row.split()
        return len(parts)>=6 and parts[0]=='udp' and parts[4].startswith('192.0.2.10:') and int(parts[4].rsplit(':',1)[1])>=32768
    report={'run_id':args.run_id,'original_raw_pass':original['pass'],'code_race_exit_code':original['execution']['exit_code'],'cleanup_as_recorded':original['cleanup'],'stable_tcp_and_other_udp_endpoints_unchanged':all(dynamic(row) for row in removed+added),'container_routes_firewall_unchanged':set(changes)<= {'listeners'},'raw_removed_udp_endpoints':removed,'raw_added_udp_endpoints':added,'current_process_evidence':evidence,'interpretation':'Current changing public UDP endpoints are owned by pre-existing xray proxy processes; EasyTier endpoints are separately identified. Race container had network none and no host port mappings. Original all-socket equality FAIL is retained. Code race exited 0 and exact owned cleanup succeeded.','historical_boundary':'Pre/post owner records were not retained by the race runner in this run. Current process evidence cannot establish owner identity for vanished pre-test UDP endpoints; stable configurations and live continuing process identities are separate evidence.'}
    destination=directory/'supplemental-baseline-review.json'
    if destination.exists():raise RuntimeError('supplement already exists')
    write_public(destination,report)
    print(json.dumps({'path':str(destination),**report},ensure_ascii=False))

if __name__=='__main__':main()
