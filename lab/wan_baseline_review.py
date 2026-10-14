"""Append raw socket delta attribution from saved pre/post owner records."""
import argparse
import json
import re

from remote import WORKSPACE, write_public

def normalize(row):return re.sub(r'users:.*$','',row).strip()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('--kind',choices=['wan','race'],default='wan')
    args=parser.parse_args()
    folder=WORKSPACE/'lab'/'runs'/args.run_id
    original=json.loads((folder/(args.kind+'-result.json')).read_text(encoding='utf-8'))
    reviews={}
    for role,item in original['snapshots'].items():
        changes=item['comparison']['changes']
        before={normalize(row):row for row in item['before']['snapshot']['listeners']}
        after={normalize(row):row for row in item['after']['snapshot']['listeners']}
        observations=[]
        for side,rows in [('removed',sorted(set(before)-set(after))),('added',sorted(set(after)-set(before)))]:
            raw=before if side=='removed' else after
            for row in rows:
                owner=raw[row]
                fields=row.split()
                observations.append({'change':side,'socket':row,'process_names':re.findall(r'\("([^"\n]+)"',owner),'pids':[int(value) for value in re.findall(r'pid=(\d+)',owner)],'public_udp_highport':len(fields)>=6 and fields[0]=='udp' and fields[4].startswith('192.0.2.10:') and int(fields[4].rsplit(':',1)[1])>=32768})
        identified=all(row['public_udp_highport'] and row['process_names']==['xray'] for row in observations)
        reviews[role]={'raw_baseline_unchanged':item['comparison']['unchanged'],'change_keys':sorted(changes),'socket_deltas_with_saved_owners':observations,'all_changed_sockets_existing_xray_dynamic_udp':identified,'stable_tcp_fixed_udp_container_routes_firewall':set(changes)<= {'listeners'} and identified,'full_before_after_snapshots_saved':True}
    cleanup=all(item.get('directory_removed') for item in original['cleanup'].values()) if args.kind=='wan' else original['cleanup'].get('directory_removed')
    code=all(item['pass'] for item in original['scenarios'].values()) and original['random_probe']['pass'] if args.kind=='wan' else original['execution'].get('exit_code')==0 and original['execution'].get('owned_container_removed')
    report={'run_id':args.run_id,'kind':args.kind,'binary_sha256':original.get('binary_sha256',original.get('related_binary_sha256')),'raw_original_pass':original['pass'],'code_checks_pass':code,'exact_owned_cleanup_complete':cleanup,'host_baseline_reviews':reviews,'supplemental_review_confirms_stable_services_and_config':all(item['stable_tcp_fixed_udp_container_routes_firewall'] for item in reviews.values()),'interpretation':'Raw all-socket equality gate remains unchanged and false when existing Xray UDP egress sockets churn. Saved before/after ss records identify every changed UDP socket owner; stable TCP/fixed UDP endpoints, containers, default routes and firewall configuration are evaluated separately. This supplemental review does not rewrite raw PASS/FAIL or establish long-term reliability/security.'}
    destination=folder/'supplemental-baseline-review.json'
    if destination.exists():raise RuntimeError('preserve existing supplemental review')
    write_public(destination,report)
    print(json.dumps({'path':str(destination),**report},ensure_ascii=False))

if __name__=='__main__':main()
