"""Extract switch timeline without inventing missing per-message outcomes."""
import argparse
import json

from remote import WORKSPACE, owned_dir, write_public
from wan import json_lines

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    args=parser.parse_args()
    owned_dir(args.run_id)
    directory=WORKSPACE/'lab'/'runs'/args.run_id
    evidence=json.loads((directory/'udp_to_tcp.evidence.json').read_text(encoding='utf-8'))
    result=evidence['result']
    sid=result['initial']['session_id']
    probe=json_lines(json.loads((directory/'udp_to_tcp.probe-log.json').read_text(encoding='utf-8'))['lines'])
    progress=[row for row in probe if row.get('event')=='progress']
    failed_udp=[]
    for row in progress:
        observation=row.get('udp')
        if isinstance(observation,dict) and observation.get('success') is False:
            before,after=observation.get('carrier_before'),observation.get('carrier_after')
            phase='tcp_before_and_after' if before==after=='tcp' else 'udp_before_and_after' if before==after=='udp' else 'carrier_changed_during_operation'
            failed_udp.append({'iteration':row['iteration'],'elapsed_since_probe_ms':row.get('elapsed_since_probe_ms'),'phase_observation':phase,'udp':observation})
    def compact(row):
        session=row['session']
        return {'iteration':row['iteration'],'elapsed_since_probe_ms':row.get('elapsed_since_probe_ms'),'udp':row.get('udp'),'carrier':session['carrier'],'generation':session['generation'],'retransmissions':session['retransmissions'],'dropped':session['dropped'],'tx_buffered':session['tx_buffered'],'rx_buffered':session['rx_buffered']}
    first_tcp=next((row['iteration'] for row in progress if row['session']['carrier']=='tcp'),None)
    nearby=[compact(row) for row in progress if first_tcp is None or first_tcp-3<=row['iteration']<=first_tcp+2]
    if progress and progress[-1]['iteration'] not in [row['iteration'] for row in nearby]:nearby.append(compact(progress[-1]))
    server=json_lines(json.loads((directory/'server-log.json').read_text(encoding='utf-8'))['lines'])
    samples=[]
    for index,row in enumerate(server):
        for session in row.get('sessions') or []:
            if session.get('session_id')==sid:samples.append({'server_log_line_index_zero_based':index,**{key:session[key] for key in ('carrier','generation','retransmissions','dropped','tx_buffered','rx_buffered')}})
    first_server_tcp=next((index for index,row in enumerate(samples) if row['carrier']=='tcp'),None)
    server_nearby=samples[max(0,(first_server_tcp or 0)-4):(first_server_tcp or 0)+3]
    observations_present=all(isinstance(row.get('udp'),dict) for row in progress) and len(failed_udp)==result['udp_failed']
    reason=('New probe telemetry identifies unsuccessful UDP operations and their observed carrier/generation before and after. Those endpoint observations do not prove frame delivery, exact relay loss instant, or target processing. An operation crossing the carrier change cannot be assigned a precise loss phase.' if observations_present else 'Progress records lack complete per-iteration UDP outcomes. The failed message cannot be reliably assigned to an iteration or pre/post TCP recovery from these existing logs.')
    report={'run_id':args.run_id,'binary_sha256':json.loads((directory/'wan-result.json').read_text(encoding='utf-8'))['binary_sha256'],'scenario_pass':evidence['pass'],'tcp_completed':result['tcp_completed'],'udp_completed':result['udp_completed'],'udp_failed':result['udp_failed'],'client_first_tcp_progress_iteration':first_tcp,'client_near_switch':nearby,'server_near_switch':server_nearby,'failed_udp_operations':failed_udp,'per_iteration_udp_observations_complete':observations_present,'can_locate_failed_operation':observations_present,'reason':reason,'counter_boundary':'Dropped is a local protocol counter, not a proof that no datagram was lost in the relay or network. The relay deliberately discards traffic and does not emit per-message records.'}
    destination=directory/'udp-failure-analysis.json'
    if destination.exists():raise RuntimeError('analysis already exists; preserve evidence')
    write_public(destination,report)
    print(json.dumps({'path':str(destination),**report},ensure_ascii=False))

if __name__=='__main__':main()
