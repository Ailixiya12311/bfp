"""Run the authorized Singapore -> Los Angeles protocol WAN matrix.

Uses only run-owned binaries, files and processes. UDP failures are introduced
by the owned relay; firewall/routes and existing services are never modified.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import pathlib
import secrets
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from remote import Remote, RemoteRun, LabError, SANITIZER, WORKSPACE, load_hosts, new_run_id, write_public, compare_snapshots


def credentials():
    def pair():
        key = X25519PrivateKey.generate()
        return base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode(), base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    server_private, server_public = pair()
    client_private, client_public = pair()
    admit = base64.b64encode(secrets.token_bytes(32)).decode()
    server = {'admission': admit, 'private': server_private, 'public': server_public, 'allowed_clients': [client_public]}
    client = {'admission': admit, 'private': client_private, 'public': client_public, 'server_public': server_public}
    SANITIZER.config({'credentials': server})
    SANITIZER.config({'credentials': client})
    return server, client


def free_port(remote, start, bind_address):
    return remote.python("""import socket,json
port=None
for candidate in range(%r,%r):
    sockets=[]
    try:
        for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
            sock=socket.socket(socket.AF_INET,kind);sockets.append(sock);sock.bind((%r,candidate))
        port=candidate;break
    except OSError:pass
    finally:
        for sock in sockets:sock.close()
if port is None:raise RuntimeError('no available owned lab port')
print(json.dumps({'port':port}))
""" % (start,start+30,bind_address))['port']


def json_lines(text):
    rows = []
    for line in text.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def target_opens(run):
    rows = json_lines(run.read('fixture.log'))
    return max((item.get('opened',0) for item in rows if item.get('event')=='target_open'), default=0)


def wait_result(run, name, timeout):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        status = run.remote.python(run._check()+"name=%r\nresult=p/(name+'.result.json')\nmanifest=json.loads((p/(name+'.process.json')).read_text())\nproc=pathlib.Path('/proc')/str(manifest['pid'])\nprint(json.dumps({'result_ready':result.exists(),'process_exists':proc.exists()}))" % name)
        if status['result_ready']:
            return json.loads(run.read(name+'.result.json'))
        if not status['process_exists']:
            raise LabError(f"{name}: probe exited without result; inspect sanitized owned log")
        time.sleep(.5)
    raise LabError(f"{name}: probe exceeded bounded collection deadline")


def random_probe(sender, receiver_ip, port):
    return sender.python(r'''
import socket,secrets,concurrent.futures,json,time
target=(%r,%r)
def tcp(size):
    sock=socket.socket();sock.settimeout(3)
    try:
        sock.connect(target)
        if size:sock.sendall(secrets.token_bytes(size))
        try:
            data=sock.recv(1024)
            return {'transport':'tcp','sent':size,'application_response_bytes':len(data),'closed':not data}
        except socket.timeout:return {'transport':'tcp','sent':size,'application_response_bytes':0,'timeout':True}
        except ConnectionResetError:return {'transport':'tcp','sent':size,'application_response_bytes':0,'reset':True}
    except OSError as e:return {'transport':'tcp','sent':size,'application_response_bytes':0,'connect_error':type(e).__name__}
    finally:sock.close()
rows=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(tcp,[0,1,16,64,128,512,1024,1200]))
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.settimeout(.25)
for size in [0,1,16,64,128,512,1024,1200]*2:sock.sendto(secrets.token_bytes(size),target)
received=0;responses=0;deadline=time.monotonic()+1.5
while time.monotonic()<deadline:
    try:data,_=sock.recvfrom(4096);received+=len(data);responses+=1
    except socket.timeout:pass
sock.close()
rows.append({'transport':'udp','requests':16,'responses':responses,'application_response_bytes':received})
print(json.dumps({'observations':rows,'no_application_response':all(r['application_response_bytes']==0 for r in rows),'tcp_connected':sum('connect_error' not in r for r in rows if r['transport']=='tcp')}))
''' % (receiver_ip,port), timeout=15)


def run_wan(binary, count=50, size=16384, interval='100ms', timeout='60s', ticket_lifecycle=False):
    binary = pathlib.Path(binary).resolve()
    binary_data = binary.read_bytes()
    binary_hash = hashlib.sha256(binary_data).hexdigest()
    run_id = new_run_id()
    output = WORKSPACE/'lab'/'runs'/run_id
    output.mkdir(parents=True,exist_ok=False)
    frozen_binary = output/'bfp-linux-amd64'
    frozen_binary.write_bytes(binary_data)
    del binary_data
    hosts = load_hosts()
    report = {'run_id':run_id,'time_utc':datetime.now(timezone.utc).isoformat(),'binary':str(binary),'binary_sha256':binary_hash,'path':'Singapore sender -> Los Angeles receiver','scope':'bounded prototype WAN matrix; no maturity/security audit claim','scenarios':{},'cleanup':{},'snapshots':{}}
    lifecycle_options = {'ticket_ttl':'12s','ticket_refresh_lead':'8s','ticket_overlap':'6s','max_session_lifetime':'5m'} if ticket_lifecycle else {}
    report['ticket_lifecycle'] = {'enabled':ticket_lifecycle,'options':lifecycle_options,'gate':'each scenario must cross the original 12-second ticket TTL and observe an installed refresh'}
    remotes, runs = {}, {}
    started = time.monotonic()
    try:
        for role,host in hosts.items():
            remotes[role] = Remote(host).connect()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = {pool.submit(remote.snapshot):role for role,remote in remotes.items()}
            for future in concurrent.futures.as_completed(futures):
                report['snapshots'][futures[future]]={'before':future.result()}
        for role, remote in remotes.items():
            run = RemoteRun(remote,run_id)
            run.create()
            runs[role] = run
            report.setdefault('staged',{})[role] = run.upload_binary(frozen_binary)
            if report['staged'][role]['sha256'] != binary_hash:
                raise LabError('staged binary differs from frozen run input')
        receiver,sender = remotes['receiver'],remotes['sender']
        receive_run,send_run = runs['receiver'],runs['sender']
        server_port = free_port(receiver,51880,'0.0.0.0')
        fixture_port = free_port(receiver,19180,'127.0.0.1')
        server_creds,client_creds = credentials()
        receive_run.config('server.json',{'listen':f'0.0.0.0:{server_port}','credentials':server_creds,'policy':{'AllowPrivate':True,'AllowedCIDRs':['127.0.0.0/8'],'AllowedPorts':[fixture_port],'MaxConcurrent':4,'Timeout':10000000000},'max_sessions':4,**({'options':lifecycle_options} if ticket_lifecycle else {})})
        receive_run.start(['fixture','-listen',f'127.0.0.1:{fixture_port}'],name='fixture')
        receive_run.start(['server','-config','server.json','-stats','1s'],name='server')
        report['ports']={'server':server_port,'fixture':fixture_port}
        print(json.dumps({'stage':'server_started','run_id':run_id,'ports':report['ports']}),flush=True)
        for index,(scenario,blackhole) in enumerate([('normal_udp','0s'),('udp_to_tcp','8s'),('initial_udp_blocked','1ns')]):
            relay_port=free_port(sender,19181+index,'127.0.0.1')
            config_name=scenario+'.json'
            send_run.config(config_name,{'server':f'127.0.0.1:{relay_port}','tcp_server':f'{hosts["receiver"].hostname}:{server_port}','credentials':client_creds,'socks':'127.0.0.1:0',**({'options':lifecycle_options} if ticket_lifecycle else {})})
            before_opens=target_opens(receive_run)
            send_run.start(['relay','-listen',f'127.0.0.1:{relay_port}','-target',f'{hosts["receiver"].hostname}:{server_port}','-blackhole-after',blackhole],name=scenario+'-relay')
            send_run.start(['probe','-config',config_name,'-target',f'127.0.0.1:{fixture_port}','-udp-target',f'127.0.0.1:{fixture_port}','-count',str(count),'-size',str(size),'-interval',interval,'-duration',timeout,'-result',scenario+'.result.json'],name=scenario)
            print(json.dumps({'stage':'probe_started','scenario':scenario,'relay_port':relay_port}),flush=True)
            try:
                result=wait_result(send_run,scenario,timeout=85)
                after_opens=target_opens(receive_run)
                initial=result.get('initial',{});final=result.get('final',{})
                udp_ok = result.get('udp_completed')==count and result.get('udp_failed')==0
                continuity = result.get('pass') and result.get('same_session') and after_opens-before_opens==1 and result.get('tcp_completed')==count and udp_ok
                if scenario=='normal_udp':
                    carrier_ok=initial.get('carrier')=='udp' and final.get('carrier')=='udp' and final.get('switches')==0
                elif scenario=='udp_to_tcp':
                    carrier_ok=initial.get('carrier')=='udp' and final.get('carrier')=='tcp' and final.get('switches',0)>=1 and final.get('generation',0)>initial.get('generation',0)
                else:
                    carrier_ok=initial.get('carrier')=='tcp' and final.get('carrier')=='tcp'
                lifecycle_ok = not ticket_lifecycle or (result.get('elapsed_ms',0)>12000 and final.get('ticket_refreshes',0)>=1)
                evidence={'pass':bool(continuity and carrier_ok and lifecycle_ok),'result':result,'target_open_before':before_opens,'target_open_after':after_opens,'one_target_connection':after_opens-before_opens==1,'carrier_expectation_met':carrier_ok,'udp_all_completed':udp_ok,'ticket_lifecycle_gate_met':lifecycle_ok,'relay_blackhole_after':blackhole,'probe_count':count,'probe_bytes':size}
                report['scenarios'][scenario]=evidence
            except Exception as error:
                report['scenarios'][scenario]={'pass':False,'error_type':type(error).__name__,'error':SANITIZER.text(str(error))[:2048]}
            write_public(output/(scenario+'.evidence.json'),report['scenarios'][scenario])
            write_public(output/(scenario+'.probe-log.json'),{'lines':send_run.read(scenario+'.log')})
            print(json.dumps({'stage':'probe_complete','scenario':scenario,'pass':report['scenarios'][scenario].get('pass'),'result':report['scenarios'][scenario].get('result',{})}),flush=True)
        before_probe=target_opens(receive_run)
        report['random_probe']=random_probe(sender,hosts['receiver'].hostname,server_port)
        after_probe=target_opens(receive_run)
        report['random_probe'].update({'target_open_before':before_probe,'target_open_after':after_probe,'no_target_side_effect':before_probe==after_probe})
        report['random_probe']['pass']=report['random_probe']['no_application_response'] and before_probe==after_probe and report['random_probe']['tcp_connected']==8
        write_public(output/'server-log.json',{'lines':receive_run.read('server.log')})
        write_public(output/'fixture-log.json',{'lines':receive_run.read('fixture.log')})
        print(json.dumps({'stage':'random_probe_complete','pass':report['random_probe']['pass']}),flush=True)
    except Exception as error:
        report['error_type']=type(error).__name__
        report['error']=SANITIZER.text(str(error))[:2048]
    finally:
        for role,run in runs.items():
            try:
                transport=run.remote.client.get_transport() if run.remote.client else None
                if transport is None or not transport.is_active():
                    run.remote.close()
                    run.remote.connect()
                report['cleanup'][role]=run.cleanup()
            except Exception as error:
                report['cleanup'][role]={'directory_removed':False,'error_type':type(error).__name__,'error':SANITIZER.text(str(error))[:2048]}
        for role,remote in remotes.items():
            try:
                after=remote.snapshot()
                report['snapshots'].setdefault(role,{})['after']=after
                before=report['snapshots'][role].get('before')
                if before:report['snapshots'][role]['comparison']=compare_snapshots(before,after)
            except Exception as error:
                report['snapshots'].setdefault(role,{})['after_error']=type(error).__name__
            remote.close()
        report['elapsed_seconds']=round(time.monotonic()-started,3)
        report['pass']=len(report['scenarios'])==3 and all(item.get('pass') for item in report['scenarios'].values()) and report.get('random_probe',{}).get('pass') and len(report['cleanup'])==2 and all(item.get('directory_removed') for item in report['cleanup'].values()) and all(item.get('comparison',{}).get('unchanged') for item in report['snapshots'].values())
        write_public(output/'wan-result.json',report)
    return report,output/'wan-result.json'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)
    parser.add_argument('--count',type=int,default=50)
    parser.add_argument('--size',type=int,default=16384)
    parser.add_argument('--interval',default='100ms')
    parser.add_argument('--duration',default='60s')
    parser.add_argument('--ticket-lifecycle',action='store_true',help='require credential refresh across an original 12-second TTL in each WAN scenario')
    args=parser.parse_args()
    try:
        report,path=run_wan(args.binary,args.count,args.size,args.interval,args.duration,args.ticket_lifecycle)
        print(json.dumps({'stage':'complete','pass':report['pass'],'run_id':report['run_id'],'path':str(path),'scenarios':{name:value.get('pass') for name,value in report['scenarios'].items()},'error':report.get('error')},ensure_ascii=False),flush=True)
        return 0 if report['pass'] else 1
    except Exception as error:
        print(json.dumps({'pass':False,'error_type':type(error).__name__,'error':SANITIZER.text(str(error))[:2048]},ensure_ascii=False),flush=True)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
