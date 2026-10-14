"""Read only metadata and sanitized logs of one exact owned run."""
import argparse
import concurrent.futures
import json

from remote import Remote, RemoteRun, load_hosts, SANITIZER


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('--log')
    args=parser.parse_args()
    hosts=load_hosts()
    def inspect(host):
        try:
            with Remote(host) as remote:
                run=RemoteRun(remote,args.run_id)
                data=remote.python(run._check()+"print(json.dumps({f.name:f.stat().st_size for f in p.iterdir()}))")
                if args.log:
                    data['sanitized_log']=run.read(args.log)
                return data
        except Exception as error:
            return {'error_type':type(error).__name__,'error':SANITIZER.text(str(error))[:1024]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures={role:pool.submit(inspect,host) for role,host in hosts.items()}
        print(json.dumps({role:future.result() for role,future in futures.items()},ensure_ascii=False))


if __name__=='__main__':
    main()
