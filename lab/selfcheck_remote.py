"""Exercise only fresh run-owned staging/cleanup without starting the protocol."""
import concurrent.futures
import json
import secrets

from remote import Remote, RemoteRun, WORKSPACE, SANITIZER, load_hosts, new_run_id, compare_snapshots, write_public


def main():
    hosts = load_hosts()
    run_id = new_run_id()
    result = {'run_id': run_id, 'purpose': 'owned-helper-self-check', 'hosts': {}}

    def exercise(host):
        with Remote(host) as remote:
            before = remote.snapshot()
            run = RemoteRun(remote, run_id)
            report = {'created': run.create()}
            try:
                report['config'] = run.config('helper-test.json', {'run_id': run_id, 'secret': secrets.token_hex(32)})
                # Read existing system executable into our new private directory;
                # no changes to that executable or any existing process/service.
                remote.python(run._check()+"import shutil\nshutil.copyfile('/bin/sleep',p/'sleep')\nos.chmod(p/'sleep',0o700)\nprint(json.dumps({'copied_fixture':True}))")
                report['process'] = run.start(['30'], name='fixture', binary='sleep')
                report['modes'] = remote.python(run._check()+"print(json.dumps({f.name:oct(f.stat().st_mode&0o777) for f in p.iterdir()}))")
                report['sanitized_log'] = run.read('fixture.log')
            finally:
                report['cleanup'] = run.cleanup()
            after = remote.snapshot()
            report['baseline_comparison'] = compare_snapshots(before, after)
            report['pass'] = report['cleanup']['directory_removed'] and report['baseline_comparison']['unchanged']
            return report

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(exercise, host): role for role, host in hosts.items()}
        for future in concurrent.futures.as_completed(futures):
            role = futures[future]
            try:
                result['hosts'][role] = future.result()
            except Exception as error:
                result['hosts'][role] = {'pass': False, 'error_type': type(error).__name__, 'error': SANITIZER.text(str(error))[:2048]}
    result['pass'] = all(host.get('pass') for host in result['hosts'].values())
    output = WORKSPACE/'lab'/'runs'/run_id/'helper-check.json'
    write_public(output, result)
    print(json.dumps({'run_id': run_id, 'pass': result['pass'], 'path': str(output), 'hosts': result['hosts']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
