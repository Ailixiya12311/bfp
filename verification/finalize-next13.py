"""Bind local/race evidence without rewriting frozen gate or historical failures."""
from pathlib import Path
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'.staging/r9-next13'
OUT=STAGE/'verification/r9-next13'
frozen=json.loads((OUT/'local-gate/source-manifest.json').read_text(encoding='utf-8'))
local=json.loads((OUT/'local-gate/local-summary.json').read_text(encoding='utf-8'))
run_id='09a74805d9f86838c7a6b141dc26eded'
run=STAGE/'lab/runs'/run_id
race=json.loads((run/'race-result.json').read_text(encoding='utf-8'))
log=json.loads((run/'race-log.json').read_text(encoding='utf-8'))['text']
expected=frozen['source_manifest']
race_rows=[{'path':r['path'],'sha256':r['sha256']}for r in race['source_manifest']]
actual=[STAGE/'go.mod',STAGE/'go.sum']
for directory in ('adapter','classification','cmd','gateway','internal','obfuscation','protocol','scheduler','security','session','tests'):
    actual.extend((STAGE/directory).rglob('*.go'))
live=[{'path':p.relative_to(STAGE).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in sorted(actual)]
binary=next(b for b in local['binaries']if b['platform']=='linux')
report={
    'revision':'v0.1-r9-next13','source_manifest_sha256':frozen['manifest_sha256'],
    'source_file_count':len(expected),'source_unchanged_after_race':live==expected,
    'race_source_matches_local_manifest':race_rows==expected,
    'race_related_binary_matches':race['related_binary_sha256']==binary['sha256'],
    'local_checks_pass':local['local_checks_pass'],'local_packages_passed':local['checks']['go_test']['packages_passed'],
    'local_top_level_tests_passed':local['checks']['go_test']['top_level_tests_passed'],
    'independent_linux_race':{'run_id':run_id,'strict_pass':race['pass'],'program_exit_code':race['execution']['exit_code'],
       'packages_passed':len(re.findall(r'^ok\s+',log,re.MULTILINE)), 'race_report_present':'DATA RACE'in log,
       'owned_container_removed':race['execution']['owned_container_removed'],'owned_directory_removed':race['cleanup']['directory_removed'],
       'snapshot_unchanged':race['snapshot_comparison']['unchanged'],'result_path':str(run/'race-result.json')},
    'wan':{'status':'not_run','singapore_transfer_or_business':'none_in_this_revision'},
    'four_categories':{'core_implemented':2,'partially_implemented':2,'finally_accepted':0},
    'acceptance_complete':False,'production_ready':False,'released':False,
    'pending':['closed Session queue/backend/reader reference retirement','shared Server UDP strict write wall-clock boundary','complete close/recovery/READY matrix','original 8s UDP recovery stability','classification WAN/fairness/reliability/FEC','client DNS/fake-IP/TUN/IPv6','independent security review'],
}
report['source_bound_local_and_race_pass']=all((report['source_unchanged_after_race'],report['race_source_matches_local_manifest'],report['race_related_binary_matches'],report['local_checks_pass'],race['pass']))
with (OUT/'evidence-index.json').open('x',encoding='utf-8')as output: output.write(json.dumps(report,indent=2)+'\n')
print(json.dumps(report),flush=True)

