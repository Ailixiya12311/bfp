"""Record final race evidence and distinguish existing classification config from the pending FEC bridge."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next15'
OUT = STAGE / 'verification/r9-next15'
index_path = OUT / 'evidence-index.json'
index = json.loads(index_path.read_text(encoding='utf-8'))
assert index['source_bound_local_fuzz_and_race_pass']
run_id = index['independent_linux_race']['run_id']
assert run_id == 'df694751c362311643bdf98946514c17'
# This only clarifies derived remaining-work metadata; raw gate/race results
# and both earlier failed source manifests retain their original contents.
previous_pending = index['pending'][0]
index['pending'][0] = 'FEC policy integration with existing classification CLI and SOCKS domain metadata; trusted external rule tag/application identity bridge'
index['pending_scope_clarification'] = {
    'previous_text': previous_pending,
    'existing_implementation': ['classification CLI rules', 'administrator-enabled SOCKS target domain metadata'],
    'pending_extension': ['FEC profile selection through CLI/adapter policy', 'external Clash rule tags and application identity'],
    'scope': 'clarifies remaining work; does not change source, raw results or acceptance counts'}
index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

race_link = f'C:/Users/developer/Desktop/bfp/.staging/r9-next15/lab/runs/{run_id}/race-result.json'
index_link = 'C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/evidence-index.json'
completion = (
    f'next15 洛杉矶 source-bound Linux race run `{run_id}` 已通过：17 个包、exit 0、无 DATA RACE 报告，'
    'owned 测试容器和临时目录已删除，receiver 前后快照 `unchanged=true`。'
    '138 个上传源码哈希与 attempt03 冻结清单一致，关联 Linux 二进制元数据匹配，当前源码及 next14 父边界未变。'
    f'见 [race 结果]({race_link}) 与 [最终证据索引]({index_link})。'
    '新加坡/WAN 尚未执行；两次旧 gate 失败仍保留原结论，四类完成数量与三个 false 标记不变。'
)
updates = [
    ('docs/数据报纠错与能力协商-r9-next15.md',
     'next15 洛杉矶 source-bound Linux race 已启动，当前尚无结论；没有 next15 新加坡上传或 WAN 业务场景，next14 的通过不继承到 next15。',
     completion + ' next14 的通过不继承到 next15。'),
    ('docs/BFP协议技术文档-v0.1-r9.md',
     'next15 洛杉矶 source-bound Linux race 已启动、尚无结论，新加坡/WAN 尚未执行；两次旧 gate 失败不改，历史通过不继承到新源码。',
     completion + ' 历史通过不继承到新源码。'),
    ('docs/实现进度.md',
     'next15 洛杉矶 source-bound Linux race 执行中、尚无结论，新加坡/WAN 尚未执行；本地通过不改变前两次失败及整体未验收状态。',
     completion),
]
for relative, old, new in updates:
    path = ROOT / relative
    current = path.read_text(encoding='utf-8')
    if current.count(old) != 1:
        raise RuntimeError(f'expected exactly one progress passage: {relative}')
    path.write_text(current.replace(old, new), encoding='utf-8')
    print(json.dumps({'path': relative, 'updated': True}), flush=True)
print(json.dumps({'race_run_id': run_id, 'evidence_index': str(index_path), 'source_bound_checks_pass': True}), flush=True)
