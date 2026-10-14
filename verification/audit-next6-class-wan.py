"""Independently audit collected next6 WAN evidence; never run remote commands.

Only class-wan-independent-audit.json is written. The runner's original result
and logs remain authoritative and unchanged, including every failed scene.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next6'
SCENES = ('normal_udp', 'udp_to_tcp', 'initial_udp_blocked')
SOURCE_DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal',
               'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')
EXPECTED_BINARY = '2583677700803cbabbbdf986454844a38fcd1512ba1e9a15e780c14e4de5df86'
EXPECTED_MANIFEST = '055490ea2724f05796e24d2654236dcb6bdb4126e64125535d50c86865d3ce8e'
PROFILE = 'class-announcement-v1'
COUNT, SIZE, UNIQUE = 50, 4096, 50 * 4096
PROBE_GATES = {'initial_both_normal', 'initial_local_exact_ack', 'both_bulk_seen',
               'both_restored_normal', 'local_final_exact_ack', 'versions_advance',
               'local_unique_bytes_exact', 'echo_bytes_exact', 'same_session',
               'same_local_flow', 'no_terminal_flow', 'idle_adds_no_business_bytes', 'deadline_met'}
MAX_JSON_BYTES, MAX_LOG_BYTES, MAX_LINE_BYTES = 16 << 20, 4 << 20, 256 << 10
MAX_ISSUES = 64


class EvidenceError(ValueError):
    pass


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise EvidenceError('duplicate_json_key')
        out[key] = value
    return out


def _constant(_value):
    raise EvidenceError('nonfinite_json_number')


def strict_json(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def positive(value):
    return type(value) is int and value > 0


def uint(value):
    return type(value) is int and value >= 0


def obj(value):
    return value if isinstance(value, dict) else {}


def load_document(path, issues, input_hashes):
    """Keep errors bounded and content-free; never print untrusted log strings."""
    name = path.name
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise EvidenceError('document_byte_budget_exceeded')
        data = path.read_bytes()
        input_hashes[name] = {'bytes': len(data), 'sha256': sha256(data)}
        value = strict_json(data.decode('utf-8', errors='strict'))
        if not isinstance(value, dict):
            raise EvidenceError('document_root_not_object')
        return value
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        issues.append({'file': name, 'error_type': type(error).__name__,
                       'reason': str(error) if isinstance(error, EvidenceError) else 'document_read_or_parse_failed'})
        return {}


def parse_log(document, filename, expected_terminal_error=None):
    text = document.get('lines')
    result = {'file': filename, 'pass': False, 'line_count': 0, 'json_rows': 0,
              'blank_lines': 0, 'malformed_count': 0, 'issues': [], 'issues_truncated': False,
              'complete_newline': False, 'expected_terminal_error_count': 0}
    rows = []
    if not isinstance(text, str):
        result['reason'] = 'missing_lines_string'
        return rows, result
    encoded = text.encode('utf-8')
    result.update(bytes=len(encoded), sha256=sha256(encoded), complete_newline=text.endswith('\n'))
    if len(encoded) > MAX_LOG_BYTES:
        result['reason'] = 'log_byte_budget_exceeded'
        return rows, result
    lines = text.splitlines()
    last_nonblank = max((n for n, line in enumerate(lines, 1) if line.strip()), default=0)
    for number, line in enumerate(lines, 1):
        result['line_count'] = number
        if not line.strip():
            result['blank_lines'] += 1
            continue
        try:
            if len(line.encode('utf-8')) > MAX_LINE_BYTES:
                raise EvidenceError('line_byte_budget_exceeded')
            value = strict_json(line)
            if not isinstance(value, dict):
                raise EvidenceError('log_row_not_object')
            rows.append((number, value))
            result['json_rows'] += 1
        except (ValueError, RecursionError) as error:
            if expected_terminal_error and number == last_nonblank and line == expected_terminal_error:
                # Frozen main prints this one error to stderr after the JSON
                # failure result. A whitelist never masks arbitrary malformed rows.
                result['expected_terminal_error_count'] += 1
                continue
            result['malformed_count'] += 1
            if len(result['issues']) < MAX_ISSUES:
                result['issues'].append({'line': number, 'error_type': type(error).__name__,
                    'reason': str(error) if isinstance(error, EvidenceError) else 'invalid_json',
                    'line_sha256': sha256(line.encode('utf-8'))})
            else:
                result['issues_truncated'] = True
    # emit writes complete JSON lines. A partial final line is not ignored.
    result['pass'] = result['malformed_count'] == 0 and result['json_rows'] > 0 and result['complete_newline']
    return rows, result


def source_binding(report, run_dir, issues, inputs):
    manifest_path = STAGE / 'verification/r9-next6/local-gate/source-manifest.json'
    summary_path = STAGE / 'verification/r9-next6/local-gate/local-summary.json'
    manifest = load_document(manifest_path, issues, inputs)
    summary = load_document(summary_path, issues, inputs)
    rows = manifest.get('source_manifest')
    valid_rows = isinstance(rows, list) and len(rows) == 98
    calculated = ''
    current = []
    mismatches = []
    if valid_rows:
        calculated = sha256((json.dumps(rows, sort_keys=True, indent=2) + '\n').encode())
        seen = set()
        for row in rows:
            relative = obj(row).get('path')
            digest = obj(row).get('sha256')
            if not isinstance(relative, str) or not isinstance(digest, str):
                valid_rows = False
                continue
            pure = PurePosixPath(relative)
            if pure.is_absolute() or '..' in pure.parts or '\\' in relative or relative in seen:
                valid_rows = False
                continue
            seen.add(relative)
            try:
                path = STAGE.joinpath(*pure.parts)
                if path.resolve().is_relative_to(STAGE.resolve()) is False or path.is_symlink():
                    raise EvidenceError('source_path_unsafe')
                actual = sha256(path.read_bytes())
                current.append({'path': relative, 'sha256': actual})
                if actual != digest:
                    mismatches.append(relative)
            except (OSError, EvidenceError):
                mismatches.append(relative)
        actual_paths = {p.relative_to(STAGE).as_posix() for d in SOURCE_DIRS for p in (STAGE / d).rglob('*.go')}
        actual_paths.update(('go.mod', 'go.sum'))
        mismatches.extend(sorted(actual_paths.symmetric_difference(seen)))
    binaries = summary.get('binaries', [])
    summary_binary = next((x.get('sha256') for x in binaries if isinstance(x, dict) and x.get('platform') == 'linux'), None)
    frozen_path = run_dir / 'bfp-linux-amd64'
    try:
        frozen_data = frozen_path.read_bytes()
        frozen_digest = sha256(frozen_data)
        elf = frozen_data[:4] == b'\x7fELF'
        inputs[frozen_path.name] = {'bytes': len(frozen_data), 'sha256': frozen_digest}
    except OSError:
        frozen_digest, elf = '', False
        issues.append({'file': frozen_path.name, 'reason': 'frozen_binary_missing'})
    gates = {
        'manifest_schema': valid_rows,
        'manifest_digest_matches_fixed_revision': calculated == manifest.get('manifest_sha256') == EXPECTED_MANIFEST,
        'source_files_unchanged': valid_rows and not mismatches and len(current) == 98,
        'local_build_provenance_matches_manifest': summary.get('source_manifest_sha256') == EXPECTED_MANIFEST and summary.get('source_unchanged') is True and obj(obj(summary.get('checks')).get('build_linux')).get('pass') is True,
        'local_build_binary_digest': summary_binary == EXPECTED_BINARY,
        'run_binary_digest': report.get('binary_sha256') == frozen_digest == EXPECTED_BINARY,
        'run_binary_elf': elf,
    }
    return {'gates': gates, 'pass': all(gates.values()), 'source_manifest_sha256': calculated,
            'frozen_binary_sha256': frozen_digest, 'source_mismatches': mismatches[:MAX_ISSUES],
            'source_mismatch_count': len(mismatches),
            'provenance_boundary': 'Hashes bind collected run artifact and current source to the frozen local build record; this audit does not independently rebuild the binary.'}


def exact_ack(view):
    view = obj(view)
    version = view.get('TXVersion')
    return (positive(version) and positive(view.get('TXPublishedVersion'))
            and positive(view.get('TXAckedVersion')) and view.get('TXPublishedVersion') == version
            and view.get('TXAckedVersion') == version and view.get('TXPending') is False)


def valid_view(view, flow):
    view = obj(view)
    local, peer = obj(view.get('LocalTX')), obj(view.get('PeerTX'))
    return (positive(flow) and positive(view.get('ID')) and view.get('ID') == flow and view.get('Network') == 'tcp'
            and view.get('Terminal') is False and exact_ack(view)
            and type(local.get('Class')) is int and local.get('Class') in (0, 1, 2)
            and uint(local.get('TotalBytes')) and peer.get('Known') is True
            and positive(peer.get('Version')) and type(peer.get('Class')) is int
            and peer.get('Class') in (0, 1, 2))


def paired(local, server, flow):
    return (valid_view(local, flow) and valid_view(server, flow)
            and server['LocalTX']['Class'] == local['PeerTX']['Class']
            and server['TXVersion'] == local['PeerTX']['Version']
            and server['PeerTX']['Class'] == local['LocalTX']['Class']
            and server['PeerTX']['Version'] == local['TXVersion'])


def server_samples(rows, sid, flow):
    samples, schema_issues = [], []
    failed_snapshots = 0
    for line, row in rows:
        if row.get('event') != 'stats':
            continue
        sessions, classes = row.get('sessions'), row.get('classifications')
        if not isinstance(sessions, list):
            schema_issues.append({'line': line, 'reason': 'stats_sessions_not_array'})
            continue
        states = [state for state in sessions if isinstance(state, dict) and state.get('session_id') == sid]
        if row.get('classification_snapshot_ok') is not True:
            failed_snapshots += 1
            continue
        if not isinstance(classes, dict):
            schema_issues.append({'line': line, 'reason': 'classifications_not_object'})
            continue
        if sid not in classes:
            continue
        views = classes[sid]
        if views is None:
            # FlowClassifications returns a nil Go slice for a retained Session
            # with no live flow. JSON null is an empty view, not a flow sample.
            continue
        if not isinstance(views, list):
            schema_issues.append({'line': line, 'reason': 'session_classifications_not_array'})
            continue
        selected = [view for view in views if isinstance(view, dict) and view.get('ID') == flow]
        if not selected:
            continue
        if len(states) != 1 or len(selected) != 1:
            schema_issues.append({'line': line, 'reason': 'sample_missing_or_ambiguous_session_flow'})
            continue
        state = states[0]
        if not positive(state.get('generation')) or state.get('carrier') not in ('udp', 'tcp'):
            schema_issues.append({'line': line, 'reason': 'sample_invalid_runtime_scope'})
            continue
        samples.append({'line': line, 'runtime': state, 'view': selected[0]})
    return samples, {'schema_issue_count': len(schema_issues), 'issues': schema_issues[:MAX_ISSUES],
                     'snapshot_failure_count': failed_snapshots, 'matched_flow_samples': len(samples)}


def sample_ref(sample):
    """Only bounded diagnostic fields are copied into public audit evidence."""
    state, view = sample['runtime'], sample['view']
    return {'server_log_line': sample['line'], 'session_id': state.get('session_id'),
            'generation': state.get('generation'), 'carrier': state.get('carrier'),
            'flow_id': view.get('ID'), 'tx_version': view.get('TXVersion'),
            'tx_published_version': view.get('TXPublishedVersion'), 'tx_acked_version': view.get('TXAckedVersion'),
            'tx_pending': view.get('TXPending'), 'local_class': obj(view.get('LocalTX')).get('Class'),
            'local_unique_bytes': obj(view.get('LocalTX')).get('TotalBytes'),
            'peer_known': obj(view.get('PeerTX')).get('Known'),
            'peer_version': obj(view.get('PeerTX')).get('Version'),
            'peer_class': obj(view.get('PeerTX')).get('Class')}


def carrier_ok(scene, initial, final):
    if scene == 'normal_udp':
        return initial.get('carrier') == final.get('carrier') == 'udp' and final.get('switches') == 0
    if scene == 'udp_to_tcp':
        return (initial.get('carrier') == 'udp' and final.get('carrier') == 'tcp'
                and positive(initial.get('generation')) and positive(final.get('generation'))
                and final['generation'] > initial['generation'] and positive(final.get('switches')))
    return initial.get('carrier') == final.get('carrier') == 'tcp' and final.get('switches') == 0


def audit_scene(scene, evidence, rows, probe_rows, probe_parse):
    evidence, result = obj(evidence), obj(obj(evidence).get('result'))
    initial, final = obj(result.get('initial')), obj(result.get('final'))
    sid, flow = final.get('session_id'), result.get('flow_id')
    samples, schemas = server_samples(rows, sid, flow)
    checkpoints = {}
    for name, expected_class in (('initial', 1), ('bulk', 2), ('restored', 1), ('final', 1)):
        local = obj(result.get(name + '_class'))
        matches = [sample for sample in samples if paired(local, sample['view'], flow)
                   and local['LocalTX']['Class'] == expected_class and local['PeerTX']['Class'] == expected_class]
        if name == 'initial':
            matches = [sample for sample in matches if local['TXVersion'] == local['PeerTX']['Version'] == 1
                       and sample['runtime'].get('generation') == initial.get('generation')
                       and sample['runtime'].get('carrier') == initial.get('carrier')]
        final_scope = [sample for sample in matches
                       if sample['runtime'].get('generation') == final.get('generation')
                       and sample['runtime'].get('carrier') == final.get('carrier')]
        byte_matches = [sample for sample in final_scope
                        if obj(local.get('LocalTX')).get('TotalBytes') == UNIQUE
                        and obj(sample['view'].get('LocalTX')).get('TotalBytes') == UNIQUE]
        checkpoints[name] = {'local_exact_ack': valid_view(local, flow),
            'both_directions_exact_ack_sample': bool(matches),
            'both_directions_exact_ack_final_generation_sample': bool(final_scope),
            'both_unique_bytes_final_generation_sample': bool(byte_matches),
            'matching_samples': len(matches), 'final_generation_matching_samples': len(final_scope),
            'first_sample': sample_ref(matches[0]) if matches else None,
            'first_final_generation_sample': sample_ref(final_scope[0]) if final_scope else None,
            'first_final_generation_byte_sample': sample_ref(byte_matches[0]) if byte_matches else None}
        if name == 'initial' and not matches:
            checkpoints[name]['missing_sample_is_failure'] = True
            checkpoints[name]['sampling_boundary'] = 'The initial Normal checkpoint may be shorter than the fixed 100 ms server sampler; absent peer ACK evidence stays false.'
    checked = result.get('checked_gates')
    snapshots = [obj(result.get(name + '_class')) for name in ('initial', 'bulk', 'restored', 'final')]
    progress = [row for _line, row in probe_rows if row.get('event') == 'class_progress']
    progress_consistent = bool(progress) and all(obj(row.get('class')).get('ID') == flow
        and obj(row.get('session')).get('session_id') == sid for row in progress)
    final_probe_results = [row for _line, row in probe_rows if 'checked_gates' in row and 'wire_version' in row]
    local_final = snapshots[-1]
    final_progress = [row for row in progress if row.get('iteration') == COUNT and obj(row.get('class')) == local_final]
    live_final = obj(final_progress[0].get('session')) if len(final_progress) == 1 else {}
    final_flow_runtime = (live_final.get('session_id') == sid and live_final.get('flows') == 1
                          and live_final.get('opened') == 1 and live_final.get('carrier') == final.get('carrier')
                          and live_final.get('generation') == final.get('generation'))
    gates = {
        'raw_probe_pass': result.get('pass') is True,
        'wire_profile_capability_handshake_inferred': result.get('wire_version') == 3 and result.get('profile') == PROFILE and type(result.get('capabilities')) is int and result.get('capabilities') == 1 and bool(initial.get('session_id')),
        'fixed_count_size': result.get('expected_tcp') == COUNT and result.get('tcp_completed') == COUNT and result.get('bytes_per_operation') == SIZE and result.get('expected_unique_bytes') == UNIQUE,
        'all_original_probe_gates_true': isinstance(checked, dict) and set(checked) == PROBE_GATES and all(value is True for value in checked.values()),
        'same_session': isinstance(sid, str) and bool(sid) and initial.get('session_id') == sid and result.get('same_session') is True,
        'same_nonterminal_tcp_flow': positive(flow) and all(valid_view(view, flow) for view in snapshots) and final_flow_runtime,
        'carrier_matrix': carrier_ok(scene, initial, final),
        'one_target_connection_runner_attestation': evidence.get('one_target_connection') is True,
        'bulk_dual_direction_exact_ack': checkpoints['bulk']['both_directions_exact_ack_sample'],
        'restored_dual_direction_exact_ack': checkpoints['restored']['both_directions_exact_ack_sample'],
        'final_dual_direction_exact_ack_same_generation_carrier': checkpoints['final']['both_directions_exact_ack_final_generation_sample'],
        'final_both_unique_bytes_same_generation_carrier': checkpoints['final']['both_unique_bytes_final_generation_sample'],
        'local_idle_unique_bytes': obj(snapshots[2].get('LocalTX')).get('TotalBytes') == obj(local_final.get('LocalTX')).get('TotalBytes') == UNIQUE,
        'versions_advance': all(positive(view.get('TXVersion')) and positive(obj(view.get('PeerTX')).get('Version')) for view in snapshots) and snapshots[0].get('TXVersion', 0) < snapshots[1].get('TXVersion', 0) < snapshots[2].get('TXVersion', 0) and obj(snapshots[0].get('PeerTX')).get('Version', 0) < obj(snapshots[1].get('PeerTX')).get('Version', 0) < obj(snapshots[2].get('PeerTX')).get('Version', 0),
        'fixed_outer_deadline': uint(result.get('elapsed_ms')) and 0 < result['elapsed_ms'] <= 35000,
        'original_inner_deadline': uint(result.get('max_tcp_operation_ms')) and 0 < result['max_tcp_operation_ms'] <= 8000,
        'fixed_evidence_settle': result.get('evidence_settle_ms') == 1000,
        'probe_log_parse': probe_parse['pass'],
        'probe_progress_session_flow_consistent': progress_consistent,
        'probe_log_final_result_matches_collected_result': len(final_probe_results) == 1 and final_probe_results[0] == result,
        'server_sample_schema': schemas['schema_issue_count'] == 0,
    }
    initial_pass = checkpoints['initial']['both_directions_exact_ack_sample']
    selected_pass = all(gates.values())
    return {'raw_runner_scenario_pass': evidence.get('pass') is True, 'selected_sample_gates': gates,
            'selected_samples_without_initial_pass': selected_pass, 'initial_dual_direction_exact_ack_sample': initial_pass,
            'all_four_checkpoint_samples_pass': selected_pass and initial_pass, 'checkpoints': checkpoints,
            'server_sample_diagnostics': schemas, 'probe_log_parse': probe_parse,
            'final_flow_runtime_evidence': {'last_live_progress_matches_final_class': len(final_progress) == 1,
                'last_live_progress_runtime_matches_result': final_flow_runtime,
                'result_final_flows': final.get('flows'), 'last_live_progress_flows': live_final.get('flows'),
                'boundary': 'Frozen executeClassProbe emits live final progress before deferred conn.Close; outer deferred Stats rewrites result.Final after closing the flow. Live-flow evidence uses the matching final progress, with same carrier/generation.'},
            'profile_evidence_kind': 'inferred from successful frozen mandatory default handshake; emitted constants are not an independent runtime negotiation measurement',
            'one_target_evidence_kind': 'runner before/after target_open counter attestation; counters are not separately persisted per scene'}


def audit(run_id):
    if not re.fullmatch(r'[0-9a-f]{32}', run_id):
        raise EvidenceError('run_id_must_be_32_lowercase_hex')
    run_dir = STAGE / 'lab/runs' / run_id
    if not run_dir.is_dir() or run_dir.is_symlink() or not run_dir.resolve().is_relative_to((STAGE / 'lab/runs').resolve()):
        raise EvidenceError('run_directory_missing_or_unsafe')
    issues, inputs = [], {}
    report = load_document(run_dir / 'class-wan-result.json', issues, inputs)
    server_doc = load_document(run_dir / 'server-log.json', issues, inputs)
    server_rows, server_parse = parse_log(server_doc, 'server-log.json')
    binding = source_binding(report, run_dir, issues, inputs)
    scenario_results = {}
    for scene in SCENES:
        evidence = obj(obj(report.get('scenarios')).get(scene))
        probe_result = obj(evidence.get('result'))
        failure = probe_result.get('failure')
        expected_error = ('bfp: class probe ' + failure + ' failed') if probe_result.get('pass') is False and isinstance(failure, str) and re.fullmatch(r'[a-z_]+', failure) else None
        probe_doc = load_document(run_dir / (scene + '.probe-log.json'), issues, inputs)
        probe_rows, probe_parse = parse_log(probe_doc, scene + '.probe-log.json', expected_error)
        scenario_results[scene] = audit_scene(scene, evidence, server_rows, probe_rows, probe_parse)
    artifact_gates = {'document_parse': not issues, 'source_binary_binding': binding['pass'],
        'run_id': report.get('run_id') == run_id, 'revision': report.get('revision') == 'r9-next6',
        'declared_wire_profile_capabilities': report.get('wire_version') == 3 and report.get('profile') == PROFILE and type(report.get('capabilities')) is int and report.get('capabilities') == 1,
        'frozen_limits': report.get('limits') == {'count': COUNT, 'size': SIZE, 'interval': '100ms', 'duration': '35s'},
        'scene_set_exact': set(obj(report.get('scenarios'))) == set(SCENES), 'server_log_parse': server_parse['pass']}
    artifact_pass = all(artifact_gates.values())
    selected_pass = artifact_pass and all(scene['selected_samples_without_initial_pass'] for scene in scenario_results.values())
    initial_pass = artifact_pass and all(scene['initial_dual_direction_exact_ack_sample'] for scene in scenario_results.values())
    post = {'raw_runner_selected_checks_pass': report.get('selected_checks_pass') is True,
            'cleanup_attested': set(obj(report.get('cleanup'))) == {'receiver', 'sender'} and all(obj(x).get('directory_removed') is True for x in obj(report.get('cleanup')).values()),
            'snapshots_unchanged_attested': set(obj(report.get('snapshots'))) == {'receiver', 'sender'} and all(obj(obj(x).get('comparison')).get('unchanged') is True for x in obj(report.get('snapshots')).values()),
            'random_probe_silent_attested': obj(report.get('random_probe')).get('pass') is True and obj(report.get('random_probe')).get('no_application_response') is True and obj(report.get('random_probe')).get('tcp_connected') == 8}
    return {'audit_version': 3, 'run_id': run_id, 'revision': 'r9-next6',
            'audited_at_utc': datetime.now(timezone.utc).isoformat(),
            'audit_mode': 'local read-only evidence parsing; independent output only; no remote commands or business reruns',
            'auditor_sha256': sha256(Path(__file__).read_bytes()), 'input_artifacts': inputs,
            'input_issue_count': len(issues), 'input_issues': issues[:MAX_ISSUES],
            'artifact_gates': artifact_gates, 'artifact_binding_and_collection_pass': artifact_pass,
            'source_binary_binding': binding, 'server_log_parse': server_parse, 'scenarios': scenario_results,
            'selected_samples_without_initial_pass': selected_pass,
            'initial_checkpoint_samples_pass': initial_pass,
            'all_four_checkpoint_samples_pass': selected_pass and initial_pass,
            'runner_postcondition_attestations': post,
            'selected_samples_and_runner_postconditions_pass': selected_pass and all(post.values()),
            'sampling_scope': 'Selected samples prove observed Bulk/restore and final dual-direction exact ACK with matching final carrier/generation and bytes. Initial sampling is reported separately and missing evidence is false.',
            'runtime_scope_boundary': 'Server Stats and ClassificationSnapshot are sequential queries, not atomic. Only coherent matching carrier/generation rows count; no pre-recovery sample proves post-recovery convergence.',
            'unchecked_gates': {'selective_missing_class_ack_injection': False, 'retry_exhaustion': False,
                                'fairness_goodput_tail_latency': False, 'stable_original_eight_second_recovery': False},
            'raw_result_unchanged': True, 'pass': False, 'acceptance_complete': False,
            'production_ready': False, 'released': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, help='Existing frozen next6 run ID, 32 lowercase hex characters')
    args = parser.parse_args()
    result = audit(args.run)
    path = STAGE / 'lab/runs' / args.run / 'class-wan-independent-audit.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'run_id': args.run, 'path': str(path),
        'selected_samples_without_initial_pass': result['selected_samples_without_initial_pass'],
        'initial_checkpoint_samples_pass': result['initial_checkpoint_samples_pass'],
        'all_four_checkpoint_samples_pass': result['all_four_checkpoint_samples_pass'], 'pass': False}))
    return 0 if result['selected_samples_without_initial_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
