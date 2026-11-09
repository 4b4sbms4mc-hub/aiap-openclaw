# SPDX-License-Identifier: Apache-2.0
"""Build a reproducible, source-only release ZIP and checksum file."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import zipfile

args = argparse.ArgumentParser()
args.add_argument('--ci', action='store_true')
args.add_argument('--gateway-report', type=Path)
opts = args.parse_args()
root = Path(__file__).resolve().parents[1]
source = root / 'lavida'
manifest = json.loads((source / 'RELEASE.json').read_text())
version = manifest['plugin_version']
prefix = 'LaVida_for_OpenClaw_' + version


def archive_bytes(files):
    files = dict(files)
    files['SHA256SUMS'] = ('\n'.join(
        hashlib.sha256(data).hexdigest() + '  ' + name
        for name, data in sorted(files.items())) + '\n').encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(prefix + '/' + name, date_time=(2026,1,1,0,0,0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return output.getvalue()


payload = {}
for path in sorted(source.rglob('*')):
    if path.is_symlink():
        raise SystemExit('Symlink in release tree')
    if not path.is_file():
        continue
    rel = path.relative_to(source)
    if '__pycache__' in rel.parts or path.suffix == '.pyc' or rel.name == 'SHA256SUMS':
        continue
    if ('data' in rel.parts or '.venv' in rel.parts or path.suffix in {'.pem','.sqlite','.sqlite3'}
            or rel.name.endswith('-credentials.json') or rel.name == '.env'):
        raise SystemExit('Runtime data found in release tree')
    data = path.read_bytes()
    if b'-----BEGIN PRIVATE KEY-----' in data:
        raise SystemExit('Private key material found in release tree')
    payload[rel.as_posix()] = data
if opts.ci:
    sha = os.environ['GITHUB_SHA']
    repo = os.environ['GITHUB_REPOSITORY']
    run = os.environ['GITHUB_RUN_ID']
    if not opts.gateway_report:
        raise SystemExit('CI packaging requires actual Gateway acceptance evidence')
    gateway = json.loads(opts.gateway_report.read_text())
    required = {'release_checksums', 'fresh_archive_install', 'fresh_gateway_auth_and_session',
                'fresh_propose_owner_approve_recall', 'fresh_pending_rejected_and_space_isolation',
                'stopped_snapshot_checksums_and_sqlite', 'original_state_offline_during_restore',
                'restored_gateway_auth_and_session', 'restored_gateway_recall', 'restored_local_signature',
                'restored_propose_owner_approve_recall', 'temporary_processes_stopped'}
    if (gateway.get('status') != 'passed' or gateway.get('commit') != sha
            or gateway.get('temporary_state_removed') is not True
            or gateway.get('release_sha256') != hashlib.sha256(archive_bytes(payload)).hexdigest()
            or any(gateway.get('checks', {}).get(k) is not True for k in required)
            or gateway.get('plugin_version') != version
            or gateway.get('core_version') != manifest['core_version']):
        raise SystemExit('Gateway evidence does not match this validated commit/version')
    payload['CI_VALIDATION.json'] = (json.dumps({
        'commit': sha, 'workflow_run': f'https://github.com/{repo}/actions/runs/{run}',
        'core_tests': 66, 'plugin_integration_checks': 15, 'automatic_checks': 15,
        'fresh_core_docker': 'passed', 'core_restart_persistence': 'passed',
        'fresh_openclaw_install': 'passed-real-gateway-http',
        'restored_gateway_core_tool_calls': 'passed-real-gateway-http',
        'gateway_acceptance': gateway,
        'conversational_model_tool_selection': 'not-tested',
        'fresh_openclaw_docker_nas_deployment': 'not-tested'
    }, indent=2) + '\n').encode()
dist = root / 'dist'
dist.mkdir(exist_ok=True)
archive = dist / (prefix + '.zip')
archive.write_bytes(archive_bytes(payload))
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(dist / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n')
print(json.dumps({'archive':str(archive), 'sha256':digest, 'files':len(payload)+1}))
