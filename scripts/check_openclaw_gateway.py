# SPDX-License-Identifier: Apache-2.0
"""Synthetic fresh-install and stopped-snapshot restore through a real Gateway.

No production configuration is read. No model, external channel or Docker is used.
This validates the authenticated HTTP tool route, not conversational tool choice.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob('*')) if p.is_file()}


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def http(base, path, body=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path,
        data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        # Do not expose raw host errors or private configuration in reports.
        return e.code, None


def ready(process, base, path):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        require(process.poll() is None, 'fixture process exited before readiness')
        try:
            if http(base, path)[0] == 200:
                return
        except (OSError, ValueError):
            pass
        time.sleep(.25)
    raise RuntimeError('fixture readiness timed out')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openclaw-entry', type=Path, required=True)
    parser.add_argument('--node', default='node')
    parser.add_argument('--release-zip', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # A failed rerun must not leave an older passing report at the requested path.
    args.output.unlink(missing_ok=True)
    entry = args.openclaw_entry.resolve(strict=True)
    host = json.loads((entry.parent / 'package.json').read_text())
    require(host['name'] == 'openclaw' and host['version'] == '2026.9.4', 'unexpected OpenClaw package')
    node = shutil.which(args.node)
    require(node is not None, 'Node executable missing')
    node_version = subprocess.check_output([node, '--version'], text=True).strip()
    report = {'schema_version': 1, 'openclaw_version': host['version'], 'node_version': node_version,
              'python_version': sys.version.split()[0],
              'release_sha256': hashlib.sha256(args.release_zip.read_bytes()).hexdigest(),
              'commit': os.environ.get('GITHUB_SHA'), 'checks': {},
              'limits': ['No conversational model turn', 'No Docker/NAS deployment',
                         'No secure transfer or revocation-aware historical recovery guarantee']}
    checks = report['checks']
    with tempfile.TemporaryDirectory(prefix='aiap-gateway-') as tmp:
        root = Path(tmp)
        root.chmod(0o700)
        release = root / 'release'
        with zipfile.ZipFile(args.release_zip) as z:
            for item in z.infolist():
                target = release / item.filename
                require(target.resolve().is_relative_to(release.resolve()), 'unsafe release path')
                require((item.external_attr >> 16) & 0o170000 != 0o120000, 'release symlink')
            z.extractall(release)
        candidates = list(release.glob('*/RELEASE.json'))
        require(len(candidates) == 1, 'invalid release layout')
        payload = candidates[0].parent
        manifest = json.loads(candidates[0].read_text())
        report['core_version'] = manifest['core_version']
        report['plugin_version'] = manifest['plugin_version']
        for line in (payload / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ', 1)
            path = payload / name
            require(path.resolve().is_relative_to(payload.resolve()), 'unsafe checksum path')
            require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'release checksum mismatch')
        checks['release_checksums'] = True
        sys.path.insert(0, str(payload / 'core'))
        from aiap_core.client import Client, proposal
        from aiap_core.service import Service
        clean_env = {k: v for k, v in os.environ.items()
                     if k in ('PATH', 'SYSTEMROOT', 'TMPDIR', 'LANG', 'LC_ALL')}
        clean_env['PATH'] = str(Path(node).parent) + os.pathsep + clean_env.get('PATH', '')
        clean_env['PYTHONPATH'] = str(payload / 'core')
        clean_env['PYTHONDONTWRITEBYTECODE'] = '1'
        clean_env['OPENCLAW_DISABLE_BONJOUR'] = '1'
        gateway_token = secrets.token_hex(32)
        current = root / 'fresh'
        (current / 'host').mkdir(parents=True, mode=0o700)
        core = Service(current / 'core')
        core.initialize()
        owner_token = json.loads((current / 'core/owner-credentials.json').read_text())['token']
        credential = core.issue_grant(['space:general'], 'lavida-memory', 'openclaw-main')
        credential_path = current / 'host/adapter.json'
        credential_path.write_text(json.dumps(credential))
        credential_path.chmod(0o600)
        cfg = {'gateway': {'mode': 'local', 'bind': 'loopback',
                          'auth': {'mode': 'token', 'token': gateway_token}},
               'agents': {'defaults': {'workspace': str(current / 'workspace')}},
               'plugins': {'entries': {}},
               'tools': {'allow': ['aiap_memory_status', 'aiap_memory_search', 'aiap_memory_propose']}}

        def environment(directory):
            return {**clean_env, 'OPENCLAW_HOME': str(directory),
                    'OPENCLAW_STATE_DIR': str(directory / 'host'),
                    'OPENCLAW_CONFIG_PATH': str(directory / 'host/openclaw.json')}

        config_path = current / 'host/openclaw.json'
        config_path.write_text(json.dumps(cfg))
        config_path.chmod(0o600)
        require(not (current / 'host/extensions').exists(), 'fresh plugin destination already exists')
        install = subprocess.run([node, str(entry), 'plugins', 'install',
            str(payload / ('lavida-aiap-' + manifest['plugin_version'] + '.tgz')),
            '--accept-capabilities', '--force'], env=environment(current), capture_output=True, text=True, timeout=120)
        if install.returncode:
            # Operator-only diagnostic; output is not copied into the JSON report.
            diagnostic = install.stdout + install.stderr
            for secret in (gateway_token, owner_token, credential['token']):
                diagnostic = diagnostic.replace(secret, '[REDACTED]')
            print(diagnostic[-6000:], file=sys.stderr)
        require(install.returncode == 0, 'fresh plugin installation failed')
        checks['fresh_archive_install'] = True
        cfg = json.loads(config_path.read_text())
        cfg['plugins']['allow'] = ['lavida-aiap']
        cfg['plugins']['slots'] = {'memory': 'lavida-aiap'}
        cfg['plugins']['entries']['lavida-aiap'] = {'enabled': True, 'config': {
            'avatarId': credential['avatar_id'], 'autoPropose': {'enabled': False},
            'bindings': {'main': {'spaceRef': 'space:general', 'credentialFile': str(credential_path),
                'purpose': 'lavida-memory', 'runtimeRef': 'openclaw-main', 'sessionKeys': ['agent:main:main']}}}}
        fresh_expected = None
        for phase in ('fresh', 'restored'):
            core_port, gateway_port = port(), port()
            core_base = f'http://127.0.0.1:{core_port}'
            gateway_base = f'http://127.0.0.1:{gateway_port}'
            cfg['gateway']['port'] = gateway_port
            cfg['plugins']['entries']['lavida-aiap']['config']['baseUrl'] = core_base
            config_path = current / 'host/openclaw.json'
            config_path.write_text(json.dumps(cfg))
            config_path.chmod(0o600)
            core_process = gateway_process = None
            with (root / (phase + '-core.log')).open('w') as core_log, (root / (phase + '-gateway.log')).open('w') as gateway_log:
                try:
                    core_process = subprocess.Popen([sys.executable, '-m', 'aiap_core', '--data-dir',
                        str(current / 'core'), 'serve', '--port', str(core_port), '--archive-interval', '0'],
                        env=clean_env, stdout=core_log, stderr=subprocess.STDOUT)
                    ready(core_process, core_base, '/health')
                    gateway_process = subprocess.Popen([node, str(entry), 'gateway', 'run',
                        '--port', str(gateway_port), '--bind', 'loopback'], env=environment(current),
                        stdout=gateway_log, stderr=subprocess.STDOUT)
                    ready(gateway_process, gateway_base, '/healthz')
                    client = Client(core_base, owner_token)

                    def invoke(name, params, session='agent:main:main', token=gateway_token, expected=200):
                        status, value = http(gateway_base, '/tools/invoke',
                            {'tool': 'aiap_memory_' + name, 'args': params, 'sessionKey': session}, token)
                        require(status == expected, f'{phase}: {name} HTTP status {status}, expected {expected}')
                        if expected != 200:
                            return None
                        require(value.get('ok') and not value['result'].get('isError'), f'{phase}: plugin error')
                        result = value['result']
                        return result.get('details') or json.loads(result['content'][0]['text'])

                    status = invoke('status', {})
                    require(status['avatar_id'] == credential['avatar_id'] and status['space_ref'] == 'space:general', 'wrong identity/scope')
                    require(status['automatic_proposals']['enabled'] is False, 'automatic proposals enabled')
                    invoke('status', {}, token='invalid-synthetic-token', expected=401)
                    invoke('search', {'query': ''}, session='agent:main:unbound', expected=404)
                    checks[phase + '_gateway_auth_and_session'] = True
                    if phase == 'restored':
                        found = invoke('search', {'query': 'AIAP_ACCEPTED'})['results']
                        require(len(found) == 1 and found[0] == fresh_expected, 'restored identity/memory/revision mismatch')
                        for marker in ('AIAP_PENDING', 'AIAP_REJECTED', 'AIAP_PRIVATE_LIFE'):
                            require(not invoke('search', {'query': marker})['results'], 'restored excluded content recalled')
                        checks['restored_gateway_recall'] = True
                        signed = client.call('/v1/core')
                        require(Service(current / 'core').verify_local_core(signed['avatar_core'], signed['local_enrollment']), 'restored signature invalid')
                        checks['restored_local_signature'] = True
                    marker = 'AIAP_ACCEPTED' if phase == 'fresh' else 'AIAP_RESTORED_NEW'
                    candidate = invoke('propose', {'text': marker + ': synthetic concise preference.'})
                    require(candidate['status'] == 'proposed', 'candidate not pending')
                    require(not invoke('search', {'query': marker})['results'], 'pending recalled')
                    reviewed = client.call('/v1/deltas/review', {'delta_id': candidate['delta_id']})
                    require(marker in json.dumps(reviewed), 'owner review missing evidence')
                    client.call('/v1/deltas/decide', {'delta_id': candidate['delta_id'], 'approve': True})
                    found = invoke('search', {'query': marker})['results']
                    require(len(found) == 1 and found[0]['revision'] == 1, 'approved recall failed')
                    checks[phase + '_propose_owner_approve_recall'] = True
                    if phase == 'fresh':
                        fresh_expected = found[0]
                        invoke('propose', {'text': 'AIAP_PENDING synthetic candidate.'})
                        rejected = invoke('propose', {'text': 'AIAP_REJECTED synthetic candidate.'})
                        client.call('/v1/deltas/decide', {'delta_id': rejected['delta_id'], 'approve': False})
                        session = client.call('/v1/session')
                        private = client.call('/v1/deltas/propose', proposal(session, 'space:life', 'AIAP_PRIVATE_LIFE synthetic fact.'))
                        client.call('/v1/deltas/decide', {'delta_id': private['delta_id'], 'approve': True})
                        for excluded in ('AIAP_PENDING', 'AIAP_REJECTED', 'AIAP_PRIVATE_LIFE'):
                            require(not invoke('search', {'query': excluded})['results'], 'excluded content recalled')
                        checks['fresh_pending_rejected_and_space_isolation'] = True
                finally:
                    stop(gateway_process)
                    stop(core_process)
                    if sys.exc_info()[0]:
                        # Only expose the tail, with fixture secrets redacted.
                        gateway_log.flush()
                        diagnostic = (root / (phase + '-gateway.log')).read_text()[-6000:]
                        for secret in (gateway_token, owner_token, credential['token']):
                            diagnostic = diagnostic.replace(secret, '[REDACTED]')
                        print(diagnostic, file=sys.stderr)
            if phase == 'fresh':
                snapshot = root / 'snapshot'
                shutil.copytree(current, snapshot)
                expected_hashes = hashes(snapshot)
                restored = root / 'restored'
                shutil.copytree(snapshot, restored)
                require(hashes(restored) == expected_hashes, 'snapshot checksum mismatch')
                with sqlite3.connect('file:' + str(restored / 'core/core.sqlite3') + '?mode=ro', uri=True) as db:
                    require(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'SQLite integrity check failed')
                checks['stopped_snapshot_checksums_and_sqlite'] = True
                # Original paths become unavailable, so restored calls cannot hit old state.
                old = current
                current.rename(root / 'original-offline')
                current = restored
                cfg = json.loads(json.dumps(cfg).replace(str(old), str(current)))
                checks['original_state_offline_during_restore'] = not old.exists()
        checks['temporary_processes_stopped'] = True
    report['temporary_state_removed'] = not root.exists()
    report['status'] = 'passed'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
