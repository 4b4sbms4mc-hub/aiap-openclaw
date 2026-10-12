# SPDX-License-Identifier: Apache-2.0
"""Check only synthetic CI data in the isolated aiap-mvp Compose project."""
import json
import subprocess
import time
import urllib.error
import urllib.request

COMPOSE = ["docker", "compose", "-f", "lavida/compose.yaml"]


def ready():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8043/health", timeout=2) as r:
                if json.load(r).get("initialized") is True:
                    return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError("Fresh Core did not become ready")


def inside(code):
    r = subprocess.run(COMPOSE + ["exec", "-T", "core", "python", "-"],
                       input=code, text=True, capture_output=True, check=True)
    return json.loads(r.stdout)


ready()
first = inside('''
import json
from pathlib import Path
from aiap_core.client import Client, proposal
owner = json.loads(Path('/data/owner-credentials.json').read_text())
client = Client('http://127.0.0.1:8042', owner['token'])
session = client.call('/v1/session')
assert session['role'] == 'owner'
body = {'space_refs':['space:general'], 'purpose':session['purpose'], 'query':'CI_RELEASE_MARKER'}
candidate = client.call('/v1/deltas/propose', proposal(session, 'space:general', 'CI_RELEASE_MARKER: concise answers.'))
assert client.call('/v1/search', body)['count'] == 0
review = client.call('/v1/deltas/review', {'delta_id':candidate['delta_id']})
assert 'CI_RELEASE_MARKER' in json.dumps(review)
client.call('/v1/deltas/decide', {'delta_id':candidate['delta_id'], 'approve':True})
items = client.call('/v1/search', body)['items']
assert len(items) == 1 and items[0]['revision'] == 1
expected = {'avatar':session['avatar_id'], 'memory':items[0]['memory_id'], 'revision':items[0]['revision']}
Path('/data/ci-expectation.json').write_text(json.dumps(expected))
print(json.dumps({'fresh_init':True, 'pending_excluded':True, 'owner_approval':True, 'approved_recall':True}))
''')
subprocess.run(COMPOSE + ["restart", "core"], check=True, stdout=subprocess.DEVNULL)
ready()
second = inside('''
import json
from pathlib import Path
from aiap_core.client import Client
owner = json.loads(Path('/data/owner-credentials.json').read_text())
client = Client('http://127.0.0.1:8042', owner['token'])
session = client.call('/v1/session')
expected = json.loads(Path('/data/ci-expectation.json').read_text())
items = client.call('/v1/search', {'space_refs':['space:general'], 'purpose':session['purpose'], 'query':'CI_RELEASE_MARKER'})['items']
assert session['avatar_id'] == expected['avatar']
assert len(items) == 1 and items[0]['memory_id'] == expected['memory'] and items[0]['revision'] == expected['revision']
print(json.dumps({'restart_identity':True, 'restart_memory_revision':True}))
''')
print(json.dumps({**first, **second}, indent=2))
