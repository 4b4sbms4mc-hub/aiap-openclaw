# SPDX-License-Identifier: Apache-2.0
"""Publish the authorized release after CI, without overwriting prior versions."""
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

root = Path(__file__).resolve().parents[1]
repo = os.environ['GITHUB_REPOSITORY']
commit = os.environ['GITHUB_SHA']
if repo != '4b4sbms4mc-hub/aiap-openclaw' or os.environ.get('GITHUB_REF') != 'refs/heads/main':
    raise SystemExit('Release is restricted to the authorized repository main branch')
token = os.environ['GITHUB_TOKEN']
manifest = json.loads((root/'lavida/RELEASE.json').read_text())
tag = manifest['tag']
if not re.fullmatch(r'lavida-openclaw-v[0-9]+\.[0-9]+\.[0-9]+', tag):
    raise SystemExit('Unexpected tag')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

opener = urllib.request.build_opener(NoRedirect())

def request(method, path, body=None, binary=False, missing=False):
    base = 'https://uploads.github.com' if binary else 'https://api.github.com'
    data = body if binary else (None if body is None else json.dumps(body).encode())
    headers = {'Authorization':'Bearer '+token, 'Accept':'application/vnd.github+json',
               'X-GitHub-Api-Version':'2026-03-10', 'User-Agent':'AIAP-LaVida-release'}
    if data is not None:
        headers['Content-Type'] = 'application/octet-stream' if binary else 'application/json'
    try:
        with opener.open(urllib.request.Request(base+path, data=data, method=method, headers=headers), timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if missing and error.code == 404:
            return None
        raise RuntimeError('GitHub release API returned HTTP '+str(error.code)) from None

release_path = '/repos/'+repo+'/releases'
ref = request('GET', '/repos/'+repo+'/git/ref/tags/'+tag, missing=True)
if ref and ref['object']['sha'] != commit:
    raise SystemExit('Existing tag points to another commit; refusing to overwrite')
release = request('GET', release_path+'/tags/'+tag, missing=True)
if release and not release['draft']:
    print('Already published: '+release['html_url'])
    raise SystemExit(0)
if release and release['target_commitish'] != commit:
    raise SystemExit('Existing draft targets another commit')
if not release:
    release = request('POST', release_path, {
        'tag_name':tag, 'target_commitish':commit, 'name':manifest['name'],
        'body':(root/'lavida/docs/RELEASE_NOTES.md').read_text(),
        'draft':True, 'prerelease':manifest['prerelease'], 'make_latest':'false'
    })
rid = int(release['id'])
for filename in ['LaVida_for_OpenClaw_'+manifest['plugin_version']+'.zip', 'SHA256SUMS']:
    data = (root/'dist'/filename).read_bytes()
    expected = 'sha256:'+hashlib.sha256(data).hexdigest()
    assets = request('GET', release_path+'/'+str(rid)+'/assets')
    existing = next((a for a in assets if a['name']==filename), None)
    if existing:
        if existing.get('digest') != expected:
            raise SystemExit('Existing asset differs; refusing to overwrite')
    else:
        uploaded = request('POST', release_path+'/'+str(rid)+'/assets?name='+urllib.parse.quote(filename), data, binary=True)
        if uploaded['size'] != len(data) or uploaded.get('digest') != expected:
            raise SystemExit('Uploaded asset checksum mismatch; release remains a draft')
published = request('PATCH', release_path+'/'+str(rid), {'draft':False})
print('Published: '+published['html_url'])
