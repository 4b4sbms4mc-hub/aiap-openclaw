# SPDX-License-Identifier: Apache-2.0
"""Build a deterministic plugin archive directly from its reviewed source tree."""
import gzip
import io
import json
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parents[1] / 'lavida'
source = root / 'plugin'
version = json.loads((source / 'package.json').read_text())['version']
assert json.loads((source / 'openclaw.plugin.json').read_text())['version'] == version
assert json.loads((root / 'RELEASE.json').read_text())['plugin_version'] == version
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
    for path in sorted(source.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise SystemExit('Unexpected non-file in plugin source')
        data = path.read_bytes()
        info = tarfile.TarInfo('package/' + path.name)
        info.size = len(data)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(data))
target = root / ('lavida-aiap-' + version + '.tgz')
target.write_bytes(gzip.compress(buffer.getvalue(), mtime=0))
with tarfile.open(target) as archive:
    for entry in archive.getmembers():
        assert archive.extractfile(entry).read() == (source / Path(entry.name).name).read_bytes()
print('Built source-matching plugin archive ' + target.name)
