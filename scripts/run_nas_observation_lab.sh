#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Synthetic-only acceptance. Does not mount an existing Core data volume.
set -eu
[ "$(uname -s)" = Linux ] || { echo 'E_LINUX_REQUIRED' >&2; exit 2; }
[ "$#" -le 1 ] || { echo 'Usage: sh scripts/run_nas_observation_lab.sh [local-image]' >&2; exit 2; }
image=${1:-aiap-core-service:0.2.0}
case "$image" in
  ''|-*|*[!a-zA-Z0-9._:/@-]*) echo 'E_IMAGE_NAME' >&2; exit 2 ;;
esac
root=$(CDPATH= cd -P -- "$(dirname -- "$0")/.." && pwd -P)
case "$root" in *,*) echo 'E_MOUNT_PATH' >&2; exit 2 ;; esac
[ -f "$root/scripts/tests/test_recovery_live_observation.py" ] || { echo 'E_LAB_LAYOUT' >&2; exit 2; }
[ -f "$root/lavida/core/aiap_core/service.py" ] || { echo 'E_LAB_LAYOUT' >&2; exit 2; }
# Inspect only the public local image ID; do not pull, build, alter or restart it.
image_id=$(docker image inspect --format '{{.Id}}' "$image")
echo "AIAP_SYNTHETIC_LAB_IMAGE=$image_id"
# NAS shared-folder ACLs may ignore the mode requested through SMB. Stage only
# public lab code on the Linux host; never chmod the original shared directory.
staging=$(mktemp -d /tmp/aiap-observation-lab.XXXXXX)
trap 'rm -rf -- "$staging"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$staging/lavida" "$staging/scripts/tests"
cp -R "$root/lavida/core" "$staging/lavida/core"
for name in recovery_guard.py recovery_highwater.py recovery_witness.py recovery_source_gate.py recovery_live_observation.py; do
  cp "$root/scripts/$name" "$staging/scripts/$name"
done
for name in test_recovery_guard.py test_recovery_live_observation.py; do
  cp "$root/scripts/tests/$name" "$staging/scripts/tests/$name"
done
[ -z "$(find "$staging" -type l -print -quit)" ] || { echo 'E_LAB_SYMLINK' >&2; exit 2; }
chmod -R u=rwX,go=rX "$staging"
docker run --rm --pull never --network none --read-only \
  --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777 \
  --mount "type=bind,source=$staging,target=/lab,readonly" \
  --workdir /lab --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/lab/lavida/core \
  --env AIAP_DATA_DIR=/tmp/unused-aiap-data \
  --entrypoint python "$image" \
  -m unittest discover -s scripts/tests -p test_recovery_live_observation.py -v
echo 'AIAP_SYNTHETIC_LAB_PASSED_NO_PRODUCTION_VOLUME'
