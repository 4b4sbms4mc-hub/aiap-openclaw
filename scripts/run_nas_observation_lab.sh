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
docker run --rm --pull never --network none --read-only \
  --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777 \
  --mount "type=bind,source=$root,target=/lab,readonly" \
  --workdir /lab --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/lab/lavida/core \
  --env AIAP_DATA_DIR=/tmp/unused-aiap-data \
  --entrypoint python "$image" \
  -m unittest discover -s scripts/tests -p test_recovery_live_observation.py -v
echo 'AIAP_SYNTHETIC_LAB_PASSED_NO_PRODUCTION_VOLUME'
