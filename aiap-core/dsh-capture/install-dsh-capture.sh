#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Install a checksummed release archive into an existing DSH profile.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo 'Usage: sh install-dsh-capture.sh /path/to/dsh-aiap-capture-VERSION.tar.gz [DSH_PROFILE]' >&2
    exit 2
fi

archive_dir=$(cd "$(dirname "$1")" && pwd -P)
name=$(basename "$1")
if ! printf '%s\n' "$name" | grep -Eq '^dsh-aiap-capture-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz$'; then
    echo 'Choose a versioned dsh-aiap-capture release tarball.' >&2
    exit 2
fi
archive="$archive_dir/$name"
expected=$(awk -v name="$name" '$2 == name { print $1 }' "$archive_dir/SHA256SUMS-MCP.txt")
actual=$(shasum -a 256 < "$archive" | awk '{ print $1 }')
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo 'The archive did not match SHA256SUMS-MCP.txt.' >&2
    exit 1
fi

profile=${2:-"$HOME/.dsh/profiles/desktop"}
if [ ! -f "$profile/package.json" ] || [ ! -f "$profile/pnpm-workspace.yaml" ]; then
    echo 'Choose an existing DSH profile.' >&2
    exit 2
fi
cd "$profile"
package="vendor/aiap/$name"
mkdir -p vendor/aiap
if [ ! -e "$package" ]; then
    staged=$(mktemp vendor/aiap/.archive.XXXXXX)
    trap 'rm -f "$staged"' EXIT
    cp "$archive" "$staged"
    ln "$staged" "$package"
fi
if ! cmp -s "$archive" "$package"; then
    echo 'The profile already has different bytes at this archive path.' >&2
    exit 1
fi

runtime="${DSH_APP:-/Applications/DeepSeek Harness.app}/Contents/Resources/runtime/primary-runtime/dependencies"
if [ -x "$runtime/node/bin/node" ] && [ -f "$runtime/pnpm/bin/pnpm.cjs" ]; then
    "$runtime/node/bin/node" "$runtime/pnpm/bin/pnpm.cjs" add --ignore-scripts "./$package"
else
    pnpm add --ignore-scripts "./$package"
fi
