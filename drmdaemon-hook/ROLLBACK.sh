#!/system/bin/sh
set -eu
D=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
mkdir -p "$D/artifacts/rollback-copy"
printf '%s\n' 'baseline: no drmdaemon hook' > "$D/artifacts/rollback-copy/MODIFIED_FILE"
echo rollback-complete
