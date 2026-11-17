#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export ONNDEMAND_ASSET_ROOT="$REPO/src/onndemand/assets"
exec bash "$ONNDEMAND_ASSET_ROOT/scripts/coffey-root.sh" "$@"
