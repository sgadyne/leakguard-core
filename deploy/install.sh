#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUNDLE_DIR=${1:-"$(dirname -- "$SCRIPT_DIR")"}
PYTHON=${PYTHON:-python3}

"$PYTHON" --version >/dev/null
"$PYTHON" "$SCRIPT_DIR/installer.py" install "$BUNDLE_DIR"
printf '%s\n' 'LeakGuard is installed for this user. Run leakguard-doctor, or enable its optional service with leakguard-install service enable.'
