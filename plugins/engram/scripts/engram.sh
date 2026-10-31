#!/bin/sh
# Runs engram with the first working Python. No separate probe: starting Python twice
# was most of a hook's latency. Importing the module, unlike running it as a script,
# lets Python reuse compiled bytecode. Exit codes 0-2 come from engram; anything else
# means this interpreter is broken (the Windows Store stub) or too old, so try the next.
dir=${0%/*}
[ "$dir" = "$0" ] && dir=${0%\\*}
[ "$dir" = "$0" ] && dir=.
flags=
case "$1" in
  # Hooks use only the standard library, and must stay silent.
  hook-*) flags="-I -S"; exec 2>/dev/null ;;
esac
boot='import sys
if sys.version_info < (3, 8): sys.exit(9)
sys.path.insert(0, sys.argv.pop(1))
import engram
engram.main()'
try() {
  py=$1
  shift
  command -v "${py%% *}" >/dev/null 2>&1 || return 0
  $py $flags -c "$boot" "$dir" "$@"
  rc=$?
  case $rc in 0|1|2) exit $rc ;; esac
}
# On Windows python3 is usually an App Execution Alias, about 120 ms slower to start.
if [ "$OS" = Windows_NT ]; then
  try python "$@"
  try python3 "$@"
else
  try python3 "$@"
  try python "$@"
fi
try "py -3" "$@"
case "$1" in hook-*) exit 0 ;; esac
echo "engram: no Python 3.8+ found (tried python3, python, py)" >&2
exit 1
