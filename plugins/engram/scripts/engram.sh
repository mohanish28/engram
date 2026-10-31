#!/bin/sh
# Runs engram.py with the first working Python. Each candidate is executed, not just
# looked up: on Windows "python3" can be a Microsoft Store stub that only fails.
dir=${0%/*}
[ "$dir" = "$0" ] && dir=${0%\\*}
[ "$dir" = "$0" ] && dir=.
for py in python3 python "py -3"; do
  if $py -c 'import sys; sys.exit(sys.version_info < (3, 8))' </dev/null >/dev/null 2>&1; then
    exec $py "$dir/engram.py" "$@"
  fi
done
# Hooks must never fail or block a session.
case "$1" in hook-*) exit 0 ;; esac
echo "engram: no Python 3.8+ found (tried python3, python, py)" >&2
exit 1
