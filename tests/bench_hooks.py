"""Measure hook latency through the real launcher. Uses a throwaway ENGRAM_HOME.

Run from the repo root: python tests/bench_hooks.py [--notes 500] [--runs 30]
"Cold" is the first run after writing the database and clearing bytecode caches. It
cannot flush the operating system's file cache, so a true post-reboot start is slower.
"""
import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "plugins" / "engram" / "scripts"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_engram import SH  # noqa: E402

WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike "
         "november oscar papa quebec romeo sierra tango uniform victor whiskey xray").split()


def clock(cmd, payload, env, cwd):
    start = time.perf_counter()
    subprocess.run(cmd, input=payload, capture_output=True, env=env, cwd=cwd, timeout=60)
    return (time.perf_counter() - start) * 1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--notes", type=int, default=500)
    ap.add_argument("--runs", type=int, default=30)
    a = ap.parse_args()
    tmp = tempfile.mkdtemp(prefix="engram-bench-")
    try:
        cwd = os.path.join(tmp, "proj")
        os.mkdir(cwd)
        env = dict(os.environ, ENGRAM_HOME=os.path.join(tmp, "home"))
        sys.path.insert(0, str(SCRIPTS))
        os.environ["ENGRAM_HOME"] = env["ENGRAM_HOME"]
        subprocess.run([sys.executable, str(SCRIPTS / "engram.py"), "add", "seed note"],
                       env=env, cwd=cwd, capture_output=True, check=True)
        import sqlite3
        c = sqlite3.connect(os.path.join(env["ENGRAM_HOME"], "memory.db"))
        pid = c.execute("SELECT project_id FROM memories").fetchone()[0]
        now = time.time()
        for i in range(a.notes):
            text = " ".join(WORDS[(i * k + k) % len(WORDS)] for k in range(1, 13)) + " note%d" % i
            age = 0 if i % 3 else 90 * 86400
            c.execute("INSERT INTO memories(kind,text,project_id,importance,created,last_access,tier) "
                      "VALUES ('fact',?,?,3,?,?,?)", (text, pid, now - age, now - age,
                                                      "cold" if age else "hot"))
        c.commit()
        c.close()

        prompt = json.dumps({"prompt": "alpha bravo charlie rollout", "cwd": cwd, "session_id": "bench"}).encode()
        start = json.dumps({"cwd": cwd, "session_id": "bench"}).encode()
        launcher = [SH, str(SCRIPTS / "engram.sh")] if SH else None
        direct = [sys.executable, str(SCRIPTS / "engram.py")]
        print("python %s, %d notes, %d runs, %s" % (sys.version.split()[0], a.notes, a.runs, sys.platform))
        print("%-12s %-9s %8s %8s %8s %8s" % ("hook", "via", "cold", "median", "p95", "max"))
        for name, payload in (("hook-start", start), ("hook-prompt", prompt)):
            for via, cmd in (("launcher", launcher), ("python", direct)):
                if not cmd:
                    continue
                shutil.rmtree(SCRIPTS / "__pycache__", ignore_errors=True)
                cold = clock(cmd + [name], payload, env, cwd)
                times = sorted(clock(cmd + [name], payload, env, cwd) for _ in range(a.runs))
                print("%-12s %-9s %8.0f %8.0f %8.0f %8.0f" % (
                    name, via, cold, statistics.median(times),
                    times[int(len(times) * 0.95) - 1], times[-1]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
