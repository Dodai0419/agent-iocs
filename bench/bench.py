"""Time the two-tool pipeline against agent-iocs on the same logs.

    python bench/bench.py <ai-data-extractor> <zero-breach> <claude projects dir> [runs]

Baseline = ai-data-extractor's claude_code.extract() + zero-breach's
most_specific(search()) on every message's strings: the way you would glue the two tools.
"""
import statistics, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ade, zb, logs = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
runs = int(sys.argv[4]) if len(sys.argv) > 4 else 5
base = f"""
import sys; sys.path[:0] = [{str(ade)!r}, {str(zb / 'scan')!r}]
from pathlib import Path
from extractors import claude_code
from adint_scan import iocs
def strings(x):
    if isinstance(x, str): yield x
    elif isinstance(x, dict):
        for v in x.values(): yield from strings(v)
    elif isinstance(x, list):
        for v in x: yield from strings(v)
s = iocs.load({str(ROOT / 'iocs' / 'adfection_iocs.txt')!r})
hits = 0
for c in claude_code.extract([Path({logs!r})]):
    for m in c["messages"]:
        hits += len(s.most_specific(s.search(chr(10).join(strings(m)).lower())))
print(hits, "hits")
"""
cmds = {"ai-data-extractor + zero-breach": [sys.executable, "-c", base],
        "agent-iocs scan": [sys.executable, str(ROOT / "agent_iocs.py"), "scan", logs, "--json"]}
for name, cmd in cmds.items():
    times, out = [], ""
    for _ in range(runs):
        t = time.perf_counter()
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        out = p.stdout or p.stderr[-800:]
        times.append((time.perf_counter() - t) * 1000)
    hits = out.split()[0] if name.startswith("ai-") and out.split()[1:2] == ["hits"] else (out if name.startswith("ai-") else len(out.splitlines()))
    print(f"{name:32} median {statistics.median(times):7.0f} ms of {runs}  hits={hits}")
