"""Every hit the glued upstream pipeline finds, agent-iocs must find too.

    python bench/parity.py <ai-data-extractor> <zero-breach> <claude projects dir>
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [sys.argv[1], str(Path(sys.argv[2]) / "scan"), str(ROOT)]
from extractors import claude_code  # noqa: E402
from adint_scan import iocs  # noqa: E402
import agent_iocs as ai  # noqa: E402

s = iocs.load(str(ai.DEFAULT_IOCS))
proj = Path(sys.argv[3])
files = list(proj.glob("*/*.jsonl"))
base = set()
for f in files:
    for m in (claude_code._extract_session(f) or {}).get("messages", []):
        for i in s.most_specific(s.search(chr(10).join(ai._strings(m)).lower())):
            base.add((f.name, m["timestamp"], i.value))
net = [i for i in ai.load_iocs(ai.DEFAULT_IOCS)[0] if i["type"] != "sha256"]
mine = {(Path(h["file"]).name, h["timestamp"], h["indicator"]) for h in ai.scan([("claude-code", f) for f in files], net)}
print("sessions", len(files), "baseline hits", len(base), "agent-iocs hits", len(mine),
      "baseline hits missed by agent-iocs:", len(base - mine))
sys.exit(1 if base - mine else 0)
