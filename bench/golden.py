"""Regenerate tests/fixtures/golden.json from the upstream code.

    python bench/golden.py <ai-data-extractor checkout> <zero-breach checkout>
"""
import json, random, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ade, zb = Path(sys.argv[1]), Path(sys.argv[2])
sys.path[:0] = [str(ade), str(zb / "scan")]
from extractors import claude_code, codex  # noqa: E402
from adint_scan import iocs as zb_iocs  # noqa: E402

fx = ROOT / "tests" / "fixtures"
# Upstream crashes (AttributeError) on a JSONL line that is valid JSON but not an object,
# and the fixture has one on purpose. Run upstream on a copy without such lines.
tmp = Path(tempfile.mkdtemp())
for f in fx.rglob("*.jsonl"):
    out = tmp / f.relative_to(fx)
    out.parent.mkdir(parents=True, exist_ok=True)
    keep = []
    for line in f.read_text(encoding="utf-8").splitlines(True):
        try:
            if not isinstance(json.loads(line), dict):
                continue
        except ValueError:
            pass
        keep.append(line)
    out.write_text("".join(keep), encoding="utf-8")
export = claude_code.extract([tmp / "claude" / "projects"]) + codex.extract([tmp / "codex" / "sessions"])

s = zb_iocs.load(str(ROOT / "iocs" / "adfection_iocs.txt"))
rng = random.Random(7)
net = [i.value for i in s.indicators if i.type != "sha256"]
edges = ["", " ", ".", "x", "-", "_", "1", "a.", ".x", "..", "/", ":", "9.", "\n", "\"", "%2e"]
hays = []
for v in net:
    for _ in range(6):
        hays.append(rng.choice(edges) + v + rng.choice(edges) + rng.choice(edges))
for _ in range(400):  # several indicators in one record, incl. parents and children
    hays.append(" ".join(rng.choice(edges) + rng.choice(net) + rng.choice(edges) for _ in range(rng.randint(2, 5))))
cases = [[h, sorted(i.value for i in s.most_specific(s.search(h.lower())))] for h in hays]
json.dump({"export": export, "match": cases}, open(fx / "golden.json", "w", encoding="utf-8"), ensure_ascii=False, indent=0)
print("export records:", len(export), "match cases:", len(cases), "with hits:", sum(1 for c in cases if c[1]))
