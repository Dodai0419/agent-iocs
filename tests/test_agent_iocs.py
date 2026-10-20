import io, json, sys, tempfile, unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_iocs as ai  # noqa: E402

FX = ROOT / "tests" / "fixtures"
LOGS = [str(FX / "claude" / "projects"), str(FX / "codex" / "sessions")]
GOLDEN = json.loads((FX / "golden.json").read_text(encoding="utf-8"))
IOCS, ASOF = ai.load_iocs(ai.DEFAULT_IOCS)
NET = [i for i in IOCS if i["type"] != "sha256"]


def run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = ai.main(list(argv))
    return code, buf.getvalue()


class Matching(unittest.TestCase):
    def test_same_hits_as_zero_breach(self):
        # golden = most_specific(search(record)) from zero-breach on 2818 lookalike strings
        index = ai.Index(NET)
        for hay, want in GOLDEN["match"]:
            self.assertEqual(sorted(i["indicator"] for i in ai.search(hay.lower(), NET)), want, hay)
            self.assertEqual(sorted(i["indicator"] for i in ai.search(hay.lower(), index.candidates(hay.lower()))), want, hay)

    def test_index_sees_through_json_escapes(self):
        raw = json.dumps({"t": "x\ncontrolium.net\t52.174.65.77\u00a0powerium.net"}).lower()
        hits = ai.Index(NET).candidates(ai._JSON_ESC.sub(" ", raw))
        self.assertEqual([i["indicator"] for i in hits], ["52.174.65.77", "controlium.net", "powerium.net"])

    def test_lookalikes_do_not_match(self):
        hay = "notcontrolium.net controlium.network 152.174.65.771 controlium.net.evil.example"
        self.assertEqual(ai.search(hay, NET), [])
        self.assertEqual([i["indicator"] for i in ai.search("ping controlium.net.", NET)], ["controlium.net"])


class Export(unittest.TestCase):
    def test_same_records_as_ai_data_extractor(self):
        code, out = run("export", *LOGS)
        self.assertEqual(code, 0)
        self.assertEqual([json.loads(l) for l in out.splitlines()], GOLDEN["export"])


class Scan(unittest.TestCase):
    def test_hits_with_location(self):
        code, out = run("scan", *LOGS, "--json")
        hits = [json.loads(l) for l in out.splitlines()]
        self.assertEqual(code, 1)
        self.assertEqual(sorted((Path(h["file"]).name, h["line"], h["indicator"]) for h in hits), [
            ("rollout-2026-10-18-abc.jsonl", 3, "qa-noas.powerium.net"),  # a Codex shell call
            ("s-web.jsonl", 3, "controlium.net"),
            ("s-web.jsonl", 4, "52.174.65.77"),
            ("s-web.jsonl", 4, "noas.powerium.net"),
        ])

    def test_clean_logs_exit_0(self):
        code, out = run("scan", str(FX / "claude" / "projects" / "-work-clean" / ".."), "--iocs",
                        str(self._list("example.org\tcc\tprimary\n")))
        self.assertEqual(code, 0)
        self.assertIn("not proof of a clean machine", out)

    def test_bad_or_empty_list_refuses(self):
        for text in ("# only comments\n", "evil.example\tbogus\tprimary\n", "\ufeffevil.example\tcc\n"):
            code, _ = run("scan", *LOGS, "--iocs", str(self._list(text)))
            self.assertEqual(code, 2, text)

    def test_bom_and_idna(self):
        iocs, _ = ai.load_iocs(self._list("\ufeffB\u00fccher.example\tcc\tprimary\n"))
        self.assertEqual(iocs[0]["indicator"], "xn--bcher-kva.example")

    def _list(self, text):
        d = Path(tempfile.mkdtemp())
        (d / "iocs.txt").write_text(text, encoding="utf-8")
        return d / "iocs.txt"


if __name__ == "__main__":
    unittest.main()
