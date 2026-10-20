#!/usr/bin/env python3
"""agent-iocs: check every domain and IP your coding agents touched against a threat-intel list.

    python agent_iocs.py scan                      # ~/.claude and ~/.codex session logs vs the bundled list
    python agent_iocs.py scan PATH... --iocs FILE  # your own log folders / indicator file
    python agent_iocs.py export > chats.jsonl      # the normalized chat history, one session per line

Indicator file format (zero-breach): `indicator <TAB> tier <TAB> confidence [<TAB> source]`.
Session parsing follows jatechan/ai-data-extractor; IOC loading and boundary-aware matching
follow interplains/zero-breach (Apache-2.0). Standard library only. Reads files, never the network.
"""
import argparse, datetime, json, os, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_IOCS = HERE / "iocs" / "adfection_iocs.txt"
VALID_TIERS = {"cc", "validator", "delivery", "historical", "sample", "vuln-driver", "candiru", "candiru-ip"}
VALID_CONFIDENCE = {"primary", "secondary"}

# --- indicators (zero-breach iocs.py) ---------------------------------------------------
_LABEL = set("abcdefghijklmnopqrstuvwxyz0123456789-")
_LABEL_US = _LABEL | {"_"}
_NAME = _LABEL_US | {"."}
_DIGIT = set("0123456789")
_HEX = set("0123456789abcdef")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_ASOF = re.compile(r"^#\s*as-of:\s*(\d{4}-\d{2}-\d{2})\s*$")


def infer_type(v):
    if re.match(r"^[0-9a-f]{64}$", v):
        return "sha256"
    if _IPV4.match(v) or (":" in v and all(c in "0123456789abcdef:" for c in v)):
        return "ip"
    return "domain"


class IocError(Exception):
    pass


def load_iocs(path):
    """-> (indicators sorted by value, as-of date or None). Each indicator is a dict."""
    seen, asof = {}, None
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()  # -sig: Windows editors add a BOM
    except OSError as e:
        raise IocError("cannot read IOC file: {}".format(e))
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            m = _ASOF.match(line)
            asof = m.group(1) if m else asof
            continue
        parts = [p.strip() for p in line.split("\t") if p.strip()]
        if len(parts) < 3:
            raise IocError("line {}: expected 3 or 4 tab-separated columns, got {!r}".format(n, line))
        value, tier, conf = parts[0].lower(), parts[1], parts[2]
        if tier not in VALID_TIERS:
            raise IocError("line {}: unknown tier {!r}".format(n, tier))
        if conf not in VALID_CONFIDENCE:
            raise IocError("line {}: unknown confidence {!r}".format(n, conf))
        if any(c in value for c in "\ufeff\u200b\u200c\u200d\u2060"):
            raise IocError("line {}: invisible character in {!r}".format(n, value))
        kind = infer_type(value)
        if kind == "domain":
            value = value.rstrip(".")
            if not value.isascii():
                try:
                    value = value.encode("idna").decode("ascii")  # logs record punycode
                except UnicodeError:
                    raise IocError("line {}: {!r} is not a valid domain name".format(n, value))
        seen[value] = {"indicator": value, "tier": tier, "confidence": conf, "type": kind,
                       "source": parts[3] if len(parts) > 3 else ""}
    if not seen:  # an empty list must never print "clean"
        raise IocError("indicator file contains no indicators: {}".format(path))
    return [seen[k] for k in sorted(seen)], asof


def _bad_sets(value, kind):
    if kind == "ip":
        return (_HEX | {":", "."}, _HEX | {":"}, _HEX) if ":" in value else (_DIGIT | {"."}, _DIGIT, _DIGIT)
    return _LABEL_US, _LABEL_US, _LABEL


def _positions(hay, ind):
    """Offsets where ind occurs as a whole name/number: notcontrolium.net and
    controlium.network do not match controlium.net; controlium.net. (FQDN) does."""
    needle = ind["indicator"]
    left_bad, right_bad, cont = _bad_sets(needle, ind["type"])
    out, i = [], hay.find(needle)
    while i != -1:
        j = i + len(needle)
        ok = i == 0 or hay[i - 1] not in left_bad
        if ok and j < len(hay):
            ok = hay[j] not in right_bad and (hay[j] != "." or j + 1 >= len(hay) or hay[j + 1] not in cont)
        if ok:
            out.append(i)
        i = hay.find(needle, i + 1)
    return out


_JSON_ESC = re.compile(r"[\\](?:u[0-9a-f]{4}|.)")


def _tail_re(values, after):
    tails = sorted({v.rsplit(".", 1)[-1] for v in values}, key=len, reverse=True)
    return re.compile(r"\.(?:%s)(?!%s)" % ("|".join(map(re.escape, tails)) or "(?!)", after))


class Index:
    """Which indicators can occur in a text, from two regex passes instead of one
    full-text find per indicator (403 finds over 43 MB of logs: 16.6 s).
    Find each ".<last label>" an indicator ends with (a literal-dot regex is fast), walk
    left over the characters a name or address can hold, and try every dot-suffix.
    Always a superset of the real matches; search() applies the exact boundary rules."""

    def __init__(self, net):
        self.by_value = {i["indicator"]: i for i in net}
        dotted = [i for i in net if "." in i["indicator"] and ":" not in i["indicator"]]
        self.walks = [(_tail_re([i["indicator"] for i in dotted if i["type"] == t], after), chars, cap)
                      for t, after, chars, cap in (("domain", "[a-z0-9_-]", _NAME, 253),  # 253 = longest DNS name
                                                   ("ip", "[0-9]", _DIGIT | {"."}, 12))]   # 12 = "255.255.255."
        # IPv6 and dotless names: plain find (none in the bundled list)
        self.other = [i for i in net if ":" in i["indicator"] or "." not in i["indicator"]]

    def candidates(self, text):
        hit = {i["indicator"] for i in self.other if i["indicator"] in text}
        for regex, chars, cap in self.walks:
            for m in regex.finditer(text):
                i = m.start()
                while i > 0 and m.start() - i < cap and text[i - 1] in chars:
                    i -= 1
                labels = text[i:m.end()].split(".")
                hit.update(v for v in (".".join(labels[s:]) for s in range(len(labels) - 1)) if v in self.by_value)
        return [self.by_value[v] for v in sorted(hit)]


def search(hay, net):
    """Indicators present in one lower-cased record, most specific only (zero-breach's
    most_specific(search(record))): noas.powerium.net is one contact, not also powerium.net."""
    found = [ind for ind in net if ind["indicator"] in hay and _positions(hay, ind)]
    vals = {i["indicator"] for i in found}
    return [i for i in found if i["type"] != "domain" or not any(v.endswith("." + i["indicator"]) for v in vals)]


# --- sessions (ai-data-extractor claude_code.py / codex.py) ------------------------------
def _app_roots():
    home = Path.home()
    if sys.platform == "darwin":
        roots = [home / "Library" / "Application Support"]
    elif sys.platform == "win32":
        roots = [Path(os.environ[k]) for k in ("APPDATA", "LOCALAPPDATA") if os.environ.get(k)]
    else:
        roots = [Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")),
                 Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share"))]
    return [r for r in roots + [home] if r.exists()]


def _found(names):
    return list(dict.fromkeys(r / n for r in _app_roots() for n in names if (r / n).exists()))


def session_files(paths=None):
    """-> [(source, file)] in the same order ai-data-extractor visits them."""
    out = []
    claude = [p / "projects" for p in _found([".claude", ".claude-code", ".claude-local", ".claude-m2", ".claude-zai"])]
    codex = [p / "sessions" if (p / "sessions").exists() else p for p in _found([".codex", ".codex-local"])]
    if paths:  # a folder of project dirs (like ~/.claude/projects) or of Codex rollouts
        claude = [Path(p) for p in paths if any(Path(p).glob("*/*.jsonl"))]
        codex = [Path(p) for p in paths if any(Path(p).rglob("rollout-*.jsonl"))]
    for d in claude:
        for proj in (d.iterdir() if d.exists() else []):
            if proj.is_dir():
                out += [("claude-code", f) for f in proj.glob("*.jsonl")]
    for d in codex:
        if d.exists():
            files = list(d.rglob("rollout-*.jsonl")) or list(d.rglob("*.jsonl"))
            out += [("codex", f) for f in files]
    return out


def read_events(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            try:
                ev = json.loads(line) if line.strip() else None
            except json.JSONDecodeError:
                continue
            if isinstance(ev, dict):
                yield line_no, ev


def _claude_message(ev):
    msg = ev.get("message") or {}
    content = msg.get("content")
    texts, uses, results = ([content], [], []) if isinstance(content, str) else ([], [], [])
    for b in content if isinstance(content, list) else []:
        t = b.get("type") if isinstance(b, dict) else None
        if t == "text":
            texts.append(b.get("text", ""))
        elif t == "tool_use":
            uses.append({"name": b.get("name"), "input": b.get("input"), "id": b.get("id")})
        elif t == "tool_result":
            results.append({"tool_use_id": b.get("tool_use_id"), "content": b.get("content"),
                            "is_error": b.get("is_error", False)})
    entry = {"role": msg.get("role", ev.get("type")), "content": "\n".join(t for t in texts if t),
             "timestamp": ev.get("timestamp")}
    if uses:
        entry["tool_use"] = uses
    if results:
        entry["tool_results"] = results
    return entry


def _codex_message(ev):
    for cand in (ev.get("payload") if isinstance(ev.get("payload"), dict) else None, ev):
        if not (cand and cand.get("role") and cand.get("content") is not None):
            continue
        c, text = cand["content"], None
        if isinstance(c, str):
            text = c
        elif isinstance(c, list):
            text = "\n".join(b.get("text", "") for b in c
                             if isinstance(b, dict) and b.get("type") in ("text", "input_text", "output_text")) or None
        if text is not None:
            ok = cand["role"] in ("user", "assistant")
            return {"role": cand["role"], "content": text, "timestamp": ev.get("timestamp")} if ok else None
    return None


def conversation(source, path):
    """One session as ai-data-extractor's normalized record, or None if it has no messages."""
    msgs, sid, cwd = [], path.stem, None
    for _, ev in read_events(path):
        if source == "claude-code":
            cwd, sid = cwd or ev.get("cwd"), ev.get("sessionId", sid)
            if ev.get("type") in ("user", "assistant"):
                msgs.append(_claude_message(ev))
        elif ev.get("type") == "session_meta":
            meta = ev.get("payload", ev)
            cwd, sid = meta.get("cwd", cwd), meta.get("id", sid)
        else:
            m = _codex_message(ev)
            msgs += [m] if m else []
    if not msgs:
        return None
    return {"messages": msgs, "source": source, "session_id": sid, "project_path": cwd,
            "name": path.parent.name if source == "claude-code" else path.stem,
            "created_at": msgs[0].get("timestamp")}


# --- scan -------------------------------------------------------------------------------
def _strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for v in x.values():
            yield from _strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from _strings(v)


def scan(files, net):
    """-> hits, one per (event, indicator). Files with no candidate are never JSON-parsed."""
    index, hits = Index(net), []
    for source, path in files:
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        if not index.candidates(_JSON_ESC.sub(" ", raw)):  # "\ncontrolium.net" in raw JSON is a newline + name
            continue
        for line_no, ev in read_events(path):
            text = "\n".join(_strings(ev)).lower()
            for ind in search(text, index.candidates(text)):
                at = _positions(text, ind)[0]
                hits.append(dict(ind, file=str(path), line=line_no, agent=source,
                                 timestamp=ev.get("timestamp"), project=ev.get("cwd"),
                                 context=" ".join(text[max(0, at - 60):at + len(ind["indicator"]) + 60].split())))
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("command", choices=["scan", "export"])
    ap.add_argument("paths", nargs="*", help="log folders (default: auto-discover ~/.claude and ~/.codex)")
    ap.add_argument("--iocs", default=str(DEFAULT_IOCS), help="indicator file (zero-breach format)")
    ap.add_argument("--json", action="store_true", help="scan: one JSON hit per line")
    ap.add_argument("--exit-zero", action="store_true", help="scan: exit 0 even with hits (report only)")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):  # logs hold any language; a cp949/cp1252 pipe would crash mid-report
        sys.stdout.reconfigure(encoding="utf-8")
    files = session_files(a.paths)
    if a.command == "export":
        for source, f in files:
            c = conversation(source, f)
            if c:
                sys.stdout.write(json.dumps(c, ensure_ascii=False) + "\n")
        return 0
    try:
        iocs, asof = load_iocs(a.iocs)
    except IocError as e:
        print("error: {}".format(e), file=sys.stderr)
        return 2
    net = [i for i in iocs if i["type"] != "sha256"]
    hits = scan(files, net)
    if a.json:
        for h in hits:
            print(json.dumps(h, ensure_ascii=False))
        return 1 if hits and not a.exit_zero else 0
    for h in hits:
        print("HIT {indicator} [{tier}/{confidence}] {agent} {file}:{line} {timestamp}\n    ...{context}...".format(**h))
    age = (datetime.date.today() - datetime.date.fromisoformat(asof)).days if asof else None
    print("{} hit(s) in {} session file(s); {} network indicators{}.".format(
        len(hits), len(files), len(net), ", list as-of {} ({} days old)".format(asof, age) if asof else ""))
    if age is not None and age > 30:
        print("warning: the indicator list is over 30 days old; update it.")
    if not hits:
        print("No known indicator found. That is not proof of a clean machine: it only covers these logs and this list.")
    return 1 if hits and not a.exit_zero else 0


if __name__ == "__main__":
    sys.exit(main())
