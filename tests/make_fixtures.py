"""Writes the synthetic agent logs in tests/fixtures/ (run once; output is committed)."""
import json
from pathlib import Path

F = Path(__file__).resolve().parent / "fixtures"


def dump(path, events):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")


def cc(kind, content, ts, **kw):
    return dict({"type": kind, "sessionId": "s-web", "cwd": "/work/web", "timestamp": ts,
                 "message": {"role": kind, "content": content}}, **kw)


dump(F / "claude" / "projects" / "-work-web" / "s-web.jsonl", [
    {"type": "summary", "summary": "fix ads script", "cwd": "/work/web"},
    cc("user", "The ad tag loads slowly, check it", "2026-10-18T09:00:00Z"),
    cc("assistant", [{"type": "text", "text": "Let me fetch the tag."},
                     {"type": "tool_use", "id": "t1", "name": "Bash",
                      "input": {"command": "curl -s https://cdn.Controlium.net/tag.js | head"}}], "2026-10-18T09:00:05Z"),
    cc("user", [{"type": "tool_result", "tool_use_id": "t1", "is_error": False,
                 "content": "// served by noas.powerium.net edge 52.174.65.77\nvar x=1;"}], "2026-10-18T09:00:07Z"),
    cc("assistant", [{"type": "text", "text": "Lookalikes that must not match: notcontrolium.net, "
                                              "controlium.network, 152.174.65.771, controlium.net.evil.example"}],
       "2026-10-18T09:00:09Z"),
    "not json at all",
])
dump(F / "claude" / "projects" / "-work-clean" / "s-clean.jsonl", [
    cc("user", "add a unit test", "2026-10-18T10:00:00Z", sessionId="s-clean", cwd="/work/clean"),
    cc("assistant", [{"type": "text", "text": "Done, see https://example.com/docs"}], "2026-10-18T10:00:03Z",
       sessionId="s-clean", cwd="/work/clean"),
])
dump(F / "codex" / "sessions" / "2026" / "10" / "18" / "rollout-2026-10-18-abc.jsonl", [
    {"type": "session_meta", "timestamp": "2026-10-18T11:00:00Z", "payload": {"id": "cx-1", "cwd": "/work/api"}},
    {"type": "response_item", "timestamp": "2026-10-18T11:00:01Z",
     "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "why is DNS slow?"}]}},
    {"type": "response_item", "timestamp": "2026-10-18T11:00:04Z",
     "payload": {"type": "function_call", "name": "shell", "arguments": "{\"cmd\": \"dig qa-noas.powerium.net\"}"}},
    {"type": "response_item", "timestamp": "2026-10-18T11:00:06Z",
     "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Resolver timed out."}]}},
])
