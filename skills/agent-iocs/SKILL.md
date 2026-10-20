---
name: agent-iocs
description: Check Claude Code and Codex session logs for known spyware domains and IPs (zero-breach indicator list, or your own) and report file, line and time of each hit. Use for "did my agent contact anything malicious", "scan my agent logs for IOCs", "export my chat history".
---

# agent-iocs

Use agent-iocs when someone wants to know whether their coding agents fetched, ran or printed a known-bad domain or IP, wants their agent logs checked against a threat-intel list, or wants their Claude Code / Codex chat history exported as JSONL. Run the CLI; do not grep the logs by hand (they are large and the boundary rules matter).

## Commands (run from the repo root; Python 3.9+, no dependencies, no network)

```bash
python agent_iocs.py scan                          # ~/.claude/projects and ~/.codex/sessions vs the bundled list
python agent_iocs.py scan PATH...                  # specific log folders (a Claude projects dir or a Codex sessions dir)
python agent_iocs.py scan --iocs my_list.txt       # your own list: indicator<TAB>tier<TAB>confidence[<TAB>source]
python agent_iocs.py scan --json                   # one JSON object per hit
python agent_iocs.py export > chats.jsonl          # normalized chat history, one session per line
```

Exit codes: 0 no hits, 1 hits (`--exit-zero` keeps 0), 2 the indicator file is missing, empty or malformed.

## How to report
- For each hit give the indicator, its tier and confidence, the file:line and the timestamp, and quote the context line.
- A hit means the name appears in the log (fetched page, command, output or the user's own text). It is not proof of infection. Say so.
- "No known indicator found" is not a clean bill of health. Say that too, and point people with real concern to the Access Now Digital Security Helpline (https://www.accessnow.org/help/).
- Never delete or edit log files. The tool only reads.
