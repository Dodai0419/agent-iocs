<div align="center">

# agent-iocs

**Check every domain and IP your coding agents touched against a spyware threat-intel list.**

Your agents run `curl`, read web pages and paste tool output into their logs. Zero-breach checks your browser for the AdFection / Candiru spyware indicators; agent-iocs runs the same check over your Claude Code and Codex session logs.

Works with **Claude Code** and **Codex**.

![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg) ![Status: prototype](https://img.shields.io/badge/status-prototype-orange.svg)

</div>

## Quick start
```bash
git clone https://github.com/Dodai0419/agent-iocs && cd agent-iocs
python agent_iocs.py scan        # reads ~/.claude/projects and ~/.codex/sessions
```
Demo on the bundled fake logs (`python agent_iocs.py scan tests/fixtures/claude/projects tests/fixtures/codex/sessions`):
```
HIT controlium.net [delivery/primary] claude-code tests/fixtures/claude/projects/-work-web/s-web.jsonl:3 2026-10-18T09:00:05Z
    ...let me fetch the tag. tool_use t1 bash curl -s https://cdn.controlium.net/tag.js | head...
HIT 52.174.65.77 [cc/primary] claude-code tests/fixtures/claude/projects/-work-web/s-web.jsonl:4 2026-10-18T09:00:07Z
HIT noas.powerium.net [delivery/primary] claude-code tests/fixtures/claude/projects/-work-web/s-web.jsonl:4 2026-10-18T09:00:07Z
HIT qa-noas.powerium.net [delivery/primary] codex tests/fixtures/codex/sessions/2026/10/18/rollout-2026-10-18-abc.jsonl:3 2026-10-18T11:00:04Z
4 hit(s) in 3 session file(s); 403 network indicators, list as-of 2026-10-18 (2 days old).
```
Exit code: 0 clean, 1 hits (`--exit-zero` to only report), 2 bad indicator file. Python 3.9+, standard library only, no network.

## The problem
- Agent logs pile up hundreds of MB of URLs, shell commands and fetched pages, and nobody reads them.
- Threat-intel scanners like zero-breach look at browsers, caches and DNS, not at what your agents fetched.
- Gluing a log exporter and a matcher together is slow: one full-text search per indicator over every message.

## The solution
| Idea | Fixes |
|------|-------|
| **Read the agents' own logs** (Claude Code projects, Codex rollouts), including tool calls and tool output | The blind spot: domains your agent contacted that never touched a browser |
| **zero-breach's boundary rules, unchanged** | `notcontrolium.net`, `controlium.network` and `152.174.65.771` do not match; `controlium.net.` does |
| **One-pass index** | Find each `.<last label>` an indicator ends with, then check only those spots. Clean files are never JSON-parsed |
| **Location for every hit** | File, line, timestamp, agent and 60 characters of context, or `--json` for scripts |

`python agent_iocs.py export > chats.jsonl` also writes your chat history in ai-data-extractor's normalized format (Claude Code and Codex only).

Bring your own list with `--iocs FILE`, one `indicator<TAB>tier<TAB>confidence[<TAB>source]` per line (zero-breach format). A missing, empty or malformed list is an error, never a clean result.

## Use with Claude Code
```bash
/plugin marketplace add Dodai0419/agent-iocs
/plugin install agent-iocs@agent-iocs
```
Then ask: "check my agent logs for spyware indicators".

## Use with Codex (ChatGPT)
```bash
git clone https://github.com/Dodai0419/agent-iocs && cp -r agent-iocs/skills/* ~/.codex/skills/
```
Or copy `AGENTS.md` into your project root.

## Benchmarks
Baseline = the two upstream tools glued together: ai-data-extractor's `claude_code.extract()` and then zero-breach's `most_specific(search())` on every message (`bench/bench.py`). Windows 11, Python 3.11.1, median of N runs, process start included.

| | ai-data-extractor + zero-breach | agent-iocs |
|-|-|-|
| 3 sessions, 43 MB, no hits (5 runs) | 4924 ms | 1548 ms |
| 48 sessions, 141 MB, one session with 67 hits (3 runs) | 14266 ms | 5591 ms |
| lines of code | 937 (claude_code.py, codex.py, common.py, iocs.py) | 326 (agent_iocs.py) |
| dependencies | 0 | 0 |

The plain approach of one full-text find per indicator took 16.6 s for 403 indicators over the same 43 MB; the index pass takes 0.03 to 0.05 s per 10 to 19 MB file.

Same results, checked three ways:
- `test_same_hits_as_zero_breach`: 2818 lookalike strings (every indicator with random prefixes and suffixes, plus mixed records) give exactly zero-breach's hits.
- `test_same_records_as_ai_data_extractor`: `export` on the fixtures gives the same records as ai-data-extractor.
- `python bench/parity.py <ai-data-extractor> <zero-breach> ~/.claude/projects` on my 48 real sessions: all 67 baseline hits found, 75 in total. The 8 extra come from fields the extractor drops (for example Claude Code's `toolUseResult` copy and Codex shell calls).

Found on the way: ai-data-extractor stops with `AttributeError` on a log line that is valid JSON but not an object (`tests/fixtures` has one). agent-iocs skips it.

## Limits
- "No known indicator found" is not a clean bill of health: it covers only these logs and this list. If you have real reason for concern, contact the [Access Now Digital Security Helpline](https://www.accessnow.org/help/).
- A hit means the name appears in a log (a fetched page, an output, your own question), not that a device was infected.
- Only Claude Code and Codex logs. The bundled list is zero-breach's AdFection / Candiru set as of 2026-10-18; it warns when the list is over 30 days old.

## Inspired by
- [jatechan/ai-data-extractor](https://github.com/jatechan/ai-data-extractor) (MIT): where Claude Code and Codex keep their logs and how to normalize them.
- [interplains/zero-breach](https://github.com/interplains/zero-breach) (Apache-2.0): the indicator format, the CC0 indicator list and the boundary-aware matching rules.

## Roadmap
- [ ] Cursor, Gemini CLI and OpenCode logs.
- [ ] hosts-file and adblock list formats for `--iocs`.

## License
Apache-2.0. See `NOTICE` for the upstream copyright notices. `iocs/adfection_iocs.txt` is CC0 indicator data from zero-breach (`iocs/LICENSE.md`). Not affiliated with zero-breach or with the researchers who published the indicators.
