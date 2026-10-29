# soc-triage-copilot

Turns a raw alert case into a structured, ATT&CK-mapped triage note — the first
15 minutes of L2 work, done consistently. The verdict is **rule-based**; an LLM
may only rewrite the result as prose, and only when you explicitly ask for it.

```console
$ soc-triage-copilot triage samples/case-ransomware.json
# Triage note — INC-2026-1014

**Likely true positive** · risk **100/100** · confidence **high** · severity **critical**

**Case:** Ransomware staging on file server FS-01
**Alerts:** 3 · **Techniques:** 4 · **Indicators:** 7

## ATT&CK coverage of this case

| Technique | Name | Tactic | Confidence | Evidence |
|---|---|---|---|---|
| T1486 | Data Encrypted for Impact | Impact | medium | Ransomware extension burst @ 02:13:44 |
| T1490 | Inhibit System Recovery | Impact | medium | Shadow copy deletion via vssadmin @ 02:11:12 |
| T1562.001 | Disable or Modify Tools | Defense Evasion | medium | Defender exclusion added @ 02:10:03 |
| T1059.001 | PowerShell | Execution | medium | Defender exclusion added @ 02:10:03 |

## Next steps
1. Re-enable protection, capture the exclusion list, and treat the host as compromised.
2. Isolate the host, snapshot disk state, and check backup integrity before any restore.
3. Contain affected host(s): FS-01 - isolate from the network before eradication.
...
```

## Why it exists

L2 analysts spend their first minutes on the same mechanical steps for every
case: read the alerts, work out which techniques are in play, pull the indicators,
decide whether the alerts corroborate each other, and write it up. That work is
high-volume, easy to do inconsistently, and mostly copy-paste.

This tool does the mechanical part deterministically and leaves judgement to the
analyst. It is deliberately small: a mapping table you can read in two minutes
beats a 40 MB ATT&CK bundle you cannot audit.

## How it works

```
case.json ──► models.py ──► attack.py   (keyword → technique mapping)
                   │              │
                   │              ▼
                   └──────► triage.py  (verdict, risk score, IOCs, next steps)
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
             render.py (markdown/JSON)     llm.py (optional prose)
```

1. **Parse** — alerts, entities and timestamps are validated into dataclasses.
2. **Map** — each alert is matched against a curated technique table; multiple
   alerts for one technique raise its confidence.
3. **Score** — severity base + critical-technique bonus + corroboration bonus,
   capped at 100. Verdict bands: `likely_false_positive` < 40 ≤ `needs_review`
   < 75 ≤ `likely_true_positive`, and two critical techniques force a true
   positive regardless of score.
4. **Extract** — hosts, users, IPs, hashes, URLs and domains are normalised and
   de-duplicated; private IPs are treated as internal pivots, not block targets.
5. **Render** — a ticket-ready markdown note or a JSON payload for SOAR.

## Install

```bash
git clone https://github.com/Pdeepak18/soc-triage-copilot.git
cd soc-triage-copilot
python -m pip install -e .
```

Python 3.9+. No runtime dependencies. Optional extras:

```bash
pip install -e ".[llm]"   # requests, for OpenAI / Azure / Ollama providers
pip install -e ".[api]"   # FastAPI + uvicorn
```

## Usage

```bash
# offline, deterministic, no network
soc-triage-copilot triage samples/case-ransomware.json

# add the analyst note paragraph
soc-triage-copilot triage samples/case-ransomware.json --note

# JSON for a SOAR playbook
soc-triage-copilot triage samples/case-bec.json --format json --out report.json

# use a local model via Ollama (data never leaves the host)
soc-triage-copilot triage case.json --llm ollama

# OpenAI / Azure OpenAI (explicit opt-in, case facts are sent to the model)
export OPENAI_API_KEY=...
soc-triage-copilot triage case.json --llm openai

# automation: exit 2 when the case needs immediate escalation
soc-triage-copilot triage case.json --fail-on-true-positive
```

### HTTP API

```bash
pip install -e ".[api]"
uvicorn soc_triage_copilot.api:app --reload

curl -s localhost:8000/triage -H 'content-type: application/json' \
  -d "{\"case\": $(cat samples/case-bec.json)}" | jq .triage.verdict
```

### Case input format

```json
{
  "id": "INC-2026-1014",
  "title": "Ransomware staging on file server FS-01",
  "source": "Microsoft Sentinel",
  "created_at": "2026-10-21T02:14:00Z",
  "tags": ["ransomware", "priority-1"],
  "alerts": [
    {
      "rule": "Shadow copy deletion via vssadmin",
      "severity": "high",
      "timestamp": "2026-10-21T02:11:12Z",
      "description": "vssadmin.exe delete shadows /all /quiet",
      "entities": {"host": "FS-01", "user": "CORP\\svc_backup", "ip": "10.20.4.11"}
    }
  ]
}
```

Only `id`, `title` and `alerts[].rule` are required; everything else degrades
gracefully.

## Safety model

| Concern | Behaviour |
|---|---|
| Case data leaving the host | Never, unless `--llm openai` or `--llm azure` is passed explicitly |
| Model inventing facts | The prompt contains only the structured triage output and instructs the model not to add facts; the verdict is computed before any model call |
| Hallucinated indicators | Indicators come from deterministic regex extraction, not from the model |
| Provider failure | Falls back to the offline note with a warning; the run still succeeds |

## Tests

```bash
python -m pytest -q      # 17 tests
```

The suite covers parsing, the ransomware kill-chain verdict, IOC extraction,
timeline ordering, the offline note, provider errors, both renderers, and the CLI
including its exit codes.

## Layout

```
soc_triage_copilot/
  models.py   Case / Alert dataclasses and JSON validation
  attack.py   15-technique mapping table with recommendations
  triage.py   verdict, risk score, IOCs, timeline, next steps
  llm.py      offline/openai/azure/ollama providers + prompt builder
  render.py   markdown and JSON renderers
  cli.py      argparse entry point
  api.py      optional FastAPI surface
samples/      ransomware kill chain and BEC cases
tests/
```

## License

MIT — see [LICENSE](LICENSE).
