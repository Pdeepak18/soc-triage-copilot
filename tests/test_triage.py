"""Tests for the triage engine, renderers, LLM layer and CLI."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
sys.path.insert(0, str(ROOT))

from soc_triage_copilot.llm import (  # noqa: E402
    OfflineProvider,
    ProviderError,
    build_prompt,
    generate_note,
    get_provider,
)
from soc_triage_copilot.models import Alert, Case  # noqa: E402
from soc_triage_copilot.render import to_json, to_markdown  # noqa: E402
from soc_triage_copilot.triage import collect_iocs, triage  # noqa: E402


@pytest.fixture(scope="module")
def ransomware():
    return Case.from_dict(json.loads((SAMPLES / "case-ransomware.json").read_text()))


@pytest.fixture(scope="module")
def bec():
    return Case.from_dict(json.loads((SAMPLES / "case-bec.json").read_text()))


def test_case_parsing(ransomware):
    assert ransomware.id == "INC-2026-1014"
    assert len(ransomware.alerts) == 3
    assert ransomware.highest_severity == "critical"
    assert ransomware.alerts[0].timestamp.year == 2026


def test_ransomware_chain_is_true_positive(ransomware):
    result = triage(ransomware)
    assert result.verdict == "likely_true_positive"
    assert result.risk_score >= 75
    ids = {finding.technique_id for finding in result.findings}
    assert {"T1490", "T1486", "T1562.001"} <= ids
    assert result.confidence in ("medium", "high")


def test_findings_carry_evidence_and_recommendations(ransomware):
    result = triage(ransomware)
    for finding in result.findings:
        assert finding.evidence
        assert finding.recommendation


def test_iocs_are_collected_and_deduplicated(ransomware):
    iocs = collect_iocs(ransomware.alerts)
    assert "FS-01" in iocs["host"]
    assert "10.20.4.11" in iocs["ip"]
    assert "3f786850e387550fdab836ed7e6dc881de23001b" in iocs["hash"]
    assert all(isinstance(values, list) for values in iocs.values())


def test_timeline_is_chronological(ransomware):
    result = triage(ransomware)
    times = [entry["time"] for entry in result.timeline]
    assert times == sorted(times)


def test_next_steps_include_containment(ransomware):
    result = triage(ransomware)
    joined = " ".join(result.next_steps).lower()
    assert "isolate" in joined or "contain" in joined
    assert "fs-01" in joined


def test_bec_case_maps_phishing_and_forwarding(bec):
    result = triage(bec)
    ids = {finding.technique_id for finding in result.findings}
    assert "T1566" in ids
    assert "T1114.003" in ids
    assert result.verdict in ("needs_review", "likely_true_positive")


def test_empty_case_is_handled():
    result = triage(Case(id="CASE-EMPTY", title="Empty"))
    assert result.verdict == "needs_review"
    assert result.risk_score == 0
    assert "no alerts" in result.summary.lower()


def test_offline_note_needs_no_network(ransomware):
    result = triage(ransomware)
    note = generate_note(ransomware, result, "offline")
    assert "risk" in note.lower()
    assert "Recommended actions" in note
    assert str(result.risk_score) in note


def test_provider_selection_errors_are_explicit():
    with pytest.raises(ProviderError):
        get_provider("does-not-exist")


def test_prompt_contains_only_structured_facts(ransomware):
    result = triage(ransomware)
    prompt = build_prompt(ransomware, result)
    payload = json.loads(prompt.split("\n\n", 1)[1])
    assert payload["case"]["id"] == ransomware.id
    assert payload["findings"][0]["technique_id"].startswith("T")


def test_markdown_report_has_all_sections(ransomware):
    result = triage(ransomware)
    note = generate_note(ransomware, result, "offline")
    markdown = to_markdown(ransomware, result, note)
    for heading in ("# Triage note", "## ATT&CK coverage", "## Timeline", "## Next steps", "## Indicators"):
        assert heading in markdown


def test_json_report_round_trips(ransomware):
    result = triage(ransomware)
    payload = json.loads(to_json(ransomware, result, "note"))
    assert payload["case"]["id"] == ransomware.id
    assert payload["triage"]["risk_score"] == result.risk_score
    assert payload["note"] == "note"


def test_cli_writes_json(tmp_path):
    out = tmp_path / "report.json"
    code = subprocess.run(
        [sys.executable, "-m", "soc_triage_copilot.cli", "triage",
         str(SAMPLES / "case-ransomware.json"), "--format", "json", "--out", str(out)],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert code.returncode == 0, code.stderr
    payload = json.loads(out.read_text())
    assert payload["triage"]["verdict"] == "likely_true_positive"


def test_cli_fail_on_true_positive_exits_two():
    result = subprocess.run(
        [sys.executable, "-m", "soc_triage_copilot.cli", "triage",
         str(SAMPLES / "case-ransomware.json"), "--fail-on-true-positive"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 2


def test_offline_provider_is_a_noop_passthrough():
    provider = OfflineProvider()
    assert provider.complete("system", "prompt text") == "prompt text"


def test_alert_severity_defaults_are_safe():
    alert = Alert.from_dict({"rule": "suspicious sign-in"})
    assert alert.severity == "medium"
    assert alert.entities == {}
