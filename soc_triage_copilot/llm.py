"""Optional LLM layer.

The triage engine decides; a model may only rewrite the result. Providers are
opt-in per run (``--llm openai``) and the offline provider is the default, so a
real case never leaves the analyst's machine by accident.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

SYSTEM_PROMPT = (
    "You are a tier-2 SOC analyst writing an internal triage note. "
    "Use only the facts provided. Never invent hostnames, users, IPs or timings. "
    "Be concise: a short paragraph plus 3-5 prioritised actions. "
    "State explicitly when the evidence is insufficient."
)


@dataclass
class ProviderConfig:
    name: str
    model: str
    endpoint: str | None = None
    api_key: str | None = None


class ProviderError(RuntimeError):
    """Raised when a provider is unavailable or misconfigured."""


class BaseProvider:
    name = "base"

    def complete(self, system: str, prompt: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class OfflineProvider(BaseProvider):
    """Deterministic narrative built from the triage result. Always available."""

    name = "offline"

    def __init__(self, result=None):
        self.result = result

    def complete(self, system: str, prompt: str) -> str:
        return prompt


class OpenAIProvider(BaseProvider):
    name = "openai"

    def __init__(self, model: str | None = None, api_key: str | None = None, endpoint: str | None = None):
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.endpoint = endpoint or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if not self.api_key:
            raise ProviderError("OPENAI_API_KEY is not set")

    def complete(self, system: str, prompt: str) -> str:
        requests = _requests()
        response = requests.post(
            f"{self.endpoint.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=45,
        )
        if response.status_code != 200:
            raise ProviderError(f"OpenAI HTTP {response.status_code}: {response.text[:200]}")
        return response.json()["choices"][0]["message"]["content"].strip()


class AzureOpenAIProvider(BaseProvider):
    name = "azure"

    def __init__(self, deployment: str | None = None, api_key: str | None = None, endpoint: str | None = None):
        self.deployment = deployment or os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
        self.api_key = api_key or os.getenv("AZURE_OPENAI_KEY", "")
        self.endpoint = endpoint or os.getenv("AZURE_OPENAI_ENDPOINT", "")
        if not (self.api_key and self.endpoint and self.deployment):
            raise ProviderError("set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_KEY and AZURE_OPENAI_DEPLOYMENT")

    def complete(self, system: str, prompt: str) -> str:
        requests = _requests()
        url = (
            f"{self.endpoint.rstrip('/')}/openai/deployments/{self.deployment}"
            f"/chat/completions?api-version=2024-06-01"
        )
        response = requests.post(
            url,
            headers={"api-key": self.api_key},
            json={
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=45,
        )
        if response.status_code != 200:
            raise ProviderError(f"Azure OpenAI HTTP {response.status_code}: {response.text[:200]}")
        return response.json()["choices"][0]["message"]["content"].strip()


class OllamaProvider(BaseProvider):
    """Local model via Ollama - the only provider where data stays on the host."""

    name = "ollama"

    def __init__(self, model: str | None = None, endpoint: str | None = None):
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1")
        self.endpoint = endpoint or os.getenv("OLLAMA_HOST", "http://localhost:11434")

    def complete(self, system: str, prompt: str) -> str:
        requests = _requests()
        response = requests.post(
            f"{self.endpoint.rstrip('/')}/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "options": {"temperature": 0.2},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=90,
        )
        if response.status_code != 200:
            raise ProviderError(f"Ollama HTTP {response.status_code}: {response.text[:200]}")
        return response.json()["message"]["content"].strip()


def _requests():
    try:
        import requests
    except ImportError as exc:  # pragma: no cover
        raise ProviderError("install requests to use an LLM provider: pip install requests") from exc
    return requests


def get_provider(name: str) -> BaseProvider:
    name = (name or "offline").lower()
    if name in ("offline", "none", ""):
        return OfflineProvider()
    if name == "openai":
        return OpenAIProvider()
    if name == "azure":
        return AzureOpenAIProvider()
    if name == "ollama":
        return OllamaProvider()
    raise ProviderError(f"unknown provider '{name}' (choose offline, openai, azure or ollama)")


def build_prompt(case, result) -> str:
    """Serialise the structured triage output as the model's only source of truth."""
    payload = {
        "case": {
            "id": case.id,
            "title": case.title,
            "source": case.source,
            "tags": case.tags,
            "severity": result.severity,
            "risk_score": result.risk_score,
            "verdict": result.verdict,
            "confidence": result.confidence,
        },
        "alerts": [
            {"rule": a.rule, "severity": a.severity, "time": a.timestamp.isoformat(),
             "description": a.description, "entities": a.entities}
            for a in case.alerts
        ],
        "findings": [f.as_dict() for f in result.findings],
        "indicators": result.iocs,
        "next_steps": result.next_steps,
    }
    return (
        "Write the triage note from this structured analysis. Do not add facts.\n\n"
        + json.dumps(payload, indent=2, default=str)
    )


def generate_note(case, result, provider_name: str = "offline") -> str:
    provider = get_provider(provider_name)
    prompt = build_prompt(case, result)
    if provider.name == "offline":
        return _offline_note(case, result)
    return provider.complete(SYSTEM_PROMPT, prompt)


def _offline_note(case, result) -> str:
    lines = [
        f"{result.verdict.replace('_', ' ').title()} - risk {result.risk_score}/100, "
        f"confidence {result.confidence}.",
        result.summary,
    ]
    if result.findings:
        primary = result.findings[0]
        lines.append(
            f"Lead technique is {primary.technique_id} ({primary.technique_name}) under {primary.tactic}; "
            f"evidence: {primary.evidence[0]}."
        )
    if result.iocs:
        preferred = ("host", "user", "domain", "url", "hash", "ip", "file")
        key = next((k for k in preferred if result.iocs.get(k)), sorted(result.iocs)[0])
        lines.append(
            f"Start with {result.iocs[key][0]} ({key}) - it is the fastest pivot in this case."
        )
    lines.append("Recommended actions:")
    lines.extend(f"{index}. {step}" for index, step in enumerate(result.next_steps, start=1))
    return "\n".join(lines)
