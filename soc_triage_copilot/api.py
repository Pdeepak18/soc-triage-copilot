"""Minimal HTTP surface for SOAR / ticketing integrations.

FastAPI is optional: the core package stays dependency-free. Install the extra
with ``pip install -e ".[api]"`` and run ``uvicorn soc_triage_copilot.api:app``.
"""

from __future__ import annotations

from typing import Any

from .llm import ProviderError, generate_note
from .models import Case
from .render import to_markdown
from .triage import triage

try:  # pragma: no cover - exercised only when the api extra is installed
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except ImportError:  # pragma: no cover
    FastAPI = None  # type: ignore
    HTTPException = None  # type: ignore
    BaseModel = object  # type: ignore


if FastAPI is not None:

    app = FastAPI(
        title="soc-triage-copilot",
        version="0.1.0",
        description="Rule-based triage with an optional LLM note. Verdicts never come from the model.",
    )

    class TriageRequest(BaseModel):
        case: dict[str, Any]
        llm: str = "offline"

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/triage")
    def triage_endpoint(request: TriageRequest) -> dict[str, Any]:
        case = Case.from_dict(request.case)
        if not case.alerts:
            raise HTTPException(status_code=422, detail="case contains no alerts")
        result = triage(case)

        note = None
        if request.llm != "offline":
            try:
                note = generate_note(case, result, request.llm)
            except ProviderError as exc:
                note = f"provider unavailable: {exc}"

        return {
            "case_id": case.id,
            "triage": result.as_dict(),
            "note": note,
            "markdown": to_markdown(case, result, note),
        }

else:  # pragma: no cover
    app = None
