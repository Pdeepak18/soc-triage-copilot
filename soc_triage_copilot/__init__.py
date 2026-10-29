"""soc-triage-copilot - turn raw alerts into an ATT&CK-mapped triage note."""

from __future__ import annotations

__version__ = "0.1.0"

from .models import Alert, Case  # noqa: F401
from .triage import TriageResult, triage  # noqa: F401
