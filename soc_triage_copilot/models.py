"""Typed case model - the contract between the CLI, the triage engine and the API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class Alert:
    rule: str
    severity: str = "medium"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""
    entities: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Alert":
        return cls(
            rule=str(raw.get("rule") or raw.get("title") or "unnamed-alert"),
            severity=str(raw.get("severity", "medium")).lower(),
            timestamp=_parse_ts(raw.get("timestamp")),
            description=str(raw.get("description", "")),
            entities=dict(raw.get("entities", {})),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "entities": self.entities,
        }


@dataclass
class Case:
    id: str
    title: str
    alerts: list[Alert] = field(default_factory=list)
    source: str = "unknown"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Case":
        return cls(
            id=str(raw.get("id") or "CASE-0000"),
            title=str(raw.get("title") or "Untitled case"),
            alerts=[Alert.from_dict(item) for item in raw.get("alerts", [])],
            source=str(raw.get("source", "unknown")),
            created_at=_parse_ts(raw.get("created_at")),
            tags=[str(tag) for tag in raw.get("tags", [])],
            notes=str(raw.get("notes", "")),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "source": self.source,
            "created_at": self.created_at.isoformat(),
            "tags": self.tags,
            "notes": self.notes,
            "alerts": [alert.as_dict() for alert in self.alerts],
        }

    @property
    def highest_severity(self) -> str:
        order = ["informational", "low", "medium", "high", "critical"]
        ranks = [order.index(a.severity) if a.severity in order else 2 for a in self.alerts]
        return order[max(ranks)] if ranks else "informational"
