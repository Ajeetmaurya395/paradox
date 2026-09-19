"""
Paradox — Pydantic Data Models
All data structures for scans, findings, and WebSocket events.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from uuid import uuid4


class ScanRequest(BaseModel):
    """Request to start a new scan."""
    target_url: str = Field(..., description="Website URL or agent API endpoint")
    scan_modes: list[str] = Field(
        default=["security", "privacy", "agent"],
        description='Scan modes: "security", "privacy", "agent"'
    )


class Finding(BaseModel):
    """A single vulnerability or issue found during scanning."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    scan_id: str
    mode: str                    # "security" | "privacy" | "agent"
    category: str                # "xss" | "sqli" | "tracker" | "prompt_injection" ...
    severity: str                # "critical" | "high" | "medium" | "low" | "info"
    title: str                   # e.g. "XSS in search form"
    description: str             # What was found
    evidence: dict = Field(default_factory=dict)  # Request sent, response received
    fix_suggestion: str = ""     # How to fix (with code)
    cedar_policy: Optional[str] = None  # Which Cedar policy it violates
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ScanEvent(BaseModel):
    """Real-time WebSocket event sent during scanning."""
    event_type: str              # "attack_started" | "finding" | "check_passed" | "scan_complete"
    mode: str                    # "security" | "privacy" | "agent"
    message: str                 # Human-readable description
    data: dict = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ScanResult(BaseModel):
    """Complete result of a scan session."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    target_url: str
    scan_modes: list[str] = Field(default_factory=list)
    status: str = "running"      # "running" | "completed" | "error"
    security_score: Optional[int] = None   # 0-100
    privacy_score: Optional[int] = None
    agent_score: Optional[int] = None
    overall_score: Optional[int] = None
    total_findings: int = 0
    findings_by_severity: dict = Field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    findings: list[Finding] = Field(default_factory=list)
    started_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None


class AgentChatRequest(BaseModel):
    """Request to chat with the defender agent."""
    message: str
    agent_type: str = "defender"  # "defender" or "partyrock"


class AgentChatResponse(BaseModel):
    """Response from the defender agent."""
    response: str
    agent_type: str
