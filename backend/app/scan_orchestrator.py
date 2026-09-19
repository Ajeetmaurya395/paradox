"""
Paradox — Scan Orchestrator
Coordinates all three scan modes, streams WebSocket events, calculates scores.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional
from .models import ScanResult, ScanRequest
from .opensearch_client import index_scan, update_scan, index_finding
from .cedar_engine import evaluate_finding
from .agents.security_agent import run_security_scan
from .agents.privacy_agent import run_privacy_scan
from .agents.redteam_agent import run_redteam_scan
from .agents.defender_agent import get_defender_response

logger = logging.getLogger("paradox.orchestrator")

# WebSocket connection manager
class ConnectionManager:
    """Manages WebSocket connections for real-time scan events."""

    def __init__(self):
        self.active_connections: dict = {}  # scan_id -> list of websockets

    async def connect(self, scan_id: str, websocket):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        logger.info(f"WebSocket connected for scan {scan_id}")

    def disconnect(self, scan_id: str, websocket):
        if scan_id in self.active_connections:
            self.active_connections[scan_id] = [
                ws for ws in self.active_connections[scan_id] if ws != websocket
            ]
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: str, data: dict):
        if scan_id in self.active_connections:
            dead = []
            for ws in self.active_connections[scan_id]:
                try:
                    await ws.send_json(data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.active_connections[scan_id].remove(ws)


manager = ConnectionManager()


async def run_scan(scan_request: ScanRequest) -> ScanResult:
    """
    Run a full scan with all selected modes.
    Returns the scan result and streams events via WebSocket.
    """
    # Create scan record
    scan = ScanResult(
        target_url=scan_request.target_url,
        scan_modes=scan_request.scan_modes,
    )

    # Save initial scan to storage
    index_scan(scan.model_dump())

    # Broadcast scan started
    await manager.broadcast(scan.id, {
        "event_type": "scan_started",
        "mode": "all",
        "message": f"🚀 Scan started on {scan_request.target_url}",
        "data": {"scan_id": scan.id, "target": scan_request.target_url, "modes": scan_request.scan_modes},
        "timestamp": datetime.utcnow().isoformat()
    })

    all_findings = []
    graph_data = None
    battle_rounds = []

    # Event callback for broadcasting
    async def event_callback(event: dict):
        await manager.broadcast(scan.id, event)

    # Run scan modes concurrently
    tasks = []

    if "security" in scan_request.scan_modes:
        tasks.append(("security", run_security_scan(scan_request.target_url, scan.id, event_callback)))

    if "privacy" in scan_request.scan_modes:
        tasks.append(("privacy", run_privacy_scan(scan_request.target_url, scan.id, event_callback)))

    if "agent" in scan_request.scan_modes:
        # For agent mode, use local defender endpoint or the provided URL
        agent_endpoint = scan_request.target_url
        if not agent_endpoint.startswith("http"):
            agent_endpoint = "http://localhost:8000/api/agent/chat"
        tasks.append(("agent", run_redteam_scan(agent_endpoint, scan.id, event_callback)))

    # Execute all tasks
    for mode, task in tasks:
        try:
            result = await task

            if mode == "security":
                findings, score = result
                scan.security_score = score
                all_findings.extend(findings)

            elif mode == "privacy":
                findings, score, gdata = result
                scan.privacy_score = score
                graph_data = gdata
                all_findings.extend(findings)

            elif mode == "agent":
                findings, score, rounds = result
                scan.agent_score = score
                battle_rounds = rounds
                all_findings.extend(findings)

        except Exception as e:
            logger.error(f"Scan mode '{mode}' failed: {e}")
            await manager.broadcast(scan.id, {
                "event_type": "error",
                "mode": mode,
                "message": f"⚠️ {mode.title()} scan encountered an error: {str(e)}",
                "data": {"error": str(e)},
                "timestamp": datetime.utcnow().isoformat()
            })

    # Cedar evaluation for each finding
    for finding in all_findings:
        finding_dict = finding.model_dump() if hasattr(finding, 'model_dump') else finding
        cedar_result = evaluate_finding(finding_dict)
        if not cedar_result["compliant"]:
            if hasattr(finding, 'cedar_policy'):
                finding.cedar_policy = cedar_result["violated_policies"][0]["policy"] if cedar_result["violated_policies"] else None
            finding_dict["cedar_result"] = cedar_result

        # Index finding to storage
        index_finding(finding_dict)

    # Calculate overall score
    scores = [s for s in [scan.security_score, scan.privacy_score, scan.agent_score] if s is not None]
    scan.overall_score = int(sum(scores) / len(scores)) if scores else 0

    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.severity if hasattr(f, 'severity') else f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scan.total_findings = len(all_findings)
    scan.findings_by_severity = severity_counts
    scan.status = "completed"
    scan.completed_at = datetime.utcnow().isoformat()

    # Update scan in storage
    update_scan(scan.id, scan.model_dump())

    # Broadcast scan complete
    await manager.broadcast(scan.id, {
        "event_type": "scan_complete",
        "mode": "all",
        "message": f"✅ Scan complete! Overall Score: {scan.overall_score}/100",
        "data": {
            "scan_id": scan.id,
            "overall_score": scan.overall_score,
            "security_score": scan.security_score,
            "privacy_score": scan.privacy_score,
            "agent_score": scan.agent_score,
            "total_findings": scan.total_findings,
            "findings_by_severity": severity_counts,
            "graph_data": graph_data,
            "battle_rounds": battle_rounds,
        },
        "timestamp": datetime.utcnow().isoformat()
    })

    return scan
