"""
Paradox — FastAPI Main Server
REST API + WebSocket endpoints for the security platform.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from .models import ScanRequest, AgentChatRequest, AgentChatResponse
from .opensearch_client import init_opensearch, get_scan, get_all_scans, delete_scan, search_findings, get_scan_stats
from .cedar_engine import init_cedar, get_compliance_report
from .scan_orchestrator import run_scan, manager
from .agents.defender_agent import get_defender_response

# Load environment
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("paradox")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("🚀 Paradox starting up...")
    init_opensearch()
    init_cedar()
    logger.info("✅ Paradox ready!")
    yield
    logger.info("👋 Paradox shutting down...")


app = FastAPI(
    title="Paradox",
    description="AI-Powered Security, Privacy & Agent Red-Team Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── REST API Endpoints ───────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "paradox"}


@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    """Start a new scan. Returns scan_id immediately, results stream via WebSocket."""
    logger.info(f"Scan requested: {request.target_url} modes={request.scan_modes}")

    # Validate scan modes
    valid_modes = {"security", "privacy", "agent"}
    invalid = set(request.scan_modes) - valid_modes
    if invalid:
        raise HTTPException(400, f"Invalid scan modes: {invalid}")

    # Run scan in background
    from .models import ScanResult
    scan = ScanResult(
        target_url=request.target_url,
        scan_modes=request.scan_modes,
    )
    scan_id = scan.id

    # Start scan as background task
    asyncio.create_task(run_scan(request))

    return {
        "scan_id": scan_id,
        "status": "started",
        "target_url": request.target_url,
        "scan_modes": request.scan_modes,
    }


@app.get("/api/scans")
async def list_scans():
    """List all past scans with scores."""
    scans = get_all_scans()
    return {"scans": scans, "total": len(scans)}


@app.get("/api/scans/{scan_id}")
async def get_scan_by_id(scan_id: str):
    """Get full scan result with all findings."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.delete("/api/scans/{scan_id}")
async def delete_scan_by_id(scan_id: str):
    """Delete a scan and its findings."""
    success = delete_scan(scan_id)
    if not success:
        raise HTTPException(404, "Scan not found")
    return {"status": "deleted", "scan_id": scan_id}


@app.get("/api/stats")
async def get_stats():
    """Get aggregate scan statistics."""
    return get_scan_stats()


@app.get("/api/search")
async def search(q: str = ""):
    """Full-text search across all findings."""
    if not q:
        return {"findings": [], "query": q}
    findings = search_findings(q)
    return {"findings": findings, "query": q, "total": len(findings)}


@app.post("/api/agent/chat")
async def agent_chat(request: AgentChatRequest):
    """
    Chat with the defender agent directly.
    Used both for testing and as the red-team target endpoint.
    """
    response = get_defender_response(request.message)
    return AgentChatResponse(response=response, agent_type=request.agent_type)


@app.get("/api/compliance/{scan_id}")
async def get_compliance(scan_id: str):
    """Get Cedar compliance report for a scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    findings = scan.get("findings", [])
    report = get_compliance_report(findings)
    return report


# ─── WebSocket Endpoint ───────────────────────────────────────────────────

@app.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """Real-time scan event stream via WebSocket."""
    await manager.connect(scan_id, websocket)
    try:
        while True:
            # Keep connection alive, receive any client messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"event_type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        manager.disconnect(scan_id, websocket)
        logger.error(f"WebSocket error: {e}")


# ─── Startup Message ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
