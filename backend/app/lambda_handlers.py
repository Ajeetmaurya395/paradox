"""
Paradox — Serverless Lambda Handlers
Provides AWS SAM compatibility for deploying the backend via Lambda + API Gateway.
"""

import json
import asyncio
from typing import Any, Dict
from pydantic import ValidationError
from .models import ScanRequest
from .opensearch_client import get_all_scans, get_scan
from .scan_orchestrator import run_scan

def _json_response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body)
    }

def start_scan(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for POST /api/scan"""
    try:
        body = json.loads(event.get("body", "{}"))
        req = ScanRequest(**body)
        
        # In a real serverless architecture, we would dispatch this to an SQS queue
        # For demonstration, we'll run it synchronously (may timeout depending on scan duration)
        loop = asyncio.get_event_loop()
        scan_result = loop.run_until_complete(run_scan(req))
        
        return _json_response(200, {
            "scan_id": scan_result.id,
            "status": "started",
            "target_url": req.target_url,
            "scan_modes": req.scan_modes,
        })
    except ValidationError as e:
        return _json_response(400, {"error": "Invalid request body", "details": e.errors()})
    except Exception as e:
        return _json_response(500, {"error": str(e)})

def get_scans(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for GET /api/scans"""
    try:
        scans = get_all_scans()
        return _json_response(200, {"scans": scans, "total": len(scans)})
    except Exception as e:
        return _json_response(500, {"error": str(e)})

def get_scan_by_id(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for GET /api/scans/{id}"""
    try:
        path_params = event.get("pathParameters", {})
        scan_id = path_params.get("id")
        
        if not scan_id:
            return _json_response(400, {"error": "Missing scan ID parameter"})
            
        scan = get_scan(scan_id)
        if not scan:
            return _json_response(404, {"error": "Scan not found"})
            
        return _json_response(200, scan)
    except Exception as e:
        return _json_response(500, {"error": str(e)})
