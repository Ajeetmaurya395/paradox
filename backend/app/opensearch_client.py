"""
Paradox — OpenSearch Client
Stores and retrieves scan results and findings.
Falls back to in-memory storage if OpenSearch is unavailable.
"""

import json
import os
import logging
from typing import Optional
from pathlib import Path

logger = logging.getLogger("paradox.opensearch")

# In-memory fallback storage
_memory_store = {
    "scans": {},
    "findings": {}
}

_DATA_FILE = Path(__file__).parent.parent / "data" / "paradox_data.json"
_opensearch_client = None
_use_opensearch = False


def _save_to_disk():
    """Persist in-memory data to JSON file."""
    try:
        _DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_DATA_FILE, "w") as f:
            json.dump(_memory_store, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save data to disk: {e}")


def _load_from_disk():
    """Load persisted data from JSON file."""
    global _memory_store
    try:
        if _DATA_FILE.exists():
            with open(_DATA_FILE, "r") as f:
                _memory_store = json.load(f)
                logger.info(f"Loaded {len(_memory_store.get('scans', {}))} scans from disk")
    except Exception as e:
        logger.error(f"Failed to load data from disk: {e}")


def init_opensearch():
    """Initialize OpenSearch connection or fall back to in-memory store."""
    global _opensearch_client, _use_opensearch

    opensearch_url = os.getenv("OPENSEARCH_URL", "http://localhost:9200")

    try:
        from opensearchpy import OpenSearch
        client = OpenSearch(
            hosts=[opensearch_url],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            timeout=5
        )
        # Test connection
        info = client.info()
        logger.info(f"Connected to OpenSearch: {info['version']['distribution']}")
        _opensearch_client = client
        _use_opensearch = True
        _create_indices()
    except Exception as e:
        logger.warning(f"OpenSearch unavailable ({e}). Using in-memory fallback.")
        _use_opensearch = False
        _load_from_disk()


def _create_indices():
    """Create OpenSearch indices if they don't exist."""
    if not _opensearch_client:
        return

    scan_mapping = {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "target_url": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "scan_modes": {"type": "keyword"},
                "status": {"type": "keyword"},
                "security_score": {"type": "integer"},
                "privacy_score": {"type": "integer"},
                "agent_score": {"type": "integer"},
                "overall_score": {"type": "integer"},
                "total_findings": {"type": "integer"},
                "started_at": {"type": "date"},
                "completed_at": {"type": "date"}
            }
        }
    }

    finding_mapping = {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "scan_id": {"type": "keyword"},
                "mode": {"type": "keyword"},
                "category": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "title": {"type": "text"},
                "description": {"type": "text"},
                "evidence": {"type": "object", "enabled": False},
                "fix_suggestion": {"type": "text"},
                "cedar_policy": {"type": "keyword"},
                "timestamp": {"type": "date"}
            }
        }
    }

    for index_name, mapping in [("paradox-scans", scan_mapping), ("paradox-findings", finding_mapping)]:
        try:
            if not _opensearch_client.indices.exists(index=index_name):
                _opensearch_client.indices.create(index=index_name, body=mapping)
                logger.info(f"Created index: {index_name}")
        except Exception as e:
            logger.error(f"Failed to create index {index_name}: {e}")


def index_scan(scan: dict) -> str:
    """Save a scan result. Returns scan ID."""
    scan_id = scan.get("id", "unknown")

    if _use_opensearch:
        try:
            _opensearch_client.index(
                index="paradox-scans",
                id=scan_id,
                body={k: v for k, v in scan.items() if k != "findings"},
                refresh=True
            )
        except Exception as e:
            logger.error(f"OpenSearch index_scan failed: {e}")
            _memory_store["scans"][scan_id] = scan
    else:
        _memory_store["scans"][scan_id] = scan
        _save_to_disk()

    return scan_id


def update_scan(scan_id: str, updates: dict):
    """Update fields on an existing scan."""
    if _use_opensearch:
        try:
            _opensearch_client.update(
                index="paradox-scans",
                id=scan_id,
                body={"doc": updates},
                refresh=True
            )
        except Exception as e:
            logger.error(f"OpenSearch update_scan failed: {e}")
            if scan_id in _memory_store["scans"]:
                _memory_store["scans"][scan_id].update(updates)
    else:
        if scan_id in _memory_store["scans"]:
            _memory_store["scans"][scan_id].update(updates)
            _save_to_disk()


def index_finding(finding: dict) -> str:
    """Save an individual finding. Returns finding ID."""
    finding_id = finding.get("id", "unknown")
    scan_id = finding.get("scan_id", "unknown")

    if _use_opensearch:
        try:
            _opensearch_client.index(
                index="paradox-findings",
                id=finding_id,
                body=finding,
                refresh=True
            )
        except Exception as e:
            logger.error(f"OpenSearch index_finding failed: {e}")
            _memory_store["findings"].setdefault(scan_id, []).append(finding)
    else:
        _memory_store["findings"].setdefault(scan_id, []).append(finding)
        _save_to_disk()

    return finding_id


def get_scan(scan_id: str) -> Optional[dict]:
    """Retrieve a scan by ID."""
    if _use_opensearch:
        try:
            result = _opensearch_client.get(index="paradox-scans", id=scan_id)
            scan = result["_source"]
            scan["findings"] = get_findings(scan_id)
            return scan
        except Exception as e:
            logger.error(f"OpenSearch get_scan failed: {e}")

    scan = _memory_store["scans"].get(scan_id)
    if scan:
        scan = dict(scan)
        scan["findings"] = _memory_store["findings"].get(scan_id, [])
    return scan


def get_all_scans() -> list:
    """Get all scans (most recent first)."""
    if _use_opensearch:
        try:
            result = _opensearch_client.search(
                index="paradox-scans",
                body={"query": {"match_all": {}}, "sort": [{"started_at": "desc"}], "size": 50}
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"OpenSearch get_all_scans failed: {e}")

    scans = list(_memory_store["scans"].values())
    scans.sort(key=lambda s: s.get("started_at", ""), reverse=True)
    return scans


def get_findings(scan_id: str, severity: Optional[str] = None, category: Optional[str] = None) -> list:
    """Get findings for a scan, optionally filtered."""
    if _use_opensearch:
        try:
            must = [{"term": {"scan_id": scan_id}}]
            if severity:
                must.append({"term": {"severity": severity}})
            if category:
                must.append({"term": {"category": category}})

            result = _opensearch_client.search(
                index="paradox-findings",
                body={"query": {"bool": {"must": must}}, "size": 200}
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"OpenSearch get_findings failed: {e}")

    findings = _memory_store["findings"].get(scan_id, [])
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if category:
        findings = [f for f in findings if f.get("category") == category]
    return findings


def search_findings(query: str) -> list:
    """Full-text search across all findings."""
    if _use_opensearch:
        try:
            result = _opensearch_client.search(
                index="paradox-findings",
                body={
                    "query": {
                        "multi_match": {
                            "query": query,
                            "fields": ["title", "description", "category", "fix_suggestion"]
                        }
                    },
                    "size": 50
                }
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"OpenSearch search_findings failed: {e}")

    all_findings = []
    for findings_list in _memory_store["findings"].values():
        for f in findings_list:
            if query.lower() in json.dumps(f).lower():
                all_findings.append(f)
    return all_findings[:50]


def get_scan_stats() -> dict:
    """Aggregate stats: total scans, avg scores, top vulnerabilities."""
    scans = get_all_scans()
    if not scans:
        return {"total_scans": 0, "avg_security_score": 0, "avg_privacy_score": 0, "avg_agent_score": 0}

    sec_scores = [s.get("security_score", 0) for s in scans if s.get("security_score") is not None]
    priv_scores = [s.get("privacy_score", 0) for s in scans if s.get("privacy_score") is not None]
    agent_scores = [s.get("agent_score", 0) for s in scans if s.get("agent_score") is not None]

    return {
        "total_scans": len(scans),
        "avg_security_score": int(sum(sec_scores) / len(sec_scores)) if sec_scores else 0,
        "avg_privacy_score": int(sum(priv_scores) / len(priv_scores)) if priv_scores else 0,
        "avg_agent_score": int(sum(agent_scores) / len(agent_scores)) if agent_scores else 0,
    }


def delete_scan(scan_id: str) -> bool:
    """Delete a scan and its findings."""
    if _use_opensearch:
        try:
            _opensearch_client.delete(index="paradox-scans", id=scan_id, refresh=True)
            _opensearch_client.delete_by_query(
                index="paradox-findings",
                body={"query": {"term": {"scan_id": scan_id}}}
            )
            return True
        except Exception as e:
            logger.error(f"OpenSearch delete_scan failed: {e}")

    if scan_id in _memory_store["scans"]:
        del _memory_store["scans"][scan_id]
        _memory_store["findings"].pop(scan_id, None)
        _save_to_disk()
        return True
    return False
