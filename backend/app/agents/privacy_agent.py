"""
Paradox — Privacy Scanner Agent
Detects trackers, analyzes cookies, and builds data flow graphs.
"""

import logging
from datetime import datetime
from ..models import Finding
from .tools.privacy_tools import (
    extract_external_resources, identify_trackers,
    analyze_cookies_privacy, check_privacy_policy_link,
    build_data_flow_graph
)

logger = logging.getLogger("paradox.agents.privacy")


async def run_privacy_scan(target_url: str, scan_id: str, event_callback=None):
    """
    Run a comprehensive privacy scan on the target URL.

    Args:
        target_url: URL to scan
        scan_id: Scan session ID
        event_callback: Async callback for real-time events

    Returns:
        Tuple of (findings list, score, graph_data)
    """
    findings = []
    graph_data = {"nodes": [], "edges": []}

    async def emit(event_type, message, data=None):
        if event_callback:
            await event_callback({
                "event_type": event_type,
                "mode": "privacy",
                "message": message,
                "data": data or {},
                "timestamp": datetime.utcnow().isoformat()
            })

    await emit("mode_started", "👁️ Privacy scan initiated", {"target": target_url})

    # ── Phase 1: Extract External Resources ────────────────────────────────
    await emit("attack_started", "Extracting all external resources...")
    resources = {}
    try:
        resources = extract_external_resources(target_url)
        if resources.get("error"):
            await emit("finding", f"⚠️ Error extracting resources: {resources['error']}")
        else:
            await emit("check_passed",
                       f"✅ Found {resources.get('total_external_resources', 0)} external resources from "
                       f"{resources.get('unique_external_domains', 0)} domains")
    except Exception as e:
        logger.error(f"Resource extraction failed: {e}")
        await emit("finding", f"⚠️ Resource extraction failed: {e}")

    # ── Phase 2: Identify Trackers ─────────────────────────────────────────
    await emit("attack_started", "Matching resources against tracker database...")
    trackers = []
    try:
        trackers = identify_trackers(resources)

        for tracker in trackers:
            is_known = tracker.get("category") != "unknown"
            severity = "info"
            if tracker.get("risk") == "high":
                severity = "high"
            elif tracker.get("risk") == "medium":
                severity = "medium"
            else:
                severity = "low"

            finding = Finding(
                scan_id=scan_id, mode="privacy",
                category="tracker" if is_known else "unknown_tracker",
                severity=severity,
                title=f"{'Tracker' if is_known else 'Unknown External Resource'}: {tracker.get('name', tracker.get('domain'))}",
                description=f"{tracker.get('name', 'Unknown')} by {tracker.get('company', 'Unknown')} — "
                           f"Category: {tracker.get('category', 'unknown')} | "
                           f"Data collected: {tracker.get('data_collected', 'Unknown')}",
                evidence={
                    "tracker_domain": tracker.get("tracker_domain", ""),
                    "tracker_category": tracker.get("category", "unknown"),
                    "company": tracker.get("company", "Unknown"),
                    "risk": tracker.get("risk", "medium"),
                },
                fix_suggestion=f"Consider removing {tracker.get('name', 'this tracker')} or adding a consent banner. "
                              f"Users should opt-in before {tracker.get('category', 'tracking')} trackers are loaded."
            )
            findings.append(finding)
            await emit("tracker_found", f"📡 Found: {tracker.get('name', tracker.get('domain'))}", {
                "tracker": tracker,
                "finding": finding.model_dump()
            })

        if not trackers:
            await emit("check_passed", "✅ No known trackers detected")

    except Exception as e:
        logger.error(f"Tracker identification failed: {e}")

    # ── Phase 3: Excessive Trackers Check ──────────────────────────────────
    if len(trackers) > 5:
        non_infra_trackers = [t for t in trackers if t.get("category") not in ("infrastructure",)]
        if len(non_infra_trackers) > 5:
            finding = Finding(
                scan_id=scan_id, mode="privacy", category="excessive_trackers",
                severity="high",
                title=f"Excessive Tracking: {len(non_infra_trackers)} Third-Party Trackers",
                description=f"Found {len(non_infra_trackers)} non-infrastructure trackers. "
                           f"This is a significant privacy concern and may violate data minimization principles.",
                evidence={"tracker_count": len(non_infra_trackers), "trackers": [t.get("name") for t in non_infra_trackers]},
                fix_suggestion="Audit all third-party trackers. Remove unnecessary ones. "
                              "Implement a consent management platform (CMP) to get user consent before loading trackers."
            )
            findings.append(finding)
            await emit("finding", f"🔴 Excessive tracking: {len(non_infra_trackers)} trackers found!", finding.model_dump())

    # ── Phase 4: Cookie Privacy Analysis ───────────────────────────────────
    await emit("attack_started", "Analyzing cookie privacy categories...")
    cookies = []
    try:
        cookies = analyze_cookies_privacy(target_url)
        ad_cookies = [c for c in cookies if c.get("category") == "advertising"]
        analytics_cookies = [c for c in cookies if c.get("category") == "analytics"]
        unknown_cookies = [c for c in cookies if c.get("category") == "unknown"]

        if ad_cookies:
            finding = Finding(
                scan_id=scan_id, mode="privacy", category="insecure_cookies_privacy",
                severity="high",
                title=f"{len(ad_cookies)} Advertising Cookies Without Consent",
                description=f"Found {len(ad_cookies)} advertising cookies set without explicit user consent: "
                           f"{', '.join(c.get('name', '?') for c in ad_cookies[:5])}",
                evidence={"advertising_cookies": ad_cookies},
                fix_suggestion="Implement a cookie consent banner. Do not set advertising cookies until the user explicitly opts in."
            )
            findings.append(finding)
            await emit("finding", f"🔴 {len(ad_cookies)} advertising cookies set without consent", finding.model_dump())

        if analytics_cookies:
            await emit("check_passed", f"ℹ️ {len(analytics_cookies)} analytics cookies found")

        if unknown_cookies:
            await emit("check_passed", f"⚠️ {len(unknown_cookies)} unclassified cookies found")

        total_cookies = len(cookies)
        await emit("check_passed", f"✅ Cookie analysis complete: {total_cookies} total cookies")

    except Exception as e:
        logger.error(f"Cookie analysis failed: {e}")

    # ── Phase 5: Privacy Policy Check ──────────────────────────────────────
    await emit("attack_started", "Checking for privacy policy...")
    try:
        policy_result = check_privacy_policy_link(target_url)
        if not policy_result.get("has_privacy_policy"):
            finding = Finding(
                scan_id=scan_id, mode="privacy", category="no_privacy_policy",
                severity="high",
                title="No Privacy Policy Found",
                description="No accessible privacy policy was found on this website. "
                           "This is a legal requirement in most jurisdictions (GDPR, CCPA, DPDP Act).",
                evidence=policy_result,
                fix_suggestion="Add a clearly visible privacy policy page that covers:\n"
                              "- What data you collect\n- How you use it\n"
                              "- Third-party sharing\n- User rights\n- Contact information"
            )
            findings.append(finding)
            await emit("finding", "🔴 No privacy policy found!", finding.model_dump())
        else:
            await emit("check_passed", f"✅ Privacy policy found at {policy_result.get('privacy_policy_url', 'N/A')}")
    except Exception as e:
        logger.error(f"Privacy policy check failed: {e}")

    # ── Phase 6: Build Data Flow Graph ─────────────────────────────────────
    await emit("attack_started", "Building data flow graph...")
    try:
        graph_data = build_data_flow_graph(target_url, trackers, cookies)
        await emit("graph_data", "📊 Data flow graph built", graph_data)
    except Exception as e:
        logger.error(f"Graph building failed: {e}")

    # ── Calculate Score ────────────────────────────────────────────────────
    score = calculate_privacy_score(trackers, cookies, findings)
    await emit("mode_completed", f"👁️ Privacy scan complete — Score: {score}/100", {
        "score": score,
        "total_findings": len(findings),
        "total_trackers": len(trackers),
        "total_cookies": len(cookies),
        "graph": graph_data,
    })

    return findings, score, graph_data


def calculate_privacy_score(trackers: list, cookies: list, findings: list) -> int:
    """Calculate privacy score from 0-100."""
    score = 100

    # Tracker penalties
    non_infra = [t for t in trackers if t.get("category") not in ("infrastructure",)]
    score -= min(50, len(non_infra) * 5)

    # Ad tracker extra penalty
    ad_trackers = [t for t in trackers if t.get("category") == "advertising"]
    score -= min(20, len(ad_trackers) * 8)

    # Session recording extra penalty
    session_trackers = [t for t in trackers if t.get("category") == "session_recording"]
    score -= len(session_trackers) * 10

    # Cookie penalties
    ad_cookies = [c for c in cookies if c.get("category") == "advertising"]
    score -= min(15, len(ad_cookies) * 5)

    # Missing privacy policy
    has_no_policy = any(f.category == "no_privacy_policy" for f in findings if hasattr(f, 'category'))
    if has_no_policy:
        score -= 15

    return max(0, score)
