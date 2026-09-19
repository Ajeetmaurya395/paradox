"""
Paradox — Security Scanner Agent
Strands-powered agent that orchestrates security scanning tools.
Uses a hybrid approach: deterministic tool execution + LLM-guided strategy.
"""

import logging
from datetime import datetime
from uuid import uuid4
from ..models import Finding
from .tools.attack_library import get_fix_suggestion
from .tools.http_tools import http_request, check_security_headers, check_cookies, check_ssl
from .tools.html_tools import crawl_page, find_forms
from .tools.security_tools import (
    test_sql_injection, test_xss, test_path_traversal,
    check_sensitive_paths, check_rate_limiting
)

logger = logging.getLogger("paradox.agents.security")


async def run_security_scan(target_url: str, scan_id: str, event_callback=None):
    """
    Run a comprehensive security scan on the target URL.
    This runs deterministically — no LLM needed for core functionality.

    Args:
        target_url: URL to scan
        scan_id: Scan session ID
        event_callback: Async callback for real-time events

    Returns:
        List of Finding objects
    """
    findings = []

    async def emit(event_type, message, data=None):
        if event_callback:
            await event_callback({
                "event_type": event_type,
                "mode": "security",
                "message": message,
                "data": data or {},
                "timestamp": datetime.utcnow().isoformat()
            })

    await emit("mode_started", "🔒 Security scan initiated", {"target": target_url})

    # ── Phase 1: SSL/HTTPS Check ───────────────────────────────────────────
    await emit("attack_started", "Checking SSL/HTTPS configuration...")
    try:
        ssl_result = check_ssl(target_url)
        if ssl_result.get("issues"):
            for issue in ssl_result["issues"]:
                severity = "high" if "not use HTTPS" in issue else "medium"
                finding = Finding(
                    scan_id=scan_id, mode="security", category="no_https",
                    severity=severity,
                    title="SSL/HTTPS Issue",
                    description=issue,
                    evidence=ssl_result,
                    fix_suggestion=get_fix_suggestion("no_https")
                )
                findings.append(finding)
                await emit("finding", f"🔴 {issue}", finding.model_dump())
        else:
            await emit("check_passed", "✅ HTTPS/SSL configuration is secure")
    except Exception as e:
        logger.error(f"SSL check failed: {e}")

    # ── Phase 2: Security Headers ──────────────────────────────────────────
    await emit("attack_started", "Analyzing security headers...")
    try:
        headers_result = check_security_headers(target_url)
        if headers_result.get("missing_headers"):
            missing_names = [h["header"] for h in headers_result["missing_headers"]]
            finding = Finding(
                scan_id=scan_id, mode="security", category="missing_headers",
                severity="high" if len(missing_names) > 3 else "medium",
                title=f"Missing {len(missing_names)} Security Headers",
                description=f"The following security headers are missing: {', '.join(missing_names)}",
                evidence={"missing_headers": missing_names, "header_score": headers_result.get("header_score", 0)},
                fix_suggestion=get_fix_suggestion("missing_headers")
            )
            findings.append(finding)
            await emit("finding", f"🔴 Missing security headers: {', '.join(missing_names[:3])}{'...' if len(missing_names) > 3 else ''}", finding.model_dump())

        if headers_result.get("present_headers"):
            await emit("check_passed", f"✅ {len(headers_result['present_headers'])} security headers present")
    except Exception as e:
        logger.error(f"Header check failed: {e}")

    # ── Phase 3: Cookie Security ───────────────────────────────────────────
    await emit("attack_started", "Checking cookie security flags...")
    try:
        cookies = check_cookies(target_url)
        insecure_cookies = [c for c in cookies if c.get("issues") and not c.get("error")]
        if insecure_cookies:
            finding = Finding(
                scan_id=scan_id, mode="security", category="insecure_cookies",
                severity="medium",
                title=f"{len(insecure_cookies)} Cookies Missing Security Flags",
                description=f"Found {len(insecure_cookies)} cookies without proper security flags (HttpOnly, Secure, SameSite)",
                evidence={"insecure_cookies": insecure_cookies[:5]},
                fix_suggestion=get_fix_suggestion("insecure_cookies")
            )
            findings.append(finding)
            await emit("finding", f"🟡 {len(insecure_cookies)} cookies missing security flags", finding.model_dump())
        else:
            await emit("check_passed", "✅ Cookie security flags look good")
    except Exception as e:
        logger.error(f"Cookie check failed: {e}")

    # ── Phase 4: Page Crawl & Form Discovery ───────────────────────────────
    await emit("attack_started", "Crawling page and discovering forms...")
    page_data = {}
    forms = []
    try:
        page_data = crawl_page(target_url)
        forms = page_data.get("forms", [])
        await emit("check_passed",
                   f"✅ Crawled page: {page_data.get('total_links', 0)} links, {len(forms)} forms, {page_data.get('total_scripts', 0)} scripts found")
    except Exception as e:
        logger.error(f"Page crawl failed: {e}")

    # ── Phase 5: SQL Injection Testing ─────────────────────────────────────
    await emit("attack_started", "Testing for SQL injection vulnerabilities...")
    try:
        # Test URL parameters
        sqli_result = test_sql_injection(target_url)
        if sqli_result.get("vulnerable"):
            finding = Finding(
                scan_id=scan_id, mode="security", category="sqli",
                severity="critical",
                title="SQL Injection Vulnerability Detected",
                description=f"SQL injection found on URL parameters. {len(sqli_result.get('successful_payloads', []))} payloads succeeded.",
                evidence=sqli_result,
                fix_suggestion=get_fix_suggestion("sqli")
            )
            findings.append(finding)
            await emit("finding", "🔴 CRITICAL: SQL injection vulnerability found!", finding.model_dump())
        else:
            await emit("check_passed", "✅ URL parameters not vulnerable to SQL injection")

        # Test each form
        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("name") and inp.get("type") not in ("hidden", "submit", "button", "file"):
                    sqli_form = test_sql_injection(form["action"], inp["name"], form["method"])
                    if sqli_form.get("vulnerable"):
                        finding = Finding(
                            scan_id=scan_id, mode="security", category="sqli",
                            severity="critical",
                            title=f"SQL Injection in Form ({inp['name']})",
                            description=f"SQL injection found in form field '{inp['name']}' on {form['action']}",
                            evidence=sqli_form,
                            fix_suggestion=get_fix_suggestion("sqli")
                        )
                        findings.append(finding)
                        await emit("finding", f"🔴 CRITICAL: SQL injection in form field '{inp['name']}'", finding.model_dump())
    except Exception as e:
        logger.error(f"SQL injection test failed: {e}")

    # ── Phase 6: XSS Testing ──────────────────────────────────────────────
    await emit("attack_started", "Testing for Cross-Site Scripting (XSS)...")
    try:
        xss_result = test_xss(target_url)
        if xss_result.get("vulnerable"):
            finding = Finding(
                scan_id=scan_id, mode="security", category="xss",
                severity="high",
                title="Cross-Site Scripting (XSS) Vulnerability",
                description=f"XSS vulnerability found. {len(xss_result.get('reflected_payloads', []))} payloads reflected.",
                evidence=xss_result,
                fix_suggestion=get_fix_suggestion("xss")
            )
            findings.append(finding)
            await emit("finding", "🔴 XSS vulnerability detected!", finding.model_dump())
        else:
            await emit("check_passed", "✅ URL parameters not vulnerable to XSS")

        # Test forms for XSS
        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("name") and inp.get("type") not in ("hidden", "submit", "button", "file"):
                    xss_form = test_xss(form["action"], inp["name"], form["method"])
                    if xss_form.get("vulnerable"):
                        finding = Finding(
                            scan_id=scan_id, mode="security", category="xss",
                            severity="high",
                            title=f"XSS in Form Field ({inp['name']})",
                            description=f"Reflected XSS in form field '{inp['name']}' on {form['action']}",
                            evidence=xss_form,
                            fix_suggestion=get_fix_suggestion("xss")
                        )
                        findings.append(finding)
                        await emit("finding", f"🔴 XSS in form field '{inp['name']}'", finding.model_dump())
    except Exception as e:
        logger.error(f"XSS test failed: {e}")

    # ── Phase 7: Path Traversal ────────────────────────────────────────────
    await emit("attack_started", "Testing for path traversal vulnerabilities...")
    try:
        traversal_result = test_path_traversal(target_url)
        if traversal_result.get("vulnerable"):
            finding = Finding(
                scan_id=scan_id, mode="security", category="path_traversal",
                severity="critical",
                title="Path Traversal Vulnerability",
                description="Path traversal payloads succeeded — server file system may be accessible",
                evidence=traversal_result,
                fix_suggestion=get_fix_suggestion("path_traversal")
            )
            findings.append(finding)
            await emit("finding", "🔴 CRITICAL: Path traversal vulnerability!", finding.model_dump())
        else:
            await emit("check_passed", "✅ No path traversal vulnerabilities found")
    except Exception as e:
        logger.error(f"Path traversal test failed: {e}")

    # ── Phase 8: Sensitive Path Discovery ──────────────────────────────────
    await emit("attack_started", "Checking for exposed sensitive paths...")
    try:
        sensitive = check_sensitive_paths(target_url)
        accessible_paths = [s for s in sensitive if s.get("accessible")]
        if accessible_paths:
            for path_info in accessible_paths:
                finding = Finding(
                    scan_id=scan_id, mode="security", category="sensitive_path",
                    severity=path_info.get("severity", "medium"),
                    title=f"Sensitive Path Accessible: {path_info['path']}",
                    description=f"The path {path_info['path']} is accessible and may leak sensitive information",
                    evidence=path_info,
                    fix_suggestion=get_fix_suggestion("sensitive_path")
                )
                findings.append(finding)
                await emit("finding", f"🟡 Sensitive path accessible: {path_info['path']}", finding.model_dump())
        else:
            await emit("check_passed", "✅ No sensitive paths found accessible")

        # Info-level: existing but forbidden paths
        forbidden_paths = [s for s in sensitive if s.get("status_code") == 403]
        if forbidden_paths:
            await emit("check_passed", f"ℹ️ {len(forbidden_paths)} paths exist but access is forbidden (good)")
    except Exception as e:
        logger.error(f"Sensitive path check failed: {e}")

    # ── Phase 9: Rate Limiting ─────────────────────────────────────────────
    await emit("attack_started", "Testing rate limiting...")
    try:
        rate_result = check_rate_limiting(target_url, num_requests=15)
        if not rate_result.get("rate_limited"):
            finding = Finding(
                scan_id=scan_id, mode="security", category="no_rate_limiting",
                severity="medium",
                title="No Rate Limiting Detected",
                description=f"Sent {rate_result.get('requests_sent', 15)} rapid requests with no rate limiting. This enables brute-force attacks.",
                evidence=rate_result,
                fix_suggestion=get_fix_suggestion("no_rate_limiting")
            )
            findings.append(finding)
            await emit("finding", "🟡 No rate limiting detected", finding.model_dump())
        else:
            await emit("check_passed", f"✅ Rate limiting active (blocked after {rate_result.get('limited_after', 'N/A')} requests)")
    except Exception as e:
        logger.error(f"Rate limiting test failed: {e}")

    # ── Calculate Score ────────────────────────────────────────────────────
    score = calculate_security_score(findings)
    await emit("mode_completed", f"🔒 Security scan complete — Score: {score}/100", {
        "score": score,
        "total_findings": len(findings),
        "findings_by_severity": count_by_severity(findings)
    })

    return findings, score


def calculate_security_score(findings: list) -> int:
    """Calculate security score from 0-100 based on findings."""
    score = 100
    for finding in findings:
        if isinstance(finding, Finding):
            sev = finding.severity
        else:
            sev = finding.get("severity", "info")

        if sev == "critical":
            score -= 25
        elif sev == "high":
            score -= 15
        elif sev == "medium":
            score -= 8
        elif sev == "low":
            score -= 3
    return max(0, score)


def count_by_severity(findings: list) -> dict:
    """Count findings by severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = finding.severity if isinstance(finding, Finding) else finding.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
