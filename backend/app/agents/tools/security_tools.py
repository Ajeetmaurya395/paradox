"""
Paradox — Security Testing Tools
Active scanning tools for SQL injection, XSS, path traversal, and more.
"""

import httpx
import asyncio
import logging
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from .attack_library import (
    SQL_PAYLOADS, XSS_PAYLOADS, PATH_TRAVERSAL,
    SENSITIVE_PATHS, get_fix_suggestion
)

logger = logging.getLogger("paradox.tools.security")

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# SQL injection error signatures
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "syntax error",
    "mysql_fetch",
    "pg_query",
    "sqlite3.operationalerror",
    "ora-01756",
    "sql syntax",
    "mysql_num_rows",
    "sqlstate",
    "postgresql",
    "microsoft sql",
    "invalid query",
]


def test_sql_injection(url: str, param_name: str = "", method: str = "GET") -> dict:
    """
    Test a URL/form parameter for SQL injection vulnerabilities.

    Args:
        url: Target URL (with or without query params)
        param_name: Specific parameter name to test
        method: HTTP method (GET or POST)

    Returns:
        Dict with vulnerability status, successful payloads, and evidence
    """
    results = {
        "url": url,
        "parameter": param_name,
        "method": method,
        "vulnerable": False,
        "payloads_tested": 0,
        "successful_payloads": [],
        "evidence": [],
    }

    try:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
            # Get baseline response
            baseline = client.get(url, headers={"User-Agent": USER_AGENT})
            baseline_length = len(baseline.text)

            for payload in SQL_PAYLOADS:
                results["payloads_tested"] += 1

                try:
                    if method.upper() == "GET":
                        # Inject into URL parameter
                        if param_name:
                            parsed = urlparse(url)
                            params = parse_qs(parsed.query)
                            params[param_name] = [payload]
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                        else:
                            separator = "&" if "?" in url else "?"
                            test_url = f"{url}{separator}q={payload}"
                        response = client.get(test_url, headers={"User-Agent": USER_AGENT})
                    else:
                        data = {param_name or "q": payload}
                        response = client.post(url, data=data, headers={"User-Agent": USER_AGENT})

                    response_text = response.text.lower()

                    # Check for SQL error messages in response
                    for error_sig in SQL_ERRORS:
                        if error_sig in response_text:
                            results["vulnerable"] = True
                            results["successful_payloads"].append(payload)
                            results["evidence"].append({
                                "payload": payload,
                                "error_signature": error_sig,
                                "status_code": response.status_code,
                                "response_snippet": response.text[:200]
                            })
                            break

                    # Check for significant response length change (boolean-based)
                    if abs(len(response.text) - baseline_length) > baseline_length * 0.3:
                        if "OR" in payload and payload not in [p for p in results["successful_payloads"]]:
                            results["successful_payloads"].append(payload)
                            results["evidence"].append({
                                "payload": payload,
                                "type": "boolean_based",
                                "baseline_length": baseline_length,
                                "response_length": len(response.text),
                                "status_code": response.status_code,
                            })
                            results["vulnerable"] = True

                except Exception:
                    continue

    except Exception as e:
        results["error"] = str(e)

    return results


def test_xss(url: str, param_name: str = "", method: str = "GET") -> dict:
    """
    Test an input for Cross-Site Scripting (XSS) vulnerabilities.

    Args:
        url: Target URL
        param_name: Parameter name to inject into
        method: HTTP method

    Returns:
        Dict with vulnerability status and evidence
    """
    results = {
        "url": url,
        "parameter": param_name,
        "vulnerable": False,
        "payloads_tested": 0,
        "reflected_payloads": [],
        "evidence": [],
    }

    try:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
            for payload in XSS_PAYLOADS:
                results["payloads_tested"] += 1

                try:
                    if method.upper() == "GET":
                        if param_name:
                            parsed = urlparse(url)
                            params = parse_qs(parsed.query)
                            params[param_name] = [payload]
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                        else:
                            separator = "&" if "?" in url else "?"
                            test_url = f"{url}{separator}q={payload}"
                        response = client.get(test_url, headers={"User-Agent": USER_AGENT})
                    else:
                        data = {param_name or "q": payload}
                        response = client.post(url, data=data, headers={"User-Agent": USER_AGENT})

                    # Check if payload is reflected in response WITHOUT encoding
                    if payload in response.text:
                        results["vulnerable"] = True
                        results["reflected_payloads"].append(payload)
                        results["evidence"].append({
                            "payload": payload,
                            "reflected": True,
                            "status_code": response.status_code,
                            "response_snippet": response.text[max(0, response.text.index(payload)-50):response.text.index(payload)+len(payload)+50]
                        })

                except Exception:
                    continue

    except Exception as e:
        results["error"] = str(e)

    return results


def test_path_traversal(base_url: str) -> dict:
    """
    Test for path traversal vulnerabilities using various payloads.

    Args:
        base_url: Base URL of the target

    Returns:
        Dict with vulnerability status and evidence
    """
    results = {
        "url": base_url,
        "vulnerable": False,
        "payloads_tested": 0,
        "successful_payloads": [],
    }

    linux_markers = ["root:", "bin/bash", "daemon:"]
    windows_markers = ["[extensions]", "[fonts]", "for 16-bit"]

    try:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
            for payload in PATH_TRAVERSAL:
                results["payloads_tested"] += 1
                separator = "&" if "?" in base_url else "?"
                test_url = f"{base_url}{separator}file={payload}"

                try:
                    response = client.get(test_url, headers={"User-Agent": USER_AGENT})
                    response_lower = response.text.lower()

                    for marker in linux_markers + windows_markers:
                        if marker.lower() in response_lower:
                            results["vulnerable"] = True
                            results["successful_payloads"].append({
                                "payload": payload,
                                "marker_found": marker,
                                "status_code": response.status_code,
                            })
                            break
                except Exception:
                    continue

    except Exception as e:
        results["error"] = str(e)

    return results


def check_sensitive_paths(base_url: str) -> list:
    """
    Try accessing common sensitive paths on the target server.

    Args:
        base_url: Base URL of the target

    Returns:
        List of accessible sensitive paths with details
    """
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    accessible = []

    try:
        with httpx.Client(timeout=8, follow_redirects=False, verify=False) as client:
            for path in SENSITIVE_PATHS:
                try:
                    test_url = base + path
                    response = client.get(test_url, headers={"User-Agent": USER_AGENT})

                    if response.status_code in (200, 301, 302, 403):
                        info = {
                            "path": path,
                            "url": test_url,
                            "status_code": response.status_code,
                            "content_length": len(response.text),
                        }

                        if response.status_code == 200:
                            info["severity"] = "high" if path in ("/.env", "/.git/config", "/swagger.json", "/graphql") else "medium"
                            info["accessible"] = True
                            info["content_preview"] = response.text[:200]
                        elif response.status_code == 403:
                            info["severity"] = "info"
                            info["accessible"] = False
                            info["note"] = "Path exists but access forbidden"
                        else:
                            info["severity"] = "info"
                            info["accessible"] = False
                            info["redirect_to"] = response.headers.get("location", "")

                        accessible.append(info)

                except Exception:
                    continue

    except Exception as e:
        accessible.append({"error": str(e)})

    return accessible


def check_rate_limiting(url: str, num_requests: int = 20) -> dict:
    """
    Send rapid requests to check if rate limiting is enforced.

    Args:
        url: Target URL
        num_requests: Number of rapid requests to send

    Returns:
        Dict with rate limiting status and response analysis
    """
    results = {
        "url": url,
        "requests_sent": num_requests,
        "rate_limited": False,
        "status_codes": [],
        "response_times": [],
    }

    try:
        with httpx.Client(timeout=10, verify=False) as client:
            for i in range(num_requests):
                start = time.time()
                try:
                    response = client.get(url, headers={"User-Agent": USER_AGENT})
                    elapsed = round((time.time() - start) * 1000, 2)
                    results["status_codes"].append(response.status_code)
                    results["response_times"].append(elapsed)

                    if response.status_code == 429:
                        results["rate_limited"] = True
                        results["limited_after"] = i + 1
                        break
                except Exception:
                    continue

        # Analyze results
        if not results["rate_limited"]:
            unique_codes = set(results["status_codes"])
            if 429 not in unique_codes and all(c == 200 for c in results["status_codes"]):
                results["finding"] = f"No rate limiting detected after {num_requests} rapid requests"
            elif 503 in unique_codes or 502 in unique_codes:
                results["rate_limited"] = True
                results["finding"] = "Server returned error codes under load (possible implicit rate limiting)"

        results["avg_response_time"] = round(sum(results["response_times"]) / len(results["response_times"]), 2) if results["response_times"] else 0

    except Exception as e:
        results["error"] = str(e)

    return results
