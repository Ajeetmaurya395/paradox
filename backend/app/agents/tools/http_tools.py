"""
Paradox — HTTP Tools
Strands-compatible tools for making HTTP requests and checking security headers/cookies/SSL.
"""

import httpx
import ssl
import socket
import logging
from urllib.parse import urlparse
from .attack_library import HEADER_CHECKS, HEADER_SEVERITY

logger = logging.getLogger("paradox.tools.http")

# Common browser User-Agent to avoid blocks
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def http_request(method: str, url: str, headers: dict = None, body: str = None, timeout: int = 10) -> dict:
    """
    Make an HTTP request and return status code, headers, and body.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        url: Target URL
        headers: Optional custom headers
        body: Optional request body
        timeout: Request timeout in seconds

    Returns:
        Dict with status_code, headers, body, and response_time
    """
    try:
        req_headers = {"User-Agent": USER_AGENT}
        if headers:
            req_headers.update(headers)

        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            import time
            start = time.time()
            response = client.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                content=body
            )
            elapsed = round((time.time() - start) * 1000, 2)

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:5000],  # Limit body size
            "response_time_ms": elapsed,
            "url": str(response.url),
            "redirected": str(response.url) != url,
        }
    except httpx.TimeoutException:
        return {"error": "Request timed out", "status_code": 0, "url": url}
    except Exception as e:
        return {"error": str(e), "status_code": 0, "url": url}


def check_security_headers(url: str) -> dict:
    """
    Check all security headers on a URL.
    Returns present and missing headers with severity ratings.

    Args:
        url: Target URL to check

    Returns:
        Dict with present headers, missing headers, and security score
    """
    try:
        response = http_request("GET", url)
        if response.get("error"):
            return {"error": response["error"]}

        resp_headers = {k.lower(): v for k, v in response.get("headers", {}).items()}

        present = []
        missing = []

        for header in HEADER_CHECKS:
            header_lower = header.lower()
            if header_lower in resp_headers:
                present.append({
                    "header": header,
                    "value": resp_headers[header_lower],
                    "status": "present"
                })
            else:
                missing.append({
                    "header": header,
                    "severity": HEADER_SEVERITY.get(header, "low"),
                    "status": "missing"
                })

        score = int((len(present) / len(HEADER_CHECKS)) * 100)

        return {
            "url": url,
            "present_headers": present,
            "missing_headers": missing,
            "header_score": score,
            "total_checked": len(HEADER_CHECKS),
            "total_present": len(present),
            "total_missing": len(missing),
        }
    except Exception as e:
        return {"error": str(e)}


def check_cookies(url: str) -> list:
    """
    Get all cookies from a URL and check their security flags.

    Args:
        url: Target URL to check

    Returns:
        List of cookies with their security flag status
    """
    try:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
            response = client.get(url, headers={"User-Agent": USER_AGENT})

        cookies = []
        for cookie in response.cookies.jar:
            cookie_info = {
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "value_preview": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
                "secure": cookie.secure,
                "httponly": "httponly" in cookie._rest.keys() or hasattr(cookie, 'has_nonstandard_attr') and cookie.has_nonstandard_attr('HttpOnly'),
                "samesite": cookie._rest.get("SameSite", cookie._rest.get("samesite", "Not Set")),
                "expires": str(cookie.expires) if cookie.expires else "Session",
            }

            # Check security issues
            issues = []
            if not cookie.secure:
                issues.append("Missing Secure flag — cookie sent over HTTP")
            if not cookie_info["httponly"]:
                issues.append("Missing HttpOnly flag — accessible via JavaScript")
            if cookie_info["samesite"] == "Not Set":
                issues.append("Missing SameSite flag — CSRF risk")

            cookie_info["issues"] = issues
            cookie_info["secure_score"] = "good" if not issues else ("warning" if len(issues) < 2 else "bad")
            cookies.append(cookie_info)

        return cookies
    except Exception as e:
        return [{"error": str(e)}]


def check_ssl(url: str) -> dict:
    """
    Check HTTPS and SSL/TLS configuration.

    Args:
        url: Target URL to check

    Returns:
        Dict with SSL status, certificate details, and issues
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    result = {
        "url": url,
        "uses_https": parsed.scheme == "https",
        "certificate": None,
        "issues": [],
    }

    if parsed.scheme != "https":
        result["issues"].append("Site does not use HTTPS — all traffic is unencrypted")
        # Check if HTTPS is available
        try:
            with httpx.Client(timeout=5, verify=False) as client:
                https_url = url.replace("http://", "https://")
                resp = client.get(https_url, headers={"User-Agent": USER_AGENT})
                if resp.status_code < 400:
                    result["issues"].append("HTTPS is available but not enforced (no redirect)")
        except:
            result["issues"].append("HTTPS is not available on this server")
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "serial": cert.get("serialNumber"),
                }
                result["tls_version"] = ssock.version()
    except ssl.SSLCertVerificationError as e:
        result["issues"].append(f"SSL certificate verification failed: {e}")
    except Exception as e:
        result["issues"].append(f"SSL check failed: {e}")

    # Check for mixed content
    try:
        resp = http_request("GET", url)
        body = resp.get("body", "")
        if "http://" in body and "src=" in body.lower():
            result["issues"].append("Potential mixed content: HTTP resources loaded on HTTPS page")
    except:
        pass

    return result
