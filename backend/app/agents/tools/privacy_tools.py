"""
Paradox — Privacy Detection Tools
Tools for detecting trackers, analyzing cookies, and building data flow graphs.
"""

import httpx
import logging
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

logger = logging.getLogger("paradox.tools.privacy")

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ─── Known Tracker Database ───────────────────────────────────────────────
KNOWN_TRACKERS = {
    "google-analytics.com": {"name": "Google Analytics", "company": "Google", "category": "analytics", "risk": "medium", "data_collected": "Page views, user behavior, demographics"},
    "googletagmanager.com": {"name": "Google Tag Manager", "company": "Google", "category": "analytics", "risk": "medium", "data_collected": "Tag management, event tracking"},
    "facebook.net": {"name": "Facebook Pixel", "company": "Meta", "category": "advertising", "risk": "high", "data_collected": "User identity, browsing behavior, conversions"},
    "fbcdn.net": {"name": "Facebook CDN", "company": "Meta", "category": "advertising", "risk": "high", "data_collected": "Content delivery, user tracking"},
    "connect.facebook.net": {"name": "Facebook SDK", "company": "Meta", "category": "advertising", "risk": "high", "data_collected": "Social login, user graph, conversions"},
    "doubleclick.net": {"name": "Google Ads (DoubleClick)", "company": "Google", "category": "advertising", "risk": "high", "data_collected": "Ad targeting, cross-site tracking, conversions"},
    "googlesyndication.com": {"name": "Google AdSense", "company": "Google", "category": "advertising", "risk": "high", "data_collected": "Ad display, click tracking, user interests"},
    "googleadservices.com": {"name": "Google Ads", "company": "Google", "category": "advertising", "risk": "high", "data_collected": "Conversion tracking, remarketing"},
    "hotjar.com": {"name": "Hotjar", "company": "Hotjar", "category": "session_recording", "risk": "high", "data_collected": "Mouse movements, clicks, scrolls, form inputs, session recordings"},
    "clarity.ms": {"name": "Microsoft Clarity", "company": "Microsoft", "category": "session_recording", "risk": "high", "data_collected": "Session recordings, heatmaps, click maps"},
    "criteo.com": {"name": "Criteo", "company": "Criteo", "category": "advertising", "risk": "high", "data_collected": "Retargeting, product views, purchase data"},
    "amazon-adsystem.com": {"name": "Amazon Ads", "company": "Amazon", "category": "advertising", "risk": "medium", "data_collected": "Product interest, conversions"},
    "linkedin.com": {"name": "LinkedIn Insight", "company": "LinkedIn", "category": "advertising", "risk": "medium", "data_collected": "Professional profile, conversions"},
    "ads.linkedin.com": {"name": "LinkedIn Ads", "company": "LinkedIn", "category": "advertising", "risk": "medium", "data_collected": "Ad targeting, conversion tracking"},
    "twitter.com": {"name": "Twitter/X Pixel", "company": "X Corp", "category": "advertising", "risk": "medium", "data_collected": "User engagement, conversions"},
    "tiktok.com": {"name": "TikTok Pixel", "company": "ByteDance", "category": "advertising", "risk": "high", "data_collected": "User behavior, conversions, device fingerprint"},
    "analytics.tiktok.com": {"name": "TikTok Analytics", "company": "ByteDance", "category": "advertising", "risk": "high", "data_collected": "Event tracking, user behavior"},
    "snapchat.com": {"name": "Snapchat Pixel", "company": "Snap Inc", "category": "advertising", "risk": "medium", "data_collected": "Conversions, audience matching"},
    "mixpanel.com": {"name": "Mixpanel", "company": "Mixpanel", "category": "analytics", "risk": "medium", "data_collected": "User events, funnels, retention"},
    "segment.io": {"name": "Segment", "company": "Twilio", "category": "analytics", "risk": "medium", "data_collected": "User events, identity, data routing"},
    "segment.com": {"name": "Segment", "company": "Twilio", "category": "analytics", "risk": "medium", "data_collected": "Customer data platform"},
    "amplitude.com": {"name": "Amplitude", "company": "Amplitude", "category": "analytics", "risk": "medium", "data_collected": "Product analytics, user behavior"},
    "hubspot.com": {"name": "HubSpot", "company": "HubSpot", "category": "marketing", "risk": "medium", "data_collected": "Lead tracking, form submissions, email opens"},
    "intercom.io": {"name": "Intercom", "company": "Intercom", "category": "marketing", "risk": "medium", "data_collected": "User identity, chat history, behavior"},
    "drift.com": {"name": "Drift", "company": "Salesloft", "category": "marketing", "risk": "medium", "data_collected": "Chat interactions, user identification"},
    "newrelic.com": {"name": "New Relic", "company": "New Relic", "category": "monitoring", "risk": "low", "data_collected": "Performance metrics, errors"},
    "sentry.io": {"name": "Sentry", "company": "Sentry", "category": "monitoring", "risk": "low", "data_collected": "Error tracking, stack traces"},
    "cloudflare.com": {"name": "Cloudflare", "company": "Cloudflare", "category": "infrastructure", "risk": "low", "data_collected": "CDN, DDoS protection, DNS"},
    "jsdelivr.net": {"name": "jsDelivr CDN", "company": "jsDelivr", "category": "infrastructure", "risk": "low", "data_collected": "Static file delivery"},
    "unpkg.com": {"name": "unpkg CDN", "company": "unpkg", "category": "infrastructure", "risk": "low", "data_collected": "NPM package delivery"},
    "cdn.jsdelivr.net": {"name": "jsDelivr CDN", "company": "jsDelivr", "category": "infrastructure", "risk": "low", "data_collected": "Static file delivery"},
    "fonts.googleapis.com": {"name": "Google Fonts", "company": "Google", "category": "infrastructure", "risk": "low", "data_collected": "Font delivery, IP logging"},
    "fonts.gstatic.com": {"name": "Google Fonts Static", "company": "Google", "category": "infrastructure", "risk": "low", "data_collected": "Font file delivery"},
    "adservice.google.com": {"name": "Google Ad Service", "company": "Google", "category": "advertising", "risk": "high", "data_collected": "Ad delivery, tracking"},
    "pagead2.googlesyndication.com": {"name": "Google PageAd", "company": "Google", "category": "advertising", "risk": "high", "data_collected": "Ad syndication"},
    "www.googletagservices.com": {"name": "Google Tag Services", "company": "Google", "category": "analytics", "risk": "medium", "data_collected": "Tag delivery"},
}


def extract_external_resources(url: str) -> dict:
    """
    Fetch a page and find all external scripts, images, iframes, fonts, and stylesheets.

    Args:
        url: Target URL

    Returns:
        Dict with categorized external resources
    """
    try:
        with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
            response = client.get(url, headers={"User-Agent": USER_AGENT})

        soup = BeautifulSoup(response.text, "lxml")
        target_domain = urlparse(url).netloc

        resources = {
            "scripts": [],
            "images": [],
            "iframes": [],
            "stylesheets": [],
            "fonts": [],
            "other": [],
        }

        # External scripts
        for tag in soup.find_all("script", src=True):
            src = urljoin(url, tag["src"])
            domain = urlparse(src).netloc
            if domain and domain != target_domain:
                resources["scripts"].append({"url": src, "domain": domain})

        # External images (tracking pixels)
        for tag in soup.find_all("img", src=True):
            src = urljoin(url, tag["src"])
            domain = urlparse(src).netloc
            if domain and domain != target_domain:
                width = tag.get("width", "")
                height = tag.get("height", "")
                is_pixel = (width in ("0", "1") and height in ("0", "1"))
                resources["images"].append({
                    "url": src, "domain": domain,
                    "is_tracking_pixel": is_pixel
                })

        # Iframes
        for tag in soup.find_all("iframe", src=True):
            src = urljoin(url, tag["src"])
            domain = urlparse(src).netloc
            if domain and domain != target_domain:
                resources["iframes"].append({"url": src, "domain": domain})

        # Stylesheets
        for tag in soup.find_all("link", rel="stylesheet"):
            href = tag.get("href", "")
            if href:
                src = urljoin(url, href)
                domain = urlparse(src).netloc
                if domain and domain != target_domain:
                    resources["stylesheets"].append({"url": src, "domain": domain})

        # Preconnect / dns-prefetch (hints of trackers)
        for tag in soup.find_all("link", rel=["preconnect", "dns-prefetch"]):
            href = tag.get("href", "")
            if href:
                domain = urlparse(href).netloc
                if domain and domain != target_domain:
                    resources["other"].append({
                        "url": href, "domain": domain,
                        "type": tag.get("rel", ["unknown"])[0]
                    })

        # Count totals
        total_external = sum(len(v) for v in resources.values())
        all_domains = set()
        for category in resources.values():
            for r in category:
                all_domains.add(r.get("domain", ""))

        return {
            "url": url,
            "target_domain": target_domain,
            "total_external_resources": total_external,
            "unique_external_domains": len(all_domains),
            "external_domains": list(all_domains),
            "resources": resources,
        }
    except Exception as e:
        return {"error": str(e), "url": url}


def identify_trackers(resources: dict) -> list:
    """
    Match external resources against the known tracker database.

    Args:
        resources: Output from extract_external_resources

    Returns:
        List of identified trackers with details
    """
    trackers_found = []
    seen_trackers = set()
    domains = resources.get("external_domains", [])

    for domain in domains:
        # Check against known tracker database
        for tracker_domain, tracker_info in KNOWN_TRACKERS.items():
            if tracker_domain in domain and tracker_domain not in seen_trackers:
                seen_trackers.add(tracker_domain)
                trackers_found.append({
                    "domain": domain,
                    "tracker_domain": tracker_domain,
                    **tracker_info,
                })

    # Check for unknown external domains (potential trackers)
    known_domains = set()
    for tracker_domain in KNOWN_TRACKERS.keys():
        known_domains.add(tracker_domain)

    for domain in domains:
        is_known = any(kd in domain for kd in known_domains)
        if not is_known and domain:
            trackers_found.append({
                "domain": domain,
                "tracker_domain": domain,
                "name": f"Unknown: {domain}",
                "company": "Unknown",
                "category": "unknown",
                "risk": "medium",
                "data_collected": "Unknown — external resource from unrecognized domain",
            })

    return trackers_found


def analyze_cookies_privacy(url: str) -> list:
    """
    Categorize cookies as necessary, analytics, advertising, or unknown.

    Args:
        url: Target URL

    Returns:
        List of cookies with privacy categorization
    """
    COOKIE_CATEGORIES = {
        # Analytics
        "_ga": "analytics", "_gid": "analytics", "_gat": "analytics",
        "__utma": "analytics", "__utmb": "analytics", "__utmc": "analytics",
        "__utmz": "analytics", "_hjid": "analytics", "_hjSession": "analytics",
        "mp_": "analytics", "ajs_": "analytics",
        # Advertising
        "_fbp": "advertising", "_fbc": "advertising",
        "_gcl_": "advertising", "IDE": "advertising",
        "NID": "advertising", "fr": "advertising",
        "_uetsid": "advertising", "tt_": "advertising",
        # Necessary
        "JSESSIONID": "necessary", "csrf": "necessary",
        "session": "necessary", "__cfduid": "necessary",
        "PHPSESSID": "necessary", "ASP.NET_SessionId": "necessary",
    }

    try:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
            response = client.get(url, headers={"User-Agent": USER_AGENT})

        cookies = []
        for cookie in response.cookies.jar:
            # Determine category
            category = "unknown"
            for prefix, cat in COOKIE_CATEGORIES.items():
                if cookie.name.startswith(prefix) or cookie.name == prefix:
                    category = cat
                    break

            cookies.append({
                "name": cookie.name,
                "domain": cookie.domain,
                "category": category,
                "secure": cookie.secure,
                "expires": str(cookie.expires) if cookie.expires else "Session",
                "risk": "high" if category == "advertising" else (
                    "medium" if category == "analytics" else (
                        "low" if category == "necessary" else "medium"
                    )
                ),
            })

        return cookies
    except Exception as e:
        return [{"error": str(e)}]


def check_privacy_policy_link(url: str) -> dict:
    """
    Check if a privacy policy page exists and is accessible.

    Args:
        url: Target URL

    Returns:
        Dict with privacy policy status
    """
    PRIVACY_PATHS = [
        "/privacy", "/privacy-policy", "/privacypolicy",
        "/privacy.html", "/legal/privacy",
        "/terms/privacy", "/about/privacy",
    ]
    PRIVACY_KEYWORDS = [
        "privacy policy", "privacy notice",
        "data protection", "cookie policy",
        "privacidad", "datenschutz",
    ]

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    result = {
        "url": url,
        "has_privacy_policy": False,
        "privacy_policy_url": None,
        "found_via": None,
    }

    try:
        # Method 1: Check common paths
        with httpx.Client(timeout=8, follow_redirects=True, verify=False) as client:
            for path in PRIVACY_PATHS:
                try:
                    resp = client.get(base + path, headers={"User-Agent": USER_AGENT})
                    if resp.status_code == 200 and len(resp.text) > 500:
                        result["has_privacy_policy"] = True
                        result["privacy_policy_url"] = base + path
                        result["found_via"] = "common_path"
                        return result
                except:
                    continue

            # Method 2: Search for link on homepage
            resp = client.get(url, headers={"User-Agent": USER_AGENT})
            soup = BeautifulSoup(resp.text, "lxml")

            for a_tag in soup.find_all("a", href=True):
                text = a_tag.get_text(strip=True).lower()
                href = a_tag["href"].lower()

                for keyword in PRIVACY_KEYWORDS:
                    if keyword in text or "privacy" in href:
                        result["has_privacy_policy"] = True
                        result["privacy_policy_url"] = urljoin(url, a_tag["href"])
                        result["found_via"] = "link_on_page"
                        return result

    except Exception as e:
        result["error"] = str(e)

    return result


def build_data_flow_graph(url: str, trackers: list, cookies: list) -> dict:
    """
    Build a network graph data structure for privacy visualization.

    Args:
        url: Target website URL
        trackers: List of identified trackers
        cookies: List of categorized cookies

    Returns:
        Dict with nodes and edges for the network graph
    """
    parsed = urlparse(url)
    target_domain = parsed.netloc

    nodes = [{
        "id": "target",
        "label": target_domain,
        "type": "target",
        "category": "target",
        "risk": "none",
        "size": 40,
    }]

    edges = []
    seen_nodes = {"target"}

    # Add tracker nodes
    for i, tracker in enumerate(trackers):
        node_id = f"tracker_{i}"
        if tracker.get("domain") not in seen_nodes:
            seen_nodes.add(tracker.get("domain"))
            nodes.append({
                "id": node_id,
                "label": tracker.get("name", tracker.get("domain", "Unknown")),
                "domain": tracker.get("domain", ""),
                "type": "tracker",
                "category": tracker.get("category", "unknown"),
                "company": tracker.get("company", "Unknown"),
                "risk": tracker.get("risk", "medium"),
                "data_collected": tracker.get("data_collected", "Unknown"),
                "size": 30 if tracker.get("risk") == "high" else 20,
            })
            edges.append({
                "source": "target",
                "target": node_id,
                "type": "data_flow",
                "category": tracker.get("category", "unknown"),
            })

    # Summary stats
    category_counts = {}
    for tracker in trackers:
        cat = tracker.get("category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "nodes": nodes,
        "edges": edges,
        "total_trackers": len(trackers),
        "category_counts": category_counts,
        "total_cookies": len(cookies),
        "advertising_cookies": len([c for c in cookies if c.get("category") == "advertising"]),
    }
