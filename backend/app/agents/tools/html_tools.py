"""
Paradox — HTML Parsing Tools
Tools for crawling pages, finding forms, and extracting input fields.
"""

import httpx
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger("paradox.tools.html")

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def crawl_page(url: str) -> dict:
    """
    Fetch a page and extract all links, forms, inputs, scripts, and meta tags.

    Args:
        url: Target URL to crawl

    Returns:
        Dict with links, forms, scripts, meta_tags, and page structure
    """
    try:
        with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
            response = client.get(url, headers={"User-Agent": USER_AGENT})

        soup = BeautifulSoup(response.text, "lxml")

        # Extract links
        links = []
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            abs_url = urljoin(url, href)
            links.append({
                "text": a_tag.get_text(strip=True)[:50],
                "href": abs_url,
                "is_external": urlparse(abs_url).netloc != urlparse(url).netloc
            })

        # Extract forms
        forms = find_forms_from_soup(soup, url)

        # Extract scripts
        scripts = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                scripts.append({
                    "type": "external",
                    "src": urljoin(url, src),
                    "is_external": urlparse(urljoin(url, src)).netloc != urlparse(url).netloc
                })
            elif script.string:
                scripts.append({
                    "type": "inline",
                    "length": len(script.string),
                    "preview": script.string[:100] + "..." if len(script.string) > 100 else script.string
                })

        # Extract meta tags
        meta_tags = []
        for meta in soup.find_all("meta"):
            meta_tags.append({
                "name": meta.get("name", meta.get("property", "")),
                "content": meta.get("content", "")[:100]
            })

        # Page title
        title = soup.title.string if soup.title else "No title"

        return {
            "url": url,
            "title": title,
            "status_code": response.status_code,
            "total_links": len(links),
            "total_forms": len(forms),
            "total_scripts": len(scripts),
            "links": links[:50],  # Limit to 50
            "forms": forms,
            "scripts": scripts[:30],
            "meta_tags": meta_tags,
            "external_links_count": len([l for l in links if l["is_external"]]),
            "external_scripts_count": len([s for s in scripts if s.get("is_external", False)]),
        }
    except Exception as e:
        return {"error": str(e), "url": url}


def find_forms(url: str) -> list:
    """
    Find all HTML forms on a page with their action URLs and input fields.

    Args:
        url: Target URL to scan for forms

    Returns:
        List of forms with action, method, and input fields
    """
    try:
        with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
            response = client.get(url, headers={"User-Agent": USER_AGENT})

        soup = BeautifulSoup(response.text, "lxml")
        return find_forms_from_soup(soup, url)
    except Exception as e:
        return [{"error": str(e)}]


def find_forms_from_soup(soup: BeautifulSoup, base_url: str) -> list:
    """Extract forms from a BeautifulSoup object."""
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            action = urljoin(base_url, action)
        else:
            action = base_url

        method = form.get("method", "GET").upper()

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_info = {
                "tag": inp.name,
                "type": inp.get("type", "text"),
                "name": inp.get("name", ""),
                "id": inp.get("id", ""),
                "placeholder": inp.get("placeholder", ""),
                "required": inp.has_attr("required"),
                "value": inp.get("value", ""),
            }
            if inp.name == "select":
                input_info["options"] = [opt.get("value", opt.text) for opt in inp.find_all("option")]
            inputs.append(input_info)

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
            "has_file_upload": any(i["type"] == "file" for i in inputs),
            "has_password": any(i["type"] == "password" for i in inputs),
            "input_count": len(inputs),
        })

    return forms


def find_input_fields(html: str) -> list:
    """
    Extract all input fields, textareas, and select elements from HTML.

    Args:
        html: Raw HTML string

    Returns:
        List of input field details
    """
    soup = BeautifulSoup(html, "lxml")
    fields = []
    for inp in soup.find_all(["input", "textarea", "select"]):
        fields.append({
            "tag": inp.name,
            "type": inp.get("type", "text"),
            "name": inp.get("name", ""),
            "id": inp.get("id", ""),
            "placeholder": inp.get("placeholder", ""),
            "required": inp.has_attr("required"),
        })
    return fields
