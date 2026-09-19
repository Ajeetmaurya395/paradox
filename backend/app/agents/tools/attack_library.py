"""
Paradox — Attack Payload Library
Hardcoded attack payloads that ALWAYS run deterministically, no LLM dependency.
These form the backbone of the security scanner.
"""

# ─── SQL Injection Payloads ────────────────────────────────────────────────
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "1' ORDER BY 1--",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' AND 1=CONVERT(int, @@version)--",
    "admin'--",
    "' OR ''='",
    "1' AND '1'='1",
    "'; WAITFOR DELAY '0:0:5'--",
]

# ─── XSS Payloads ─────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'>",
    "'-alert(1)-'",
    "<details open ontoggle=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
]

# ─── Path Traversal Payloads ──────────────────────────────────────────────
PATH_TRAVERSAL = [
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\system.ini",
    "....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
]

# ─── Sensitive Paths ──────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/admin",
    "/login",
    "/.env",
    "/.git/config",
    "/wp-admin",
    "/api/",
    "/swagger.json",
    "/graphql",
    "/.DS_Store",
    "/backup",
    "/debug",
    "/test",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/server-status",
    "/phpinfo.php",
    "/wp-config.php.bak",
    "/api/v1/",
    "/.htaccess",
]

# ─── Security Headers to Check ────────────────────────────────────────────
HEADER_CHECKS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ─── Header Severity Mapping ──────────────────────────────────────────────
HEADER_SEVERITY = {
    "Content-Security-Policy": "high",
    "Strict-Transport-Security": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "medium",
    "X-XSS-Protection": "low",
    "Referrer-Policy": "medium",
    "Permissions-Policy": "low",
}

# ─── Fix Suggestions ──────────────────────────────────────────────────────
FIX_SUGGESTIONS = {
    "sqli": """**Fix: Parameterized Queries**
```python
# ❌ Vulnerable
query = f"SELECT * FROM users WHERE name = '{user_input}'"

# ✅ Safe — use parameterized queries
cursor.execute("SELECT * FROM users WHERE name = %s", (user_input,))
```
Also: Use an ORM (SQLAlchemy, Django ORM), input validation, and WAF rules.""",

    "xss": """**Fix: Output Encoding + CSP**
```html
<!-- ❌ Vulnerable -->
<div>Welcome, {{ user_input }}</div>

<!-- ✅ Safe — auto-escape in templates -->
<div>Welcome, {{ user_input | escape }}</div>
```
```python
# Server-side: set Content-Security-Policy header
response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
```
Also: Use DOMPurify for client-side, HttpOnly cookies, input validation.""",

    "missing_headers": """**Fix: Add Security Headers**
```nginx
# Nginx configuration
add_header Content-Security-Policy "default-src 'self';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```""",

    "sensitive_path": """**Fix: Block Sensitive Paths**
```nginx
# Nginx: Block sensitive files
location ~ /\\.(env|git|htaccess|DS_Store) {
    deny all;
    return 404;
}
location /admin { auth_basic "Admin Area"; }
```
Also: Remove debug endpoints in production, use proper access controls.""",

    "path_traversal": """**Fix: Input Validation + Chroot**
```python
# ❌ Vulnerable
file_path = os.path.join(base_dir, user_input)

# ✅ Safe — resolve and validate path
real_path = os.path.realpath(os.path.join(base_dir, user_input))
if not real_path.startswith(os.path.realpath(base_dir)):
    raise ValueError("Path traversal detected!")
```""",

    "insecure_cookies": """**Fix: Secure Cookie Flags**
```python
# Set secure cookie flags
response.set_cookie(
    "session_id",
    value=token,
    httponly=True,      # Prevents JavaScript access
    secure=True,        # HTTPS only
    samesite="Lax",     # CSRF protection
    max_age=3600
)
```""",

    "no_rate_limiting": """**Fix: Implement Rate Limiting**
```python
# FastAPI with slowapi
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.post("/api/login")
@limiter.limit("5/minute")
async def login(request: Request):
    ...
```
```nginx
# Nginx rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
location /api/ { limit_req zone=api burst=20 nodelay; }
```""",

    "no_https": """**Fix: Enforce HTTPS**
```nginx
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```
Also: Get a free SSL certificate from Let's Encrypt.""",
}


def get_fix_suggestion(category: str) -> str:
    """Get the fix suggestion for a vulnerability category."""
    return FIX_SUGGESTIONS.get(category, "Review and apply security best practices for this vulnerability type.")
